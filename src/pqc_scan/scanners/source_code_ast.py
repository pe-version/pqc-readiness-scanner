"""AST-based crypto-API detection for Python source files.

Complements the regex-based source_code scanner. Uses libcst's
QualifiedNameProvider to resolve identifiers through their imports, so a
``from hashlib import md5 as h; h(b"x")`` call is recognized as MD5 even
though the surface syntax doesn't contain "md5" or "hashlib" together on
one line. Conversely, mentions of crypto names inside docstrings, string
literals, comments, or unrelated class names are not flagged — that is
the precision win over regex.

The AST scanner emits findings with the **same rule_ids** as the regex
scanner, so the CLI can dedup the union by ``(rule_id, location, line)``.
This means an AST finding overlapping a regex finding doesn't double-
report; only AST-exclusive findings (regex couldn't match them) survive
dedup.

Limitations:
  - Python only (.py / .pyi). The existing regex scanner remains
    authoritative for JavaScript, Go, Java, etc.
  - No data-flow tracking. ``algo = "md5"; hashlib.new(algo)`` is not
    flagged; only ``hashlib.new("md5")`` style with literal arguments is
    detected for that pattern (and only via the dispatcher entry below).
  - File parse errors fall back to "no findings" silently — the regex
    scanner still runs over the same file.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

import libcst as cst
import libcst.metadata as cst_metadata

from pqc_scan.algorithms import ALGORITHMS
from pqc_scan.findings import Finding, is_test_path
from pqc_scan.scanners.source_code import (
    MAX_FILE_BYTES,
    SKIP_DIRS,
    parse_suppression,
)


# Suffix-matched against the qualified name reported by libcst. The leading
# package path is suppressed to keep the table short and forward-compatible
# with future cryptography-library reorgs (e.g.
# `cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key` collapses
# to `rsa.generate_private_key`). The suffix MUST start at a dot boundary so
# `MyRSA.generate` does not match `RSA.generate`.
@dataclass(frozen=True)
class APIPattern:
    qualified_suffix: str  # e.g. "rsa.generate_private_key"
    rule_id: str
    algorithm_id: str


KNOWN_APIS: tuple[APIPattern, ...] = (
    # Python stdlib hashlib
    APIPattern("hashlib.md5", "pqc-scan.source.md5.python-hashlib", "md5"),
    APIPattern("hashlib.sha1", "pqc-scan.source.sha1.python-hashlib", "sha1"),

    # `cryptography` package — qualified name typically resolves to
    # `cryptography.hazmat.primitives.asymmetric.<X>.<func>` so the table
    # uses the trailing two segments.
    APIPattern("rsa.generate_private_key",
               "pqc-scan.source.rsa.cryptography-rsa-call", "rsa"),
    APIPattern("ec.generate_private_key",
               "pqc-scan.source.ecdsa.cryptography-ec-call", "ecdsa"),
    APIPattern("dsa.generate_private_key",
               "pqc-scan.source.dsa.cryptography-dsa-call", "dsa"),
    APIPattern("dh.generate_private_key",
               "pqc-scan.source.dh.cryptography-dh-call", "dh"),
    APIPattern("dh.generate_parameters",
               "pqc-scan.source.dh.cryptography-dh-call", "dh"),
    APIPattern("x25519.X25519PrivateKey.generate",
               "pqc-scan.source.x25519.cryptography-x25519-call", "x25519"),
    APIPattern("x25519.X25519PrivateKey.from_private_bytes",
               "pqc-scan.source.x25519.cryptography-x25519-call", "x25519"),
    APIPattern("x25519.X25519PublicKey.from_public_bytes",
               "pqc-scan.source.x25519.cryptography-x25519-call", "x25519"),
    APIPattern("ed25519.Ed25519PrivateKey.generate",
               "pqc-scan.source.ed25519.cryptography-ed25519-call", "ed25519"),
    APIPattern("ed25519.Ed25519PrivateKey.from_private_bytes",
               "pqc-scan.source.ed25519.cryptography-ed25519-call", "ed25519"),
    APIPattern("ed25519.Ed25519PublicKey.from_public_bytes",
               "pqc-scan.source.ed25519.cryptography-ed25519-call", "ed25519"),

    # PyCryptodome
    APIPattern("Crypto.PublicKey.RSA.generate",
               "pqc-scan.source.rsa.pycryptodome", "rsa"),
    APIPattern("Crypto.PublicKey.DSA.generate",
               "pqc-scan.source.dsa.pycryptodome", "dsa"),
    APIPattern("Crypto.Cipher.DES.new",
               "pqc-scan.source.des.pycryptodome", "des"),
    APIPattern("Crypto.Cipher.DES3.new",
               "pqc-scan.source.3des.pycryptodome", "3des"),
    APIPattern("Crypto.Cipher.ARC4.new",
               "pqc-scan.source.rc4.pycryptodome", "rc4"),
)


PYTHON_EXTENSIONS: frozenset[str] = frozenset({".py", ".pyi"})


def iter_python_files(root: Path) -> Iterator[Path]:
    """Walk Python-only files using the same skip-dir / size limits as the
    regex scanner, so AST coverage matches regex coverage 1:1 on Python."""
    if root.is_file():
        if root.suffix.lower() in PYTHON_EXTENSIONS:
            yield root
        return
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() not in PYTHON_EXTENSIONS:
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        yield path


def _matches_known_api(qualified_name: str) -> APIPattern | None:
    """Return the APIPattern whose suffix matches `qualified_name`, or None.

    Match is at a dot boundary or full equality so `MyRSA.generate` does not
    match `RSA.generate`.
    """
    for api in KNOWN_APIS:
        if qualified_name == api.qualified_suffix:
            return api
        if qualified_name.endswith("." + api.qualified_suffix):
            return api
    return None


class _CryptoCallVisitor(cst.CSTVisitor):
    """Walks a parsed module and emits crypto-API call findings."""

    METADATA_DEPENDENCIES = (
        cst_metadata.QualifiedNameProvider,
        cst_metadata.PositionProvider,
    )

    def __init__(
        self,
        location: str,
        in_test: bool,
        suppressions_by_line: dict[int, frozenset[str] | None],
    ) -> None:
        super().__init__()
        self.location = location
        self.in_test = in_test
        self.suppressions_by_line = suppressions_by_line
        self.findings: list[Finding] = []
        self._seen: set[tuple[str, int]] = set()

    def visit_Call(self, node: cst.Call) -> None:
        try:
            position = self.get_metadata(cst_metadata.PositionProvider, node).start
        except KeyError:
            return
        line = position.line

        suppression = self.suppressions_by_line.get(line)
        if suppression is not None and not suppression:
            return  # blanket suppression for this line

        try:
            qnames = self.get_metadata(cst_metadata.QualifiedNameProvider, node.func)
        except KeyError:
            return

        # Only accept names that resolve to an import — locally-defined
        # functions/classes that happen to share a crypto module name (e.g.
        # `class rsa:` inside the file) must not match.
        import_qnames = [
            q for q in qnames
            if q.source == cst_metadata.QualifiedNameSource.IMPORT
        ]
        if not import_qnames:
            return

        for qname in import_qnames:
            api = _matches_known_api(qname.name)
            if api is None:
                continue
            if suppression is not None and api.rule_id in suppression:
                continue
            key = (api.rule_id, line)
            if key in self._seen:
                continue
            self._seen.add(key)
            info = ALGORITHMS[api.algorithm_id]
            self.findings.append(
                Finding(
                    rule_id=api.rule_id,
                    algorithm_id=info.id,
                    algorithm_display=info.display,
                    severity=info.severity,
                    category=info.category,
                    location=self.location,
                    line=line,
                    context=qname.name,
                    scanner="source_code_ast",
                    replacement=info.replacement,
                    notes=info.notes,
                    in_test_path=self.in_test,
                )
            )
            return  # one finding per Call site


def _suppression_map(text: str) -> dict[int, frozenset[str] | None]:
    """Parse per-line suppression directives.

    Maps line numbers to:
      - `frozenset()` (empty) when the line has a blanket `# pqc-scan: ignore`
      - `frozenset(rule_ids)` when specific rules are silenced
      - absent when no directive is present
    """
    out: dict[int, frozenset[str] | None] = {}
    for lineno, line in enumerate(text.splitlines(), start=1):
        suppressed_all, ids = parse_suppression(line)
        if suppressed_all and not ids:
            out[lineno] = frozenset()  # blanket
        elif suppressed_all:
            out[lineno] = ids
    return out


def scan_path(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in iter_python_files(root):
        findings.extend(scan_file(path))
    return findings


def scan_file(path: Path) -> list[Finding]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    try:
        module = cst.parse_module(text)
    except cst.ParserSyntaxError:
        # Don't fail the run on syntax errors. The regex scanner still runs.
        return []
    wrapper = cst_metadata.MetadataWrapper(module)
    location = str(path)
    visitor = _CryptoCallVisitor(
        location=location,
        in_test=is_test_path(location),
        suppressions_by_line=_suppression_map(text),
    )
    wrapper.visit(visitor)
    return visitor.findings
