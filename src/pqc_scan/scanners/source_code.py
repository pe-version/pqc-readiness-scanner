from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from pqc_scan.algorithms import ALGORITHMS
from pqc_scan.findings import Finding, is_test_path


@dataclass(frozen=True)
class Rule:
    rule_id: str
    algorithm_id: str
    pattern: re.Pattern[str]


# Each rule has a stable ID of the form pqc-scan.source.<algorithm>.<context>.
# IDs are stable across releases; new variants get new IDs rather than altering
# existing ones (so suppression comments remain valid).
RULES: list[Rule] = [
    # ---- RSA ----
    Rule("pqc-scan.source.rsa.pycryptodome", "rsa", re.compile(r"\bRSA\.(?:generate|importKey|construct|new|sign|verify|encrypt|decrypt)\b")),
    Rule("pqc-scan.source.rsa.cryptography-rsa-call", "rsa", re.compile(r"\brsa\.(?:generate_private_key|generate_public_key|RSAPrivateKey|RSAPublicKey)\b")),
    Rule("pqc-scan.source.rsa.cryptography-rsa-import", "rsa", re.compile(r"from\s+cryptography[\w.]*\s+import\s+[^#\n]*\brsa\b")),
    Rule("pqc-scan.source.rsa.node-crypto", "rsa", re.compile(r"\bcrypto\.generateKeyPair(?:Sync)?\s*\(\s*['\"]rsa['\"]", re.I)),
    Rule("pqc-scan.source.rsa.go-crypto", "rsa", re.compile(r"\brsa\.GenerateKey\s*\(")),
    Rule("pqc-scan.source.rsa.java-keypair", "rsa", re.compile(r"\bKeyPairGenerator\.getInstance\(\s*[\"']RSA[\"']")),
    Rule("pqc-scan.source.rsa.java-signature", "rsa", re.compile(r"\bSignature\.getInstance\(\s*[\"'][\w]*RSA[\w]*[\"']")),
    Rule("pqc-scan.source.rsa.openssl-c", "rsa", re.compile(r"\bRSA_(?:generate_key(?:_ex)?|new|sign|verify|private_encrypt|public_decrypt)\b")),
    Rule("pqc-scan.source.rsa.openssl-evp", "rsa", re.compile(r"\bEVP_PKEY_RSA\b")),
    Rule("pqc-scan.source.rsa.ssh-rsa", "rsa", re.compile(r"\bssh-rsa\b")),

    # ---- ECDSA ----
    Rule("pqc-scan.source.ecdsa.bare-name", "ecdsa", re.compile(r"\bECDSA\b")),
    Rule("pqc-scan.source.ecdsa.python-ecdsa-pkg", "ecdsa", re.compile(r"\becdsa\.(?:generate_private_key|sign|verify|GenerateKey)\b")),
    Rule("pqc-scan.source.ecdsa.cryptography-ec-call", "ecdsa", re.compile(r"\bec\.(?:generate_private_key|EllipticCurvePrivateKey|EllipticCurvePublicKey|SEC[PT]\d+[RK]\d?)\b")),
    Rule("pqc-scan.source.ecdsa.cryptography-ec-import", "ecdsa", re.compile(r"from\s+cryptography[\w.]*\s+import\s+[^#\n]*\bec\b")),
    Rule("pqc-scan.source.ecdsa.java-signature", "ecdsa", re.compile(r"\bSignature\.getInstance\(\s*[\"'][\w]*ECDSA[\w]*[\"']")),
    Rule("pqc-scan.source.ecdsa.node-crypto", "ecdsa", re.compile(r"\bcrypto\.generateKeyPair(?:Sync)?\s*\(\s*['\"]ec['\"]", re.I)),
    Rule("pqc-scan.source.ecdsa.ssh-ecdsa", "ecdsa", re.compile(r"\becdsa-sha2-nistp(?:256|384|521)\b")),

    # ---- ECDH ----
    Rule("pqc-scan.source.ecdh.bare-name", "ecdh", re.compile(r"\bECDH\b")),
    Rule("pqc-scan.source.ecdh.cryptography-ecdh-call", "ecdh", re.compile(r"\becdh\.(?:generate_private_key|exchange|ECDH)\b")),
    Rule("pqc-scan.source.ecdh.node-crypto", "ecdh", re.compile(r"\bcrypto\.createECDH\s*\(")),
    Rule("pqc-scan.source.ecdh.java-keyagreement", "ecdh", re.compile(r"\bKeyAgreement\.getInstance\(\s*[\"']ECDH[\"']")),

    # ---- DH (finite-field) ----
    Rule("pqc-scan.source.dh.cryptography-dh-call", "dh", re.compile(r"\bdh\.(?:generate_private_key|generate_parameters)\b")),
    Rule("pqc-scan.source.dh.node-crypto", "dh", re.compile(r"\bcrypto\.createDiffieHellman\s*\(")),
    Rule("pqc-scan.source.dh.openssl-c", "dh", re.compile(r"\bDH_(?:new|generate_key|generate_parameters)\b")),
    Rule("pqc-scan.source.dh.java-keypair", "dh", re.compile(r"\bKeyPairGenerator\.getInstance\(\s*[\"']DiffieHellman[\"']")),

    # ---- DSA ----
    Rule("pqc-scan.source.dsa.pycryptodome", "dsa", re.compile(r"\bDSA\.(?:generate|importKey)\b")),
    Rule("pqc-scan.source.dsa.cryptography-dsa-call", "dsa", re.compile(r"\bdsa\.generate_private_key\b")),
    Rule("pqc-scan.source.dsa.java-keypair", "dsa", re.compile(r"\bKeyPairGenerator\.getInstance\(\s*[\"']DSA[\"']")),
    Rule("pqc-scan.source.dsa.openssl-c", "dsa", re.compile(r"\bDSA_(?:new|generate_key|generate_parameters)\b")),
    Rule("pqc-scan.source.dsa.ssh-dss", "dsa", re.compile(r"\bssh-dss\b")),

    # ---- X25519 ----
    Rule("pqc-scan.source.x25519.bare-name", "x25519", re.compile(r"\bX25519\b")),
    Rule("pqc-scan.source.x25519.cryptography-x25519-call", "x25519", re.compile(r"\bx25519\.(?:X25519PrivateKey|X25519PublicKey|generate)\b")),
    Rule("pqc-scan.source.x25519.curve25519-name", "x25519", re.compile(r"\bcurve25519\b", re.I)),

    # ---- Ed25519 ----
    Rule("pqc-scan.source.ed25519.bare-name", "ed25519", re.compile(r"\bEd25519\b")),
    Rule("pqc-scan.source.ed25519.cryptography-ed25519-call", "ed25519", re.compile(r"\bed25519\.(?:Ed25519PrivateKey|Ed25519PublicKey|generate|sign)\b")),
    Rule("pqc-scan.source.ed25519.ssh-ed25519", "ed25519", re.compile(r"\bssh-ed25519\b")),

    # ---- MD5 ----
    Rule("pqc-scan.source.md5.python-hashlib", "md5", re.compile(r"\bhashlib\.md5\b")),
    Rule("pqc-scan.source.md5.java-md", "md5", re.compile(r"\bMessageDigest\.getInstance\(\s*[\"']MD5[\"']")),
    Rule("pqc-scan.source.md5.node-crypto", "md5", re.compile(r"\bcrypto\.createHash\s*\(\s*['\"]md5['\"]", re.I)),
    Rule("pqc-scan.source.md5.bare-call", "md5", re.compile(r"\bMD5\s*\(")),
    Rule("pqc-scan.source.md5.openssl-evp", "md5", re.compile(r"\bEVP_md5\b")),
    Rule("pqc-scan.source.md5.go-stdlib", "md5", re.compile(r"\bmd5\.New\s*\(\s*\)")),

    # ---- SHA-1 ----
    Rule("pqc-scan.source.sha1.python-hashlib", "sha1", re.compile(r"\bhashlib\.sha1\b")),
    Rule("pqc-scan.source.sha1.java-md", "sha1", re.compile(r"\bMessageDigest\.getInstance\(\s*[\"']SHA-?1[\"']")),
    Rule("pqc-scan.source.sha1.node-crypto", "sha1", re.compile(r"\bcrypto\.createHash\s*\(\s*['\"]sha-?1['\"]", re.I)),
    Rule("pqc-scan.source.sha1.bare-call", "sha1", re.compile(r"\bSHA1\s*\(")),
    Rule("pqc-scan.source.sha1.openssl-evp", "sha1", re.compile(r"\bEVP_sha1\b")),
    Rule("pqc-scan.source.sha1.go-stdlib", "sha1", re.compile(r"\bsha1\.New\s*\(\s*\)")),

    # ---- DES ----
    Rule("pqc-scan.source.des.pycryptodome", "des", re.compile(r"\bDES\.new\b")),
    Rule("pqc-scan.source.des.java-cipher", "des", re.compile(r"\bCipher\.getInstance\(\s*[\"']DES[/\"']")),
    Rule("pqc-scan.source.des.node-crypto", "des", re.compile(r"\bcrypto\.createCipheriv\s*\(\s*['\"]des-")),

    # ---- 3DES ----
    Rule("pqc-scan.source.3des.pycryptodome", "3des", re.compile(r"\bDES3\.new\b")),
    Rule("pqc-scan.source.3des.bare-name-tripledes", "3des", re.compile(r"\bTripleDES\b")),
    Rule("pqc-scan.source.3des.bare-name-3des", "3des", re.compile(r"\b3DES\b")),
    Rule("pqc-scan.source.3des.java-cipher", "3des", re.compile(r"\bCipher\.getInstance\(\s*[\"'](?:DESede|TripleDES)[/\"']")),

    # ---- RC4 ----
    Rule("pqc-scan.source.rc4.pycryptodome", "rc4", re.compile(r"\bARC4\.new\b")),
    Rule("pqc-scan.source.rc4.bare-name", "rc4", re.compile(r"\bRC4\b")),
    Rule("pqc-scan.source.rc4.java-cipher", "rc4", re.compile(r"\bCipher\.getInstance\(\s*[\"']RC4[\"']")),

    # ---- AES-128 (informational) ----
    Rule("pqc-scan.source.aes128.bare-name", "aes_128", re.compile(r"\bAES[_-]?128\b")),

    # ---- XMSS family (PQC-safe with caveats) ----
    Rule("pqc-scan.source.xmss.bare-name", "xmss_family", re.compile(r"\bXMSS(?:MT)?\b")),
    Rule("pqc-scan.source.xmss.python-pkg", "xmss_family", re.compile(r"\b(?:pyspx[\w_-]*xmss|xmss[a-z_]*)\.(?:keygen|sign|verify)\b")),

    # ---- LMS / HSS family (PQC-safe with caveats) ----
    Rule("pqc-scan.source.lms.bare-name", "lms_family", re.compile(r"\b(?:HSS-?LMS|LMS-?HSS|HSS_LMS)\b")),
    Rule("pqc-scan.source.lms.alg-token", "lms_family", re.compile(r"['\"]LMS-(?:SHA256|SHAKE)[\w_-]+['\"]")),
]


SOURCE_EXTENSIONS: set[str] = {
    ".py", ".pyi",
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".go", ".rs",
    ".java", ".kt", ".kts", ".scala",
    ".c", ".h", ".cc", ".cpp", ".hpp", ".cxx", ".hh",
    ".cs", ".rb", ".php", ".swift", ".m", ".mm",
    ".sh", ".bash", ".zsh",
    ".tf", ".yml", ".yaml", ".toml", ".json", ".xml",
}

SKIP_DIRS: set[str] = {
    ".git", ".hg", ".svn",
    "node_modules", "__pycache__",
    ".venv", "venv", "env",
    ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "dist", "build", "target", "out",
    ".gradle", ".idea", ".vscode", "vendor",
}

MAX_FILE_BYTES = 2_000_000  # 2 MB
MAX_LINE_LENGTH = 1_000  # skip likely-minified lines

# Inline suppression: `# pqc-scan: ignore` (suppress all rules on this line)
# or `# pqc-scan: ignore[rule-id-1, rule-id-2]` (suppress only these rules).
# Comment leader is intentionally permissive (#, //, --, ;) to cover most languages
# in SOURCE_EXTENSIONS without per-language parsers.
SUPPRESSION_PATTERN = re.compile(
    r"(?:#|//|--|;)\s*pqc-scan:\s*ignore(?:\[([^\]]*)\])?",
    re.IGNORECASE,
)


def parse_suppression(line: str) -> tuple[bool, frozenset[str]]:
    """Return (is_suppressed, specific_rule_ids).

    If is_suppressed is True and specific_rule_ids is empty, all rules on this
    line are suppressed. If specific_rule_ids is non-empty, only those rule IDs
    are suppressed.
    """
    match = SUPPRESSION_PATTERN.search(line)
    if match is None:
        return False, frozenset()
    inner = match.group(1)
    if inner is None:
        return True, frozenset()
    ids = frozenset(s.strip() for s in inner.split(",") if s.strip())
    return True, ids


def iter_source_files(root: Path) -> Iterator[Path]:
    if root.is_file():
        if root.suffix.lower() in SOURCE_EXTENSIONS:
            yield root
        return
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() not in SOURCE_EXTENSIONS:
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        yield path


def scan_path(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in iter_source_files(root):
        findings.extend(scan_file(path))
    return findings


def scan_file(path: Path) -> list[Finding]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    findings: list[Finding] = []
    location = str(path)
    in_test = is_test_path(location)
    # Dedup keys include match position so distinct matches on the same line
    # produce distinct findings (multiple JWT issues, multiple algorithms, etc.).
    seen: set[tuple[str, int, int]] = set()
    for lineno, line in enumerate(text.splitlines(), start=1):
        if len(line) > MAX_LINE_LENGTH:
            continue
        suppressed_all, suppressed_ids = parse_suppression(line)
        if suppressed_all and not suppressed_ids:
            continue
        for rule in RULES:
            if rule.rule_id in suppressed_ids:
                continue
            for match in rule.pattern.finditer(line):
                key = (rule.rule_id, lineno, match.start())
                if key in seen:
                    continue
                seen.add(key)
                info = ALGORITHMS[rule.algorithm_id]
                findings.append(
                    Finding(
                        rule_id=rule.rule_id,
                        algorithm_id=info.id,
                        algorithm_display=info.display,
                        severity=info.severity,
                        category=info.category,
                        location=location,
                        line=lineno,
                        context=line.strip()[:200],
                        scanner="source_code",
                        replacement=info.replacement,
                        notes=info.notes,
                        in_test_path=in_test,
                    )
                )
    return findings
