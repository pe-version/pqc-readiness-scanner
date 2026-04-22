"""JSON Web Token usage scanner.

Detects:
  - The PQC migration surface: RS256/RS384/RS512, ES256/ES384/ES512, EdDSA.
  - The well-known classical-failure surface that co-occurs with PQC migration
    work: alg='none', verification disabled, weak HMAC literal secrets.

NOT a comprehensive RFC 8725 (JWT BCP) implementation. This scanner intentionally
covers only the subset that overlaps the project's PQC inventory mission.

Known limitations:
  - Line-local: a jwt.encode(...) call split across multiple lines may not fire
    the weak-HMAC heuristic, which requires the algorithm token, the call site,
    and the literal secret on the same line. Documented, not bug.
  - String-literal-aware: SUPPRESSION_PATTERN may match `# pqc-scan: ignore`
    appearing inside a string literal. Acceptable given the regex approach.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from pqc_scan.algorithms import ALGORITHMS
from pqc_scan.findings import Finding, is_test_path
from pqc_scan.scanners.source_code import (
    MAX_FILE_BYTES,
    MAX_LINE_LENGTH,
    SKIP_DIRS,
    SOURCE_EXTENSIONS,
    parse_suppression,
)
from pathlib import Path
from typing import Iterator


@dataclass(frozen=True)
class JWTRule:
    rule_id: str
    algorithm_id: str
    pattern: re.Pattern[str]


# Patterns are deliberately conservative: they match algorithm tokens in
# string-literal positions and well-known JWT API call shapes. A line that only
# mentions an algorithm name in a comment will not match unless the comment
# contains the literal-quote shape, which is uncommon enough to accept.
RULES: list[JWTRule] = [
    # alg: none — JWT spec permits it, accepting it on verification is the bug.
    JWTRule("pqc-scan.jwt.alg-none.token", "jwt_alg_none",
            re.compile(r"['\"]alg['\"]\s*:\s*['\"]none['\"]", re.I)),
    JWTRule("pqc-scan.jwt.alg-none.algorithm-kw", "jwt_alg_none",
            re.compile(r"\balgorithm\s*=\s*['\"]none['\"]", re.I)),

    # Verification disabled (PyJWT, jsonwebtoken, others).
    JWTRule("pqc-scan.jwt.verify-false.pyjwt", "jwt_verify_disabled",
            re.compile(r"\bjwt\.decode\s*\([^)]*\bverify\s*=\s*False")),
    JWTRule("pqc-scan.jwt.verify-false.options", "jwt_verify_disabled",
            re.compile(r"['\"]verify_signature['\"]\s*:\s*False")),
    JWTRule("pqc-scan.jwt.algorithms-none.pyjwt", "jwt_verify_disabled",
            re.compile(r"\bjwt\.decode\s*\([^)]*\balgorithms\s*=\s*None")),

    # PQC migration surface — RSA-based JWS algorithms.
    JWTRule("pqc-scan.jwt.rs256.token", "jwt_rs256",
            re.compile(r"['\"](?:RS|PS)(?:256|384|512)['\"]")),
    JWTRule("pqc-scan.jwt.rs256.java", "jwt_rs256",
            re.compile(r"\bSignatureAlgorithm\.(?:RS|PS)(?:256|384|512)\b")),
    JWTRule("pqc-scan.jwt.rs256.go", "jwt_rs256",
            re.compile(r"\bjwt\.SigningMethod(?:RS|PS)(?:256|384|512)\b")),

    # PQC migration surface — ECDSA-based JWS algorithms.
    JWTRule("pqc-scan.jwt.es256.token", "jwt_es256",
            re.compile(r"['\"]ES(?:256|384|512)(?:K)?['\"]")),
    JWTRule("pqc-scan.jwt.es256.java", "jwt_es256",
            re.compile(r"\bSignatureAlgorithm\.ES(?:256|384|512)\b")),
    JWTRule("pqc-scan.jwt.es256.go", "jwt_es256",
            re.compile(r"\bjwt\.SigningMethodES(?:256|384|512)\b")),

    # PQC migration surface — EdDSA.
    JWTRule("pqc-scan.jwt.eddsa.token", "jwt_eddsa",
            re.compile(r"['\"]EdDSA['\"]")),
    JWTRule("pqc-scan.jwt.eddsa.go", "jwt_eddsa",
            re.compile(r"\bjwt\.SigningMethodEdDSA\b")),
]

# Weak-HMAC-secret heuristic: HS256/HS384/HS512 + a string literal of <32 bytes
# on the same line. Fired as a separate detector because it's a multi-token check.
HS_LINE = re.compile(r"['\"]HS(?:256|384|512)['\"]")
SHORT_LITERAL = re.compile(r"['\"]([^'\"\n]{1,31})['\"]")
JWT_FUNC_NEAR = re.compile(r"\b(?:jwt\.encode|jwt\.decode|jsonwebtoken\.sign|jwt\.sign)\b")


def _scan_weak_hmac(line: str, lineno: int, location: str, in_test: bool) -> list[Finding]:
    if not HS_LINE.search(line):
        return []
    # Only flag if a JWT call is on the same line — avoids matching constants or docs.
    if not JWT_FUNC_NEAR.search(line):
        return []
    short = SHORT_LITERAL.findall(line)
    # Filter out the alg name itself (HS256 etc.) and obvious non-secret strings.
    candidates = [s for s in short if not re.fullmatch(r"HS(?:256|384|512)", s)]
    if not candidates:
        return []
    info = ALGORITHMS["jwt_weak_hmac_secret"]
    return [
        Finding(
            rule_id="pqc-scan.jwt.weak-hmac-secret.literal",
            algorithm_id=info.id,
            algorithm_display=info.display,
            severity=info.severity,
            category=info.category,
            location=location,
            line=lineno,
            context=line.strip()[:200],
            scanner="jwt",
            replacement=info.replacement,
            notes=info.notes,
            in_test_path=in_test,
        )
    ]


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


# Fast substring pre-filter: files that don't contain any JWT-adjacent token
# can't produce JWT findings, and skipping them saves the per-rule regex work
# on monorepos where most files are non-JWT. Keep this set conservative — any
# token that any rule relies on must appear here (or within a longer token).
_JWT_HINTS: tuple[bytes, ...] = (
    b"jwt", b"jws", b"alg", b"SigningMethod", b"SignatureAlgorithm",
    b"RS256", b"RS384", b"RS512", b"PS256", b"PS384", b"PS512",
    b"ES256", b"ES384", b"ES512", b"EdDSA",
    b"HS256", b"HS384", b"HS512",
)


def scan_file(path: Path) -> list[Finding]:
    try:
        raw = path.read_bytes()
    except OSError:
        return []
    # Byte-level substring pre-filter avoids decoding files that can't match.
    if not any(hint in raw for hint in _JWT_HINTS):
        return []
    text = raw.decode("utf-8", errors="replace")
    findings: list[Finding] = []
    location = str(path)
    in_test = is_test_path(location)
    seen: set[tuple[str, int, int]] = set()
    for lineno, line in enumerate(text.splitlines(), start=1):
        if len(line) > MAX_LINE_LENGTH:
            continue
        suppressed_all, suppressed_ids = parse_suppression(line)
        if suppressed_all and not suppressed_ids:
            continue
        # Group same-rule matches per call site: at most one finding per rule per line.
        per_line_seen_rules: set[str] = set()
        for rule in RULES:
            if rule.rule_id in suppressed_ids:
                continue
            if rule.rule_id in per_line_seen_rules:
                continue
            match = rule.pattern.search(line)
            if match is None:
                continue
            per_line_seen_rules.add(rule.rule_id)
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
                    scanner="jwt",
                    replacement=info.replacement,
                    notes=info.notes,
                    in_test_path=in_test,
                )
            )
        if "pqc-scan.jwt.weak-hmac-secret.literal" not in suppressed_ids:
            findings.extend(_scan_weak_hmac(line, lineno, location, in_test))
    return findings
