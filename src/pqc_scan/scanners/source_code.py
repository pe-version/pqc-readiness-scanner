from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator

from pqc_scan.algorithms import ALGORITHMS
from pqc_scan.findings import Finding


PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # ---- RSA ----
    ("rsa", re.compile(r"\bRSA\.(?:generate|importKey|construct|new|sign|verify|encrypt|decrypt)\b")),
    ("rsa", re.compile(r"\brsa\.(?:generate_private_key|generate_public_key|RSAPrivateKey|RSAPublicKey)\b")),
    ("rsa", re.compile(r"from\s+cryptography[\w.]*\s+import\s+[^#\n]*\brsa\b")),
    ("rsa", re.compile(r"\bcrypto\.generateKeyPair(?:Sync)?\s*\(\s*['\"]rsa['\"]", re.I)),
    ("rsa", re.compile(r"\brsa\.GenerateKey\s*\(")),
    ("rsa", re.compile(r"\bKeyPairGenerator\.getInstance\(\s*[\"']RSA[\"']")),
    ("rsa", re.compile(r"\bSignature\.getInstance\(\s*[\"'][\w]*RSA[\w]*[\"']")),
    ("rsa", re.compile(r"\bRSA_(?:generate_key(?:_ex)?|new|sign|verify|private_encrypt|public_decrypt)\b")),
    ("rsa", re.compile(r"\bEVP_PKEY_RSA\b")),
    ("rsa", re.compile(r"\bssh-rsa\b")),

    # ---- ECDSA ----
    ("ecdsa", re.compile(r"\bECDSA\b")),
    ("ecdsa", re.compile(r"\becdsa\.(?:generate_private_key|sign|verify|GenerateKey)\b")),
    ("ecdsa", re.compile(r"\bec\.(?:generate_private_key|EllipticCurvePrivateKey|EllipticCurvePublicKey|SEC[PT]\d+[RK]\d?)\b")),
    ("ecdsa", re.compile(r"from\s+cryptography[\w.]*\s+import\s+[^#\n]*\bec\b")),
    ("ecdsa", re.compile(r"\bSignature\.getInstance\(\s*[\"'][\w]*ECDSA[\w]*[\"']")),
    ("ecdsa", re.compile(r"\bcrypto\.generateKeyPair(?:Sync)?\s*\(\s*['\"]ec['\"]", re.I)),
    ("ecdsa", re.compile(r"\becdsa-sha2-nistp(?:256|384|521)\b")),

    # ---- ECDH ----
    ("ecdh", re.compile(r"\bECDH\b")),
    ("ecdh", re.compile(r"\becdh\.(?:generate_private_key|exchange|ECDH)\b")),
    ("ecdh", re.compile(r"\bcrypto\.createECDH\s*\(")),
    ("ecdh", re.compile(r"\bKeyAgreement\.getInstance\(\s*[\"']ECDH[\"']")),

    # ---- DH (finite-field) ----
    ("dh", re.compile(r"\bdh\.(?:generate_private_key|generate_parameters)\b")),
    ("dh", re.compile(r"\bcrypto\.createDiffieHellman\s*\(")),
    ("dh", re.compile(r"\bDH_(?:new|generate_key|generate_parameters)\b")),
    ("dh", re.compile(r"\bKeyPairGenerator\.getInstance\(\s*[\"']DiffieHellman[\"']")),

    # ---- DSA ----
    ("dsa", re.compile(r"\bDSA\.(?:generate|importKey)\b")),
    ("dsa", re.compile(r"\bdsa\.generate_private_key\b")),
    ("dsa", re.compile(r"\bKeyPairGenerator\.getInstance\(\s*[\"']DSA[\"']")),
    ("dsa", re.compile(r"\bDSA_(?:new|generate_key|generate_parameters)\b")),
    ("dsa", re.compile(r"\bssh-dss\b")),

    # ---- X25519 ----
    ("x25519", re.compile(r"\bX25519\b")),
    ("x25519", re.compile(r"\bx25519\.(?:X25519PrivateKey|X25519PublicKey|generate)\b")),
    ("x25519", re.compile(r"\bcurve25519\b", re.I)),

    # ---- Ed25519 ----
    ("ed25519", re.compile(r"\bEd25519\b")),
    ("ed25519", re.compile(r"\bed25519\.(?:Ed25519PrivateKey|Ed25519PublicKey|generate|sign)\b")),
    ("ed25519", re.compile(r"\bssh-ed25519\b")),

    # ---- MD5 ----
    ("md5", re.compile(r"\bhashlib\.md5\b")),
    ("md5", re.compile(r"\bMessageDigest\.getInstance\(\s*[\"']MD5[\"']")),
    ("md5", re.compile(r"\bcrypto\.createHash\s*\(\s*['\"]md5['\"]", re.I)),
    ("md5", re.compile(r"\bMD5\s*\(")),
    ("md5", re.compile(r"\bEVP_md5\b")),
    ("md5", re.compile(r"\bmd5\.New\s*\(\s*\)")),

    # ---- SHA-1 ----
    ("sha1", re.compile(r"\bhashlib\.sha1\b")),
    ("sha1", re.compile(r"\bMessageDigest\.getInstance\(\s*[\"']SHA-?1[\"']")),
    ("sha1", re.compile(r"\bcrypto\.createHash\s*\(\s*['\"]sha-?1['\"]", re.I)),
    ("sha1", re.compile(r"\bSHA1\s*\(")),
    ("sha1", re.compile(r"\bEVP_sha1\b")),
    ("sha1", re.compile(r"\bsha1\.New\s*\(\s*\)")),

    # ---- DES ----
    ("des", re.compile(r"\bDES\.new\b")),
    ("des", re.compile(r"\bCipher\.getInstance\(\s*[\"']DES[/\"']")),
    ("des", re.compile(r"\bcrypto\.createCipheriv\s*\(\s*['\"]des-")),

    # ---- 3DES ----
    ("3des", re.compile(r"\bDES3\.new\b")),
    ("3des", re.compile(r"\bTripleDES\b")),
    ("3des", re.compile(r"\b3DES\b")),
    ("3des", re.compile(r"\bCipher\.getInstance\(\s*[\"'](?:DESede|TripleDES)[/\"']")),

    # ---- RC4 ----
    ("rc4", re.compile(r"\bARC4\.new\b")),
    ("rc4", re.compile(r"\bRC4\b")),
    ("rc4", re.compile(r"\bCipher\.getInstance\(\s*[\"']RC4[\"']")),

    # ---- AES-128 (informational) ----
    ("aes_128", re.compile(r"\bAES[_-]?128\b")),
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
    seen: set[tuple[str, int]] = set()
    for lineno, line in enumerate(text.splitlines(), start=1):
        if len(line) > MAX_LINE_LENGTH:
            continue
        for alg_id, pattern in PATTERNS:
            if (alg_id, lineno) in seen:
                continue
            if pattern.search(line):
                seen.add((alg_id, lineno))
                info = ALGORITHMS[alg_id]
                findings.append(
                    Finding(
                        algorithm_id=info.id,
                        algorithm_display=info.display,
                        severity=info.severity,
                        category=info.category,
                        location=str(path),
                        line=lineno,
                        context=line.strip()[:200],
                        scanner="source_code",
                        replacement=info.replacement,
                        notes=info.notes,
                    )
                )
    return findings
