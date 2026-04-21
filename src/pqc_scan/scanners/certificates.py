from __future__ import annotations

from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import (
    dsa,
    ec,
    ed25519,
    rsa,
    x25519,
)

from pqc_scan.algorithms import ALGORITHMS
from pqc_scan.findings import Finding


CERT_EXTENSIONS: set[str] = {".pem", ".crt", ".cer", ".der"}


def _classify_public_key(key: object) -> str | None:
    if isinstance(key, rsa.RSAPublicKey):
        return "rsa"
    if isinstance(key, ec.EllipticCurvePublicKey):
        return "ecdsa"
    if isinstance(key, dsa.DSAPublicKey):
        return "dsa"
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "ed25519"
    if isinstance(key, x25519.X25519PublicKey):
        return "x25519"
    return None


def _load_cert(data: bytes) -> x509.Certificate | None:
    for loader in (x509.load_pem_x509_certificate, x509.load_der_x509_certificate):
        try:
            return loader(data)
        except Exception:
            continue
    return None


def scan_path(root: Path) -> list[Finding]:
    if root.is_file():
        return scan_file(root)
    findings: list[Finding] = []
    for path in root.rglob("*"):
        if path.is_file() and path.suffix.lower() in CERT_EXTENSIONS:
            findings.extend(scan_file(path))
    return findings


def scan_file(path: Path) -> list[Finding]:
    if path.suffix.lower() not in CERT_EXTENSIONS:
        return []
    try:
        data = path.read_bytes()
    except OSError:
        return []
    cert = _load_cert(data)
    if cert is None:
        return []
    return findings_for_cert(cert, location=str(path))


def findings_for_cert(cert: x509.Certificate, location: str) -> list[Finding]:
    findings: list[Finding] = []
    pubkey = cert.public_key()
    pk_alg = _classify_public_key(pubkey)
    subject = cert.subject.rfc4514_string()
    if pk_alg and pk_alg in ALGORITHMS:
        info = ALGORITHMS[pk_alg]
        findings.append(
            Finding(
                algorithm_id=info.id,
                algorithm_display=f"{info.display} (public key)",
                severity=info.severity,
                category=info.category,
                location=location,
                line=None,
                context=f"subject={subject}",
                scanner="certificates",
                replacement=info.replacement,
                notes=info.notes,
            )
        )
    sig_hash = cert.signature_hash_algorithm
    sig_name = sig_hash.name.lower() if sig_hash is not None else ""
    sig_alg_id: str | None = None
    if "md5" in sig_name:
        sig_alg_id = "md5"
    elif sig_name == "sha1":
        sig_alg_id = "sha1"
    if sig_alg_id is not None:
        info = ALGORITHMS[sig_alg_id]
        findings.append(
            Finding(
                algorithm_id=info.id,
                algorithm_display=f"{info.display} (cert signature hash)",
                severity=info.severity,
                category=info.category,
                location=location,
                line=None,
                context=f"subject={subject}",
                scanner="certificates",
                replacement=info.replacement,
                notes=info.notes,
            )
        )
    return findings
