from __future__ import annotations

import datetime as dt
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.x509.oid import NameOID


def _build_cert(public_key, signing_key, sign_hash, name: str) -> bytes:
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(dt.datetime(2024, 1, 1, tzinfo=dt.timezone.utc))
        .not_valid_after(dt.datetime(2030, 1, 1, tzinfo=dt.timezone.utc))
    )
    cert = builder.sign(signing_key, sign_hash)
    return cert.public_bytes(serialization.Encoding.PEM)


@pytest.fixture
def rsa_cert(tmp_path: Path) -> Path:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = _build_cert(key.public_key(), key, hashes.SHA256(), "test.example.com")
    path = tmp_path / "rsa.pem"
    path.write_bytes(pem)
    return path


@pytest.fixture
def ed25519_cert(tmp_path: Path) -> Path:
    key = ed25519.Ed25519PrivateKey.generate()
    pem = _build_cert(key.public_key(), key, None, "ed.example.com")
    path = tmp_path / "ed25519.pem"
    path.write_bytes(pem)
    return path
