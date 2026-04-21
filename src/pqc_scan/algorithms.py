from __future__ import annotations

from dataclasses import dataclass

from pqc_scan.findings import Severity


@dataclass(frozen=True)
class AlgorithmInfo:
    id: str
    display: str
    category: str
    severity: Severity
    replacement: str
    notes: str


CATEGORY_DESCRIPTIONS: dict[str, str] = {
    "shor_broken": (
        "Public-key algorithm broken by Shor's algorithm on a sufficiently "
        "large fault-tolerant quantum computer (CRQC). Subject to "
        "'harvest now, decrypt later' attacks today."
    ),
    "grover_weakened": (
        "Symmetric primitive whose effective security is roughly halved by "
        "Grover's algorithm. Doubling the key/digest size restores classical-"
        "equivalent post-quantum security."
    ),
    "classically_broken": (
        "Already broken by classical cryptanalysis; should be replaced "
        "regardless of the quantum threat."
    ),
    "pqc_safe": (
        "NIST PQC standard or symmetric primitive considered post-quantum "
        "secure at standard parameters."
    ),
}


ALGORITHMS: dict[str, AlgorithmInfo] = {
    "rsa": AlgorithmInfo(
        id="rsa",
        display="RSA",
        category="shor_broken",
        severity=Severity.HIGH,
        replacement="ML-KEM (FIPS 203) for key encapsulation; ML-DSA (FIPS 204) for signatures",
        notes="Broken by Shor's algorithm on a CRQC. Migrate before long-lived secrets are at risk.",
    ),
    "ecdsa": AlgorithmInfo(
        id="ecdsa",
        display="ECDSA",
        category="shor_broken",
        severity=Severity.HIGH,
        replacement="ML-DSA (FIPS 204, Dilithium) or SLH-DSA (FIPS 205, SPHINCS+)",
        notes="Elliptic-curve discrete-log is broken by Shor's algorithm.",
    ),
    "ecdh": AlgorithmInfo(
        id="ecdh",
        display="ECDH",
        category="shor_broken",
        severity=Severity.HIGH,
        replacement="Hybrid X25519 + ML-KEM, or pure ML-KEM (FIPS 203)",
        notes="Long-lived ECDH-protected secrets are subject to harvest-now-decrypt-later.",
    ),
    "dh": AlgorithmInfo(
        id="dh",
        display="Diffie-Hellman (finite-field)",
        category="shor_broken",
        severity=Severity.HIGH,
        replacement="ML-KEM (FIPS 203)",
        notes="Discrete-log over Z_p is broken by Shor's algorithm.",
    ),
    "dsa": AlgorithmInfo(
        id="dsa",
        display="DSA",
        category="shor_broken",
        severity=Severity.HIGH,
        replacement="ML-DSA (FIPS 204)",
        notes="Discrete-log signatures broken by Shor; deprecated by NIST SP 800-186.",
    ),
    "x25519": AlgorithmInfo(
        id="x25519",
        display="X25519",
        category="shor_broken",
        severity=Severity.MEDIUM,
        replacement="Hybrid X25519 + ML-KEM (recommended near-term)",
        notes=(
            "Curve25519 ECDH is quantum-vulnerable. Often retained as the classical half "
            "of a hybrid construction during migration."
        ),
    ),
    "ed25519": AlgorithmInfo(
        id="ed25519",
        display="Ed25519",
        category="shor_broken",
        severity=Severity.MEDIUM,
        replacement="ML-DSA (FIPS 204) or hybrid Ed25519 + ML-DSA",
        notes="EdDSA over Curve25519 is quantum-vulnerable.",
    ),
    "md5": AlgorithmInfo(
        id="md5",
        display="MD5",
        category="classically_broken",
        severity=Severity.CRITICAL,
        replacement="SHA-256 / SHA-3-256 (or SHA-384+ for long-term assurance)",
        notes="Collisions trivially producible. Unsafe for any security purpose.",
    ),
    "sha1": AlgorithmInfo(
        id="sha1",
        display="SHA-1",
        category="classically_broken",
        severity=Severity.HIGH,
        replacement="SHA-256 / SHA-3-256 (or SHA-384+ for long-term assurance)",
        notes="Practical collisions demonstrated (SHAttered, 2017). Deprecated by NIST.",
    ),
    "des": AlgorithmInfo(
        id="des",
        display="DES",
        category="classically_broken",
        severity=Severity.CRITICAL,
        replacement="AES-256-GCM",
        notes="56-bit key brute-forceable in seconds with commodity hardware.",
    ),
    "3des": AlgorithmInfo(
        id="3des",
        display="Triple DES",
        category="classically_broken",
        severity=Severity.HIGH,
        replacement="AES-256-GCM",
        notes="Vulnerable to Sweet32 birthday attacks; deprecated by NIST SP 800-131A.",
    ),
    "rc4": AlgorithmInfo(
        id="rc4",
        display="RC4",
        category="classically_broken",
        severity=Severity.CRITICAL,
        replacement="AES-256-GCM or ChaCha20-Poly1305",
        notes="Keystream biases make it broken; prohibited in TLS by RFC 7465.",
    ),
    "aes_128": AlgorithmInfo(
        id="aes_128",
        display="AES-128",
        category="grover_weakened",
        severity=Severity.LOW,
        replacement="AES-256-GCM",
        notes=(
            "Grover's algorithm halves effective key strength to ~64 bits. "
            "AES-256 restores 128-bit post-quantum security."
        ),
    ),
}
