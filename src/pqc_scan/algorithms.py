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
    "pqc_safe_with_caveats": (
        "Post-quantum-secure primitive whose safe use depends on operational "
        "conditions this tool cannot verify (e.g. correct state management for "
        "stateful hash-based signatures per NIST SP 800-208 §6). Reported as "
        "informational inventory; verify operational guarantees separately."
    ),
    "jwt_pqc_migration": (
        "JSON Web Token signing algorithm whose underlying primitive is broken "
        "by Shor's algorithm and must be migrated as part of PQC readiness."
    ),
    "jwt_classical_misuse": (
        "JSON Web Token usage pattern with a known classical security failure "
        "(e.g. 'alg: none', signature verification disabled, weak HMAC secret). "
        "Reported because it co-occurs with the PQC migration surface; not a "
        "general crypto-hygiene rule."
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
        severity=Severity.HIGH,
        replacement="Hybrid X25519 + ML-KEM (recommended near-term migration path)",
        notes=(
            "Curve25519 ECDH is broken by Shor's algorithm identically to RSA/ECDH. "
            "Hybrid X25519 + ML-KEM is the recommended migration path, retaining "
            "X25519 as the classical half for defense-in-depth — that's a deployment "
            "recommendation, not a reduction in primitive risk."
        ),
    ),
    "ed25519": AlgorithmInfo(
        id="ed25519",
        display="Ed25519",
        category="shor_broken",
        severity=Severity.HIGH,
        replacement="ML-DSA (FIPS 204) or hybrid Ed25519 + ML-DSA",
        notes=(
            "EdDSA over Curve25519 is broken by Shor's algorithm identically to ECDSA. "
            "Hybrid constructions retain Ed25519 as the classical half for defense-in-depth; "
            "that's a deployment recommendation, not a reduction in primitive risk."
        ),
    ),
    "md5": AlgorithmInfo(
        id="md5",
        display="MD5",
        category="classically_broken",
        severity=Severity.CRITICAL,
        replacement="SHA-256 / SHA-3-256 (or SHA-384+ for long-term assurance)",
        notes=(
            "Collisions trivially producible. Unsafe for any security purpose. "
            "If used as a non-cryptographic content hash (cache keys, ETags, content "
            "addressing), changing to SHA-256 will alter output bytes — coordinate "
            "the change with downstream consumers."
        ),
    ),
    "sha1": AlgorithmInfo(
        id="sha1",
        display="SHA-1",
        category="classically_broken",
        severity=Severity.HIGH,
        replacement="SHA-256 / SHA-3-256 (or SHA-384+ for long-term assurance)",
        notes=(
            "Practical collisions demonstrated (SHAttered, 2017). Deprecated by NIST. "
            "If used as a non-cryptographic content hash (e.g. git object IDs, dedup "
            "keys), changing to SHA-256 will alter output bytes — coordinate with "
            "downstream consumers."
        ),
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
    "xmss_family": AlgorithmInfo(
        id="xmss_family",
        display="XMSS / XMSSMT (stateful hash-based signature)",
        category="pqc_safe_with_caveats",
        severity=Severity.INFO,
        replacement="N/A — PQC-safe; verify state management.",
        notes=(
            "XMSS (RFC 8391) and its multi-tree variant XMSSMT are PQC-safe stateful "
            "hash-based signatures standardized by NIST SP 800-208. Safety depends on "
            "never reusing one-time keys, which requires careful state persistence. "
            "This tool detects use, not state-management correctness — see SP 800-208 §6."
        ),
    ),
    "lms_family": AlgorithmInfo(
        id="lms_family",
        display="LMS / HSS-LMS (stateful hash-based signature)",
        category="pqc_safe_with_caveats",
        severity=Severity.INFO,
        replacement="N/A — PQC-safe; verify state management.",
        notes=(
            "LMS (RFC 8554) and its hierarchical variant HSS are PQC-safe stateful "
            "hash-based signatures standardized by NIST SP 800-208. Safety depends on "
            "never reusing one-time keys, which requires careful state persistence. "
            "This tool detects use, not state-management correctness — see SP 800-208 §6."
        ),
    ),
    "jwt_alg_none": AlgorithmInfo(
        id="jwt_alg_none",
        display="JWT alg=none",
        category="jwt_classical_misuse",
        severity=Severity.CRITICAL,
        replacement="Require an explicit signing algorithm; reject 'none' on verification.",
        notes=(
            "RFC 7519 permits an unsecured JWS with alg='none'. Accepting it during "
            "verification allows attacker-forged tokens. Pin the accepted algorithm "
            "list and reject unsigned tokens (RFC 8725 §3.2)."
        ),
    ),
    "jwt_verify_disabled": AlgorithmInfo(
        id="jwt_verify_disabled",
        display="JWT signature verification disabled",
        category="jwt_classical_misuse",
        severity=Severity.HIGH,
        replacement="Verify signatures with a pinned algorithm allowlist.",
        notes=(
            "Calls like jwt.decode(..., verify=False) or algorithms=None accept any "
            "JWT including forged ones. Required for PQC migration sanity (you cannot "
            "migrate signing if signing isn't checked). RFC 8725 §3.1."
        ),
    ),
    "jwt_weak_hmac_secret": AlgorithmInfo(
        id="jwt_weak_hmac_secret",
        display="JWT HMAC secret too short (literal in source)",
        category="jwt_classical_misuse",
        severity=Severity.HIGH,
        replacement="Use a randomly generated secret of at least 32 bytes loaded from a secret store.",
        notes=(
            "HMAC-SHA256 needs a secret of at least the hash output length (32 bytes). "
            "Short literal secrets are brute-forceable and frequently leaked via VCS. "
            "Reported only when a string literal of <32 bytes is the visible secret."
        ),
    ),
    "jwt_rs256": AlgorithmInfo(
        id="jwt_rs256",
        display="JWT RS256 / RS384 / RS512 (RSA signature)",
        category="jwt_pqc_migration",
        severity=Severity.HIGH,
        replacement="ML-DSA (FIPS 204) once your JWT library and counterparties support it.",
        notes=(
            "RSA-PKCS1v1.5 signatures inside JWS. Broken by Shor's algorithm; part of "
            "the PQC migration surface for any service issuing or verifying JWTs."
        ),
    ),
    "jwt_es256": AlgorithmInfo(
        id="jwt_es256",
        display="JWT ES256 / ES384 / ES512 (ECDSA signature)",
        category="jwt_pqc_migration",
        severity=Severity.HIGH,
        replacement="ML-DSA (FIPS 204) once your JWT library and counterparties support it.",
        notes=(
            "ECDSA signatures inside JWS. Broken by Shor's algorithm; part of the PQC "
            "migration surface for any service issuing or verifying JWTs."
        ),
    ),
    "jwt_eddsa": AlgorithmInfo(
        id="jwt_eddsa",
        display="JWT EdDSA (Ed25519 signature)",
        category="jwt_pqc_migration",
        severity=Severity.HIGH,
        replacement="ML-DSA (FIPS 204) once your JWT library and counterparties support it.",
        notes=(
            "EdDSA (Ed25519) signatures inside JWS. Broken by Shor's algorithm; part "
            "of the PQC migration surface for any service issuing or verifying JWTs."
        ),
    ),
}
