"""TLS Supported Groups registry, filtered to entries this scanner cares about.

Source: IANA TLS Parameters registry,
https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-8

Group IDs are 16-bit integers. Numbering is delicate — the post-quantum hybrid
codepoints in the 0x11xx range (`X25519MLKEM768`, etc.) were assigned in 2024
after extensive deployment under earlier draft codepoints (`X25519Kyber768`,
0x6399). Both are listed here so we can correctly identify either generation
in the wild.

This list is a maintenance burden: as new PQC groups are standardized and
deployed, this file must be updated. Out of date → false negatives ("classical
group selected" when in fact a newer PQC group was negotiated).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class TLSGroup:
    code: int
    name: str
    family: str  # "pqc_hybrid" | "classical_ec" | "classical_ff" | "pqc_pure"
    notes: str = ""


# PQC hybrid groups: classical + ML-KEM in parallel. These are the operational
# signal that an endpoint is post-quantum-ready today.
PQC_HYBRID_GROUPS: tuple[TLSGroup, ...] = (
    TLSGroup(
        code=0x11EC,
        name="X25519MLKEM768",
        family="pqc_hybrid",
        notes="Standardized hybrid: X25519 ECDH + ML-KEM-768 (FIPS 203). "
        "Deployed by Cloudflare, Google, AWS as of 2024-2025.",
    ),
    TLSGroup(
        code=0x11EE,
        name="SecP256r1MLKEM768",
        family="pqc_hybrid",
        notes="Standardized hybrid: NIST P-256 ECDH + ML-KEM-768.",
    ),
    TLSGroup(
        code=0x11ED,
        name="SecP384r1MLKEM1024",
        family="pqc_hybrid",
        notes="Standardized hybrid: NIST P-384 ECDH + ML-KEM-1024 (CNSA 2.0 grade).",
    ),
    TLSGroup(
        code=0x6399,
        name="X25519Kyber768Draft00",
        family="pqc_hybrid",
        notes="Legacy draft codepoint (pre-FIPS-203 Kyber). Still deployed in some "
        "environments; treated as PQC hybrid for inventory purposes.",
    ),
    TLSGroup(
        code=0xFE30,
        name="P256Kyber768Draft00",
        family="pqc_hybrid",
        notes="Legacy draft codepoint. Treated as PQC hybrid for inventory purposes.",
    ),
)


# Classical elliptic-curve and finite-field groups. All are broken by Shor's
# algorithm. Severity HIGH consistent with the ECDH/X25519 entries in algorithms.py.
CLASSICAL_GROUPS: tuple[TLSGroup, ...] = (
    TLSGroup(0x001D, "X25519", "classical_ec",
             "Curve25519 ECDH; quantum-vulnerable."),
    TLSGroup(0x001E, "X448", "classical_ec",
             "Curve448 ECDH; quantum-vulnerable."),
    TLSGroup(0x0017, "secp256r1", "classical_ec",
             "NIST P-256 ECDH; quantum-vulnerable."),
    TLSGroup(0x0018, "secp384r1", "classical_ec",
             "NIST P-384 ECDH; quantum-vulnerable."),
    TLSGroup(0x0019, "secp521r1", "classical_ec",
             "NIST P-521 ECDH; quantum-vulnerable."),
    TLSGroup(0x0100, "ffdhe2048", "classical_ff",
             "Finite-field DH (RFC 7919); quantum-vulnerable."),
    TLSGroup(0x0101, "ffdhe3072", "classical_ff",
             "Finite-field DH (RFC 7919); quantum-vulnerable."),
    TLSGroup(0x0102, "ffdhe4096", "classical_ff",
             "Finite-field DH (RFC 7919); quantum-vulnerable."),
    TLSGroup(0x0103, "ffdhe6144", "classical_ff",
             "Finite-field DH (RFC 7919); quantum-vulnerable."),
    TLSGroup(0x0104, "ffdhe8192", "classical_ff",
             "Finite-field DH (RFC 7919); quantum-vulnerable."),
)


ALL_GROUPS: dict[int, TLSGroup] = {
    g.code: g for g in (*PQC_HYBRID_GROUPS, *CLASSICAL_GROUPS)
}


def lookup(code: int) -> TLSGroup | None:
    """Return the TLSGroup for a numeric ID, or None if unknown."""
    return ALL_GROUPS.get(code)


def describe(code: int) -> str:
    """Format a group code as `Name (0xNNNN)` or `unknown (0xNNNN)`."""
    group = lookup(code)
    if group is None:
        return f"unknown (0x{code:04x})"
    return f"{group.name} (0x{code:04x})"
