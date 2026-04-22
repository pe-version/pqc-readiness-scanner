"""CSV inventory in the spirit of OMB M-23-02 / NSM-10 / CISA crypto-inventory templates.

OMB M-23-02 does not pin a single canonical schema; agencies submit using NIST/CISA
inventory templates that vary in detail. This reporter emits a reasonable superset
of the columns those templates ask for, suitable as a starting point for federal
PQC migration inventories.
"""

from __future__ import annotations

import csv
import io

from pqc_scan.findings import Finding


SCANNER_TO_ASSET_TYPE: dict[str, str] = {
    "source_code": "Source Code",
    "certificates": "X.509 Certificate",
    "ssh_keys": "SSH Key",
    "tls_endpoint": "TLS Endpoint",
    "jwt": "JSON Web Token",
}

ALGORITHM_FAMILY: dict[str, str] = {
    "rsa": "Public Key",
    "ecdsa": "Public Key",
    "ecdh": "Public Key",
    "dh": "Public Key",
    "dsa": "Public Key",
    "x25519": "Public Key",
    "ed25519": "Public Key",
    "md5": "Hash",
    "sha1": "Hash",
    "des": "Symmetric Cipher",
    "3des": "Symmetric Cipher",
    "rc4": "Symmetric Cipher",
    "aes_128": "Symmetric Cipher",
    "xmss_family": "Stateful Hash-Based Signature",
    "lms_family": "Stateful Hash-Based Signature",
    "jwt_alg_none": "JWT Misuse",
    "jwt_verify_disabled": "JWT Misuse",
    "jwt_weak_hmac_secret": "JWT Misuse",
    "jwt_rs256": "JWT Signature (Public Key)",
    "jwt_es256": "JWT Signature (Public Key)",
    "jwt_eddsa": "JWT Signature (Public Key)",
}

VULNERABILITY_REASON: dict[str, str] = {
    "shor_broken": "Shor's algorithm",
    "grover_weakened": "Grover's algorithm",
    "classically_broken": "Classical cryptanalysis",
    "pqc_safe": "N/A",
    "pqc_safe_with_caveats": "N/A (state management required)",
    "jwt_pqc_migration": "Shor's algorithm (via JWT signature)",
    "jwt_classical_misuse": "Classical JWT misuse",
}

QUANTUM_VULNERABLE_CATEGORIES = {
    "shor_broken",
    "grover_weakened",
    "jwt_pqc_migration",
}


def render(findings: list[Finding], system_name: str = "") -> str:
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(
        [
            "System Name",
            "Asset Type",
            "Rule ID",
            "Algorithm",
            "Algorithm Family",
            "Quantum Vulnerable",
            "Vulnerability Source",
            "Severity",
            "Recommended Replacement",
            "Location",
            "Line",
            "In Test Path",
            "Context",
            "Notes",
        ]
    )
    for f in sorted(findings, key=lambda x: x.sort_key()):
        quantum_vuln = "Yes" if f.category in QUANTUM_VULNERABLE_CATEGORIES else "No"
        algo_name = f.algorithm_display.split(" (")[0]
        writer.writerow(
            [
                system_name,
                SCANNER_TO_ASSET_TYPE.get(f.scanner, f.scanner),
                f.rule_id,
                algo_name,
                ALGORITHM_FAMILY.get(f.algorithm_id, "Other"),
                quantum_vuln,
                VULNERABILITY_REASON.get(f.category, "Unknown"),
                f.severity.value,
                f.replacement,
                f.location,
                f.line if f.line is not None else "",
                "Yes" if f.in_test_path else "No",
                f.context,
                f.notes,
            ]
        )
    return out.getvalue()
