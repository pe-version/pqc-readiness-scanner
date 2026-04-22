from __future__ import annotations

import datetime as dt
import json
import uuid

from pqc_scan import __version__
from pqc_scan.findings import Finding


# Map algorithm ids to CycloneDX cryptoProperties.algorithmProperties.primitive
# (CycloneDX 1.6 enum: drbg, mac, block-cipher, stream-cipher, signature, hash,
#  pke, xof, kdf, key-agree, kem, ae, combiner, other, unknown)
PRIMITIVE_MAP: dict[str, str] = {
    "rsa": "pke",
    "ecdsa": "signature",
    "ecdh": "key-agree",
    "dh": "key-agree",
    "dsa": "signature",
    "x25519": "key-agree",
    "ed25519": "signature",
    "md5": "hash",
    "sha1": "hash",
    "des": "block-cipher",
    "3des": "block-cipher",
    "rc4": "stream-cipher",
    "aes_128": "block-cipher",
    "xmss_family": "signature",
    "lms_family": "signature",
    "jwt_alg_none": "signature",
    "jwt_verify_disabled": "signature",
    "jwt_weak_hmac_secret": "mac",
    "jwt_rs256": "signature",
    "jwt_es256": "signature",
    "jwt_eddsa": "signature",
}

OID_MAP: dict[str, str] = {
    "rsa": "1.2.840.113549.1.1.1",
    "ecdsa": "1.2.840.10045.2.1",
    "dsa": "1.2.840.10040.4.1",
    "ed25519": "1.3.101.112",
    "x25519": "1.3.101.110",
    "md5": "1.2.840.113549.2.5",
    "sha1": "1.3.14.3.2.26",
    "des": "1.3.14.3.2.7",
    "3des": "1.2.840.113549.3.7",
    "rc4": "1.2.840.113549.3.4",
    "aes_128": "2.16.840.1.101.3.4.1.2",
    # XMSS / LMS OIDs are advisory: the family-level entries cover multiple
    # variants, so the OID here points at the most common parent identifier.
    "xmss_family": "1.3.6.1.4.1.45724.2.1.1",
    "lms_family": "1.2.840.113549.1.9.16.3.17",
}

# CycloneDX 1.6 nistQuantumSecurityLevel: 0 = quantum-vulnerable / not applicable;
# 1-5 correspond to the NIST PQC categories. We assign by primitive category, not
# by claimed parameter set, since the scanner doesn't observe parameters.
CATEGORY_TO_NIST_LEVEL: dict[str, int] = {
    "shor_broken": 0,
    "grover_weakened": 0,
    "classically_broken": 0,
    "pqc_safe": 3,             # ML-KEM-768 / ML-DSA-65 baseline
    "pqc_safe_with_caveats": 3,
    "jwt_pqc_migration": 0,
    "jwt_classical_misuse": 0,
}


def render(findings: list[Finding], target: str = "") -> str:
    timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    sorted_findings = sorted(findings, key=lambda x: x.sort_key())
    components = [_component_for(idx, f) for idx, f in enumerate(sorted_findings)]

    payload = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "pqc-scan",
                        "version": __version__,
                    }
                ],
            },
            "properties": [
                {"name": "pqc-scan:target", "value": target or "<unspecified>"},
                {"name": "pqc-scan:finding-count", "value": str(len(findings))},
            ],
        },
        "components": components,
    }
    return json.dumps(payload, indent=2)


def _component_for(idx: int, f: Finding) -> dict:
    name = f.algorithm_display.split(" (")[0]
    primitive = PRIMITIVE_MAP.get(f.algorithm_id, "unknown")
    location_str = f.location + (f":{f.line}" if f.line else "")
    component: dict = {
        "type": "cryptographic-asset",
        "bom-ref": f"pqc-finding-{idx:04d}-{f.algorithm_id}",
        "name": name,
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": {
                "primitive": primitive,
                "parameterSetIdentifier": name,
                "executionEnvironment": "software-plain-ram",
                "implementationPlatform": "generic",
                "certificationLevel": ["none"],
                "nistQuantumSecurityLevel": CATEGORY_TO_NIST_LEVEL.get(f.category, 0),
            },
        },
        "evidence": {"occurrences": [{"location": location_str}]},
        "properties": [
            {"name": "pqc:rule-id", "value": f.rule_id},
            {"name": "pqc:severity", "value": f.severity.value},
            {"name": "pqc:category", "value": f.category},
            {"name": "pqc:recommended-replacement", "value": f.replacement},
            {"name": "pqc:scanner", "value": f.scanner},
            {"name": "pqc:in-test-path", "value": "true" if f.in_test_path else "false"},
        ],
    }
    if f.algorithm_id in OID_MAP:
        component["cryptoProperties"]["oid"] = OID_MAP[f.algorithm_id]
    return component
