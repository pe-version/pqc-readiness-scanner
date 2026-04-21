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
                "nistQuantumSecurityLevel": 0,
            },
        },
        "evidence": {"occurrences": [{"location": location_str}]},
        "properties": [
            {"name": "pqc:severity", "value": f.severity.value},
            {"name": "pqc:category", "value": f.category},
            {"name": "pqc:recommended-replacement", "value": f.replacement},
            {"name": "pqc:scanner", "value": f.scanner},
        ],
    }
    if f.algorithm_id in OID_MAP:
        component["cryptoProperties"]["oid"] = OID_MAP[f.algorithm_id]
    return component
