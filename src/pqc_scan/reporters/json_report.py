from __future__ import annotations

import json
from dataclasses import asdict

from pqc_scan.findings import Finding


def render(findings: list[Finding]) -> str:
    payload = {
        "version": 1,
        "finding_count": len(findings),
        "findings": [_serialize(f) for f in sorted(findings, key=lambda x: x.sort_key())],
    }
    return json.dumps(payload, indent=2)


def _serialize(f: Finding) -> dict:
    d = asdict(f)
    d["severity"] = f.severity.value
    return d
