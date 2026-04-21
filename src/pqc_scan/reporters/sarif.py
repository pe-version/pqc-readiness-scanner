from __future__ import annotations

import json

from pqc_scan import __version__
from pqc_scan.algorithms import ALGORITHMS
from pqc_scan.findings import Finding, Severity


SEVERITY_TO_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
INFO_URI = "https://github.com/pe-version/pqc-readiness-scanner"


def render(findings: list[Finding]) -> str:
    payload = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "pqc-scan",
                        "version": __version__,
                        "informationUri": INFO_URI,
                        "rules": _build_rules(),
                    }
                },
                "results": [
                    _result_for(f) for f in sorted(findings, key=lambda x: x.sort_key())
                ],
            }
        ],
    }
    return json.dumps(payload, indent=2)


def _build_rules() -> list[dict]:
    rules = []
    for alg_id, info in ALGORITHMS.items():
        prefix = "QuantumVulnerable" if info.category == "shor_broken" else "WeakCrypto"
        rules.append(
            {
                "id": alg_id,
                "name": f"{prefix}_{alg_id.upper()}",
                "shortDescription": {"text": info.display},
                "fullDescription": {"text": info.notes},
                "helpUri": f"{INFO_URI}#what-it-flags",
                "defaultConfiguration": {"level": SEVERITY_TO_LEVEL[info.severity]},
                "properties": {
                    "category": info.category,
                    "severity": info.severity.value,
                    "recommended_replacement": info.replacement,
                },
            }
        )
    return rules


def _result_for(f: Finding) -> dict:
    location: dict = {
        "physicalLocation": {
            "artifactLocation": {"uri": f.location},
        }
    }
    if f.line is not None:
        location["physicalLocation"]["region"] = {"startLine": f.line}
    return {
        "ruleId": f.algorithm_id,
        "level": SEVERITY_TO_LEVEL[f.severity],
        "message": {
            "text": (
                f"{f.algorithm_display} detected. {f.notes} "
                f"Recommended replacement: {f.replacement}"
            )
        },
        "locations": [location],
        "properties": {
            "scanner": f.scanner,
            "context": f.context,
            "category": f.category,
            "severity": f.severity.value,
        },
    }
