from __future__ import annotations

import json

from pqc_scan import __version__
from pqc_scan.findings import Finding, Severity

# Use the OASIS-published 2.1.0 schema URL. The historical raw.githubusercontent
# path under the "master" branch returns 404 because the spec repo's default
# branch was renamed; the docs.oasis-open.org URL is the durable canonical.
SARIF_SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
INFO_URI = "https://github.com/pe-version/pqc-readiness-scanner"

SEVERITY_TO_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def render(findings: list[Finding]) -> str:
    sorted_findings = sorted(findings, key=lambda x: x.sort_key())
    rules = _build_rules(sorted_findings)
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
                        "rules": rules,
                    }
                },
                "results": [_result_for(f) for f in sorted_findings],
            }
        ],
    }
    return json.dumps(payload, indent=2)


def _build_rules(findings: list[Finding]) -> list[dict]:
    """Emit one SARIF rule per distinct rule_id observed in this run.

    Per the SARIF 2.1.0 spec, results.ruleId must reference an entry in
    tool.driver.rules. Emitting only observed rules keeps the report compact
    while remaining valid.
    """
    seen: dict[str, Finding] = {}
    for f in findings:
        seen.setdefault(f.rule_id, f)
    rules: list[dict] = []
    for rule_id, f in sorted(seen.items()):
        rules.append(
            {
                "id": rule_id,
                "name": rule_id.replace(".", "_").replace("-", "_"),
                "shortDescription": {"text": f.algorithm_display},
                "fullDescription": {"text": f.notes},
                "helpUri": f"{INFO_URI}#what-it-flags",
                "defaultConfiguration": {"level": SEVERITY_TO_LEVEL[f.severity]},
                "properties": {
                    "category": f.category,
                    "severity": f.severity.value,
                    "recommended_replacement": f.replacement,
                    "algorithm_id": f.algorithm_id,
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
        "ruleId": f.rule_id,
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
            "in_test_path": f.in_test_path,
        },
    }
