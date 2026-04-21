from __future__ import annotations

from collections import Counter

from pqc_scan.findings import Finding, Severity


def render(findings: list[Finding], target: str = "") -> str:
    lines: list[str] = ["# PQC Readiness Report", ""]
    if target:
        lines.append(f"**Target:** `{target}`")
        lines.append("")
    if not findings:
        lines.append("No quantum-vulnerable cryptography detected.")
        return "\n".join(lines) + "\n"

    counts = Counter(f.severity for f in findings)
    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("| --- | --- |")
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        n = counts.get(sev, 0)
        if n:
            lines.append(f"| {sev.value} | {n} |")
    lines.append("")

    lines.append("## Findings")
    lines.append("")
    lines.append("| Severity | Algorithm | Location | Recommended replacement |")
    lines.append("| --- | --- | --- | --- |")
    for f in sorted(findings, key=lambda x: x.sort_key()):
        loc = f.location + (f":{f.line}" if f.line else "")
        lines.append(f"| {f.severity.value} | {f.algorithm_display} | `{loc}` | {f.replacement} |")
    lines.append("")

    lines.append("## Algorithm notes")
    lines.append("")
    seen: set[str] = set()
    for f in sorted(findings, key=lambda x: x.sort_key()):
        if f.algorithm_id in seen:
            continue
        seen.add(f.algorithm_id)
        lines.append(f"- **{f.algorithm_display.split(' (')[0]}** — {f.notes}")
    lines.append("")
    return "\n".join(lines)
