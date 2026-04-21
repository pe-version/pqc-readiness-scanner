from __future__ import annotations

from collections import Counter

from rich.console import Console
from rich.table import Table

from pqc_scan.findings import Finding, Severity


SEVERITY_STYLES: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def render(findings: list[Finding], console: Console | None = None) -> None:
    console = console or Console()
    if not findings:
        console.print("[green]No quantum-vulnerable cryptography detected.[/green]")
        return

    counts = Counter(f.severity for f in findings)
    summary_parts = []
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO):
        n = counts.get(sev, 0)
        if n:
            summary_parts.append(f"[{SEVERITY_STYLES[sev]}]{n} {sev.value}[/]")
    console.print(f"\n[bold]Findings:[/bold] {' '.join(summary_parts)}\n")

    table = Table(show_lines=False, header_style="bold")
    table.add_column("Sev", no_wrap=True)
    table.add_column("Algorithm", no_wrap=True)
    table.add_column("Location", overflow="fold")
    table.add_column("Recommended replacement", overflow="fold")

    for f in sorted(findings, key=lambda x: x.sort_key()):
        loc = f.location + (f":{f.line}" if f.line else "")
        table.add_row(
            f"[{SEVERITY_STYLES[f.severity]}]{f.severity.value}[/]",
            f.algorithm_display,
            loc,
            f.replacement,
        )
    console.print(table)
