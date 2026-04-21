from __future__ import annotations

import sys
from pathlib import Path

import click
from rich.console import Console

from pqc_scan import __version__
from pqc_scan.findings import Finding, Severity
from pqc_scan.reporters import console as console_report
from pqc_scan.reporters import csv_inventory, cyclonedx, json_report, markdown, sarif
from pqc_scan.scanners import certificates as cert_scanner
from pqc_scan.scanners import source_code as source_scanner
from pqc_scan.scanners import ssh_keys as ssh_scanner
from pqc_scan.scanners import tls_endpoint as tls_scanner


def _parse_endpoint(value: str) -> tuple[str, int]:
    if ":" in value:
        host, port = value.rsplit(":", 1)
        return host, int(port)
    return value, 443


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("path", required=False, type=click.Path(exists=True, path_type=Path))
@click.option(
    "--endpoint", "endpoints", multiple=True, metavar="HOST[:PORT]",
    help="TLS endpoint to probe. May be given multiple times.",
)
@click.option(
    "--json", "json_out", type=click.Path(path_type=Path),
    help="Write a JSON report to this file.",
)
@click.option(
    "--md", "md_out", type=click.Path(path_type=Path),
    help="Write a Markdown report to this file.",
)
@click.option(
    "--sarif", "sarif_out", type=click.Path(path_type=Path),
    help="Write a SARIF v2.1.0 report (for GitHub code scanning, ASOC tools, etc.).",
)
@click.option(
    "--cbom", "cbom_out", type=click.Path(path_type=Path),
    help="Write a CycloneDX 1.6 Cryptographic Bill of Materials (CBOM) JSON.",
)
@click.option(
    "--csv", "csv_out", type=click.Path(path_type=Path),
    help="Write a PQC inventory CSV (template based on OMB M-23-02 / NSM-10 guidance).",
)
@click.option(
    "--fail-on", type=click.Choice([s.value for s in Severity]), default=None,
    help="Exit non-zero if any finding meets or exceeds this severity.",
)
@click.option("--no-source", is_flag=True, help="Skip the source-code scan.")
@click.option("--no-certs", is_flag=True, help="Skip the certificate scan.")
@click.option("--no-ssh", is_flag=True, help="Skip the SSH-key scan.")
@click.version_option(__version__, prog_name="pqc-scan")
def main(
    path: Path | None,
    endpoints: tuple[str, ...],
    json_out: Path | None,
    md_out: Path | None,
    sarif_out: Path | None,
    cbom_out: Path | None,
    csv_out: Path | None,
    fail_on: str | None,
    no_source: bool,
    no_certs: bool,
    no_ssh: bool,
) -> None:
    """Scan for quantum-vulnerable cryptography.

    PATH is a directory or file to scan. Use --endpoint to probe live TLS hosts.
    At least one of PATH or --endpoint is required.
    """
    if path is None and not endpoints:
        raise click.UsageError("Provide a PATH and/or at least one --endpoint.")

    findings: list[Finding] = []
    if path is not None:
        if not no_source:
            findings.extend(source_scanner.scan_path(path))
        if not no_certs:
            findings.extend(cert_scanner.scan_path(path))
        if not no_ssh:
            findings.extend(ssh_scanner.scan_path(path))
    for ep in endpoints:
        host, port = _parse_endpoint(ep)
        findings.extend(tls_scanner.scan_endpoint(host, port))

    target_label = str(path) if path else ", ".join(endpoints)

    console = Console()
    console_report.render(findings, console)

    if json_out is not None:
        json_out.write_text(json_report.render(findings))
        console.print(f"\n[dim]JSON report written to {json_out}[/dim]")
    if md_out is not None:
        md_out.write_text(markdown.render(findings, target=target_label))
        console.print(f"[dim]Markdown report written to {md_out}[/dim]")
    if sarif_out is not None:
        sarif_out.write_text(sarif.render(findings))
        console.print(f"[dim]SARIF report written to {sarif_out}[/dim]")
    if cbom_out is not None:
        cbom_out.write_text(cyclonedx.render(findings, target=target_label))
        console.print(f"[dim]CycloneDX CBOM written to {cbom_out}[/dim]")
    if csv_out is not None:
        csv_out.write_text(csv_inventory.render(findings, system_name=target_label))
        console.print(f"[dim]Inventory CSV written to {csv_out}[/dim]")

    if fail_on is not None:
        threshold = Severity(fail_on).rank
        if any(f.severity.rank >= threshold for f in findings):
            sys.exit(2)
