"""Smoke tests for SARIF, CycloneDX CBOM, and CSV inventory reporters."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from pqc_scan.cli import main
from pqc_scan.findings import Finding, Severity
from pqc_scan.reporters import csv_inventory, cyclonedx, sarif


FIXTURES = Path(__file__).parent / "fixtures"

SAMPLE: list[Finding] = [
    Finding(
        algorithm_id="rsa",
        algorithm_display="RSA",
        severity=Severity.HIGH,
        category="shor_broken",
        location="src/x.py",
        line=10,
        context="rsa.generate_private_key(...)",
        scanner="source_code",
        replacement="ML-KEM (FIPS 203)",
        notes="Broken by Shor.",
    ),
    Finding(
        algorithm_id="md5",
        algorithm_display="MD5",
        severity=Severity.CRITICAL,
        category="classically_broken",
        location="src/y.py",
        line=22,
        context="hashlib.md5()",
        scanner="source_code",
        replacement="SHA-256",
        notes="Collisions producible.",
    ),
]


def test_sarif_renders_valid_json_with_correct_schema_version():
    text = sarif.render(SAMPLE)
    data = json.loads(text)
    assert data["version"] == "2.1.0"
    run = data["runs"][0]
    assert run["tool"]["driver"]["name"] == "pqc-scan"
    assert len(run["results"]) == 2


def test_sarif_severity_to_level_mapping():
    text = sarif.render(SAMPLE)
    data = json.loads(text)
    levels = {r["ruleId"]: r["level"] for r in data["runs"][0]["results"]}
    # CRITICAL and HIGH both map to "error" per SARIF conventions
    assert levels["rsa"] == "error"
    assert levels["md5"] == "error"


def test_cyclonedx_renders_valid_cbom():
    text = cyclonedx.render(SAMPLE, target="src/")
    data = json.loads(text)
    assert data["bomFormat"] == "CycloneDX"
    assert data["specVersion"] == "1.6"
    assert len(data["components"]) == 2
    assert all(c["type"] == "cryptographic-asset" for c in data["components"])


def test_cyclonedx_includes_well_known_oid():
    text = cyclonedx.render(SAMPLE)
    data = json.loads(text)
    rsa = next(c for c in data["components"] if c["name"] == "RSA")
    assert rsa["cryptoProperties"]["oid"] == "1.2.840.113549.1.1.1"


def test_cyclonedx_marks_quantum_security_level_zero():
    text = cyclonedx.render(SAMPLE)
    data = json.loads(text)
    for c in data["components"]:
        assert c["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"] == 0


def test_csv_writes_header_and_row_per_finding():
    text = csv_inventory.render(SAMPLE, system_name="test-system")
    lines = text.strip().split("\n")
    assert "System Name" in lines[0]
    assert len(lines) == 3  # header + 2 findings


def test_csv_distinguishes_quantum_vs_classical():
    text = csv_inventory.render(SAMPLE, system_name="test-system")
    assert "Yes" in text  # rsa = Shor-broken
    assert "No" in text   # md5 = classically broken, not quantum
    assert "Shor's algorithm" in text
    assert "Classical cryptanalysis" in text


def test_cli_writes_sarif_cbom_csv(tmp_path: Path):
    runner = CliRunner()
    sarif_path = tmp_path / "out.sarif"
    cbom_path = tmp_path / "out.cdx.json"
    csv_path = tmp_path / "out.csv"
    result = runner.invoke(
        main,
        [
            str(FIXTURES),
            "--sarif", str(sarif_path),
            "--cbom", str(cbom_path),
            "--csv", str(csv_path),
        ],
    )
    assert result.exit_code == 0, result.output
    sarif_data = json.loads(sarif_path.read_text())
    assert sarif_data["version"] == "2.1.0"
    cbom_data = json.loads(cbom_path.read_text())
    assert cbom_data["specVersion"] == "1.6"
    csv_text = csv_path.read_text()
    assert "System Name" in csv_text.splitlines()[0]
