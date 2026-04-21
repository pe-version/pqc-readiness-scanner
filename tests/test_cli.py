from pathlib import Path

from click.testing import CliRunner

from pqc_scan.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def test_cli_reports_findings_on_fixtures():
    runner = CliRunner()
    result = runner.invoke(main, [str(FIXTURES)])
    assert result.exit_code == 0
    assert "RSA" in result.output


def test_cli_writes_json_and_markdown(tmp_path: Path):
    runner = CliRunner()
    json_path = tmp_path / "out.json"
    md_path = tmp_path / "out.md"
    result = runner.invoke(
        main,
        [str(FIXTURES), "--json", str(json_path), "--md", str(md_path)],
    )
    assert result.exit_code == 0
    assert json_path.exists() and json_path.stat().st_size > 0
    assert md_path.exists() and md_path.stat().st_size > 0
    assert "PQC Readiness Report" in md_path.read_text()


def test_cli_fail_on_high_exits_nonzero():
    runner = CliRunner()
    result = runner.invoke(main, [str(FIXTURES), "--fail-on", "high"])
    assert result.exit_code == 2


def test_cli_requires_path_or_endpoint():
    runner = CliRunner()
    result = runner.invoke(main, [])
    assert result.exit_code != 0
    assert "PATH" in result.output or "endpoint" in result.output.lower()
