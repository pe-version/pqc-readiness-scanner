from pathlib import Path

from pqc_scan.scanners.source_code import scan_file, scan_path

FIXTURES = Path(__file__).parent / "fixtures"


def test_detects_rsa_in_python():
    findings = scan_file(FIXTURES / "vulnerable_code.py")
    assert any(f.algorithm_id == "rsa" for f in findings)


def test_detects_md5_and_sha1_in_python():
    findings = scan_file(FIXTURES / "vulnerable_code.py")
    algs = {f.algorithm_id for f in findings}
    assert "md5" in algs
    assert "sha1" in algs


def test_detects_ec_in_python():
    findings = scan_file(FIXTURES / "vulnerable_code.py")
    assert any(f.algorithm_id == "ecdsa" for f in findings)


def test_safe_code_has_no_findings():
    findings = scan_file(FIXTURES / "safe_code.py")
    assert findings == []


def test_detects_node_js_rsa():
    findings = scan_file(FIXTURES / "vulnerable_app.js")
    algs = {f.algorithm_id for f in findings}
    assert "rsa" in algs
    assert "md5" in algs


def test_detects_go_ecdsa():
    findings = scan_file(FIXTURES / "vulnerable_app.go")
    assert any(f.algorithm_id == "ecdsa" for f in findings)


def test_directory_scan_aggregates_files():
    findings = scan_path(FIXTURES)
    locations = {f.location for f in findings}
    assert any(loc.endswith("vulnerable_code.py") for loc in locations)
    assert any(loc.endswith("vulnerable_app.js") for loc in locations)
    assert any(loc.endswith("vulnerable_app.go") for loc in locations)


def test_skips_minified_lines(tmp_path: Path):
    long_line = "RSA " * 500  # > 1000 chars
    p = tmp_path / "min.js"
    p.write_text(long_line + "\n")
    assert scan_file(p) == []
