"""Tests for inline suppression, dedup-key fix, and in_test_path tagging
in the source-code scanner.
"""

from __future__ import annotations

from pathlib import Path

from pqc_scan.scanners import source_code


def _write(tmp_path: Path, name: str, body: str) -> Path:
    path = tmp_path / name
    path.write_text(body)
    return path


def test_suppression_blanket_silences_line(tmp_path: Path):
    body = "import hashlib; hashlib.md5(b'x')  # pqc-scan: ignore\n"
    path = _write(tmp_path, "x.py", body)
    findings = source_code.scan_path(path)
    assert findings == []


def test_suppression_specific_rule_silences_only_named_rule(tmp_path: Path):
    body = (
        "import hashlib; hashlib.md5(b'x'); hashlib.sha1(b'y')"
        "  # pqc-scan: ignore[pqc-scan.source.md5.python-hashlib]\n"
    )
    path = _write(tmp_path, "x.py", body)
    findings = source_code.scan_path(path)
    rule_ids = {f.rule_id for f in findings}
    assert "pqc-scan.source.md5.python-hashlib" not in rule_ids
    assert "pqc-scan.source.sha1.python-hashlib" in rule_ids


def test_dedup_distinguishes_different_match_positions_on_same_line(tmp_path: Path):
    # Two distinct MD5 patterns on the same line should produce two findings,
    # not one (the v0.1 dedup key collapsed them to one).
    body = "MD5(x); hashlib.md5(b'y')\n"
    path = _write(tmp_path, "x.py", body)
    findings = source_code.scan_path(path)
    md5 = [f for f in findings if f.algorithm_id == "md5"]
    assert len(md5) >= 2


def test_in_test_path_set_for_files_under_tests_directory(tmp_path: Path):
    test_dir = tmp_path / "tests"
    test_dir.mkdir()
    body = "import hashlib; hashlib.md5(b'x')\n"
    path = _write(test_dir, "test_x.py", body)
    findings = source_code.scan_path(path)
    assert findings
    assert all(f.in_test_path for f in findings)


def test_in_test_path_false_for_runtime_code(tmp_path: Path):
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    body = "import hashlib; hashlib.md5(b'x')\n"
    path = _write(src_dir, "auth.py", body)
    findings = source_code.scan_path(path)
    assert findings
    assert not any(f.in_test_path for f in findings)


def test_xmss_detected_with_pqc_safe_with_caveats_category(tmp_path: Path):
    body = "from xmss_lib import sign; alg = 'XMSS'\n"
    path = _write(tmp_path, "sig.py", body)
    findings = source_code.scan_path(path)
    xmss = [f for f in findings if f.algorithm_id == "xmss_family"]
    assert xmss
    assert all(f.category == "pqc_safe_with_caveats" for f in xmss)
