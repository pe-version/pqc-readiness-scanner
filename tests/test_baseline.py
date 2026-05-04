"""Tests for the project-wide baseline file (`.pqc-scan-baseline.yml`).

The baseline runs after scanner aggregation but before report rendering, so
all reporters see the same filtered set. Path matching is prefix-based on the
finding's location field.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from pqc_scan.baseline import (
    Baseline,
    BaselineEntry,
    BaselineError,
    discover_baseline,
    load_baseline,
)
from pqc_scan.findings import Finding, Severity


def _f(rule_id: str, location: str) -> Finding:
    return Finding(
        rule_id=rule_id,
        algorithm_id="rsa",
        algorithm_display="RSA",
        severity=Severity.HIGH,
        category="shor_broken",
        location=location,
        line=1,
        context="",
        scanner="source",
        replacement="ML-KEM",
        notes="",
        in_test_path=False,
    )


def test_baseline_with_no_entries_is_a_noop():
    baseline = Baseline(entries=())
    findings = [_f("pqc-scan.source.rsa", "src/auth.py")]
    assert baseline.filter(findings) == findings


def test_global_rule_suppression_drops_every_match(tmp_path: Path):
    cfg = tmp_path / "baseline.yml"
    cfg.write_text(
        "suppressions:\n"
        "  - rule: pqc-scan.source.rsa\n"
        "    reason: tracked in #1\n"
    )
    baseline = load_baseline(cfg)
    findings = [
        _f("pqc-scan.source.rsa", "src/auth.py"),
        _f("pqc-scan.source.rsa", "src/keys.py"),
        _f("pqc-scan.source.md5", "src/hash.py"),
    ]
    filtered = baseline.filter(findings)
    rule_ids = {f.rule_id for f in filtered}
    assert "pqc-scan.source.rsa" not in rule_ids
    assert "pqc-scan.source.md5" in rule_ids


def test_path_prefix_suppression_only_matches_under_prefix(tmp_path: Path):
    cfg = tmp_path / "baseline.yml"
    cfg.write_text(
        "suppressions:\n"
        "  - rule: pqc-scan.source.rsa\n"
        "    paths: ['tests/']\n"
    )
    baseline = load_baseline(cfg)
    findings = [
        _f("pqc-scan.source.rsa", "tests/fixtures/x.py"),
        _f("pqc-scan.source.rsa", "src/auth.py"),
    ]
    filtered = baseline.filter(findings)
    locations = [f.location for f in filtered]
    assert locations == ["src/auth.py"]


def test_multiple_paths_in_one_rule(tmp_path: Path):
    cfg = tmp_path / "baseline.yml"
    cfg.write_text(
        "suppressions:\n"
        "  - rule: pqc-scan.source.rsa\n"
        "    paths: ['tests/', 'build/', 'vendor/']\n"
    )
    baseline = load_baseline(cfg)
    findings = [
        _f("pqc-scan.source.rsa", "tests/x.py"),
        _f("pqc-scan.source.rsa", "build/y.py"),
        _f("pqc-scan.source.rsa", "vendor/z.py"),
        _f("pqc-scan.source.rsa", "src/keep.py"),
    ]
    filtered = baseline.filter(findings)
    assert [f.location for f in filtered] == ["src/keep.py"]


def test_path_match_is_not_a_substring_match():
    """`tests/` must not match `mytests/`. Prefix only, on path components."""
    entry = BaselineEntry(rule_id="r", paths=("tests/",))
    assert not entry.matches(_f("r", "mytests/x.py"))
    assert entry.matches(_f("r", "tests/x.py"))


def test_exact_path_match():
    entry = BaselineEntry(rule_id="r", paths=("src/legacy_etag.py",))
    assert entry.matches(_f("r", "src/legacy_etag.py"))
    assert not entry.matches(_f("r", "src/legacy_etag_other.py"))


def test_path_match_works_with_scan_root_prefix():
    """In real runs, locations include the scan-root prefix
    (e.g. `proj/src/auth.py`). A baseline written as `paths: ['src/']` should
    still match a finding under `proj/src/auth.py`, otherwise the baseline
    would be coupled to the exact invocation path.
    """
    entry = BaselineEntry(rule_id="r", paths=("src/",))
    assert entry.matches(_f("r", "proj/src/auth.py"))
    assert entry.matches(_f("r", "./proj/src/auth.py"))
    assert not entry.matches(_f("r", "proj/lib/auth.py"))


def test_exact_file_match_works_with_scan_root_prefix():
    entry = BaselineEntry(rule_id="r", paths=("src/legacy_etag.py",))
    assert entry.matches(_f("r", "proj/src/legacy_etag.py"))
    assert not entry.matches(_f("r", "proj/src/legacy_etag_other.py"))


def test_load_handles_empty_file(tmp_path: Path):
    cfg = tmp_path / "baseline.yml"
    cfg.write_text("")
    baseline = load_baseline(cfg)
    assert baseline.entries == ()


def test_load_handles_missing_paths_field(tmp_path: Path):
    cfg = tmp_path / "baseline.yml"
    cfg.write_text("suppressions:\n  - rule: pqc-scan.foo\n")
    baseline = load_baseline(cfg)
    assert len(baseline.entries) == 1
    assert baseline.entries[0].paths == ()  # global


def test_load_rejects_top_level_list(tmp_path: Path):
    cfg = tmp_path / "baseline.yml"
    cfg.write_text("- rule: foo\n")
    with pytest.raises(BaselineError):
        load_baseline(cfg)


def test_load_rejects_missing_rule(tmp_path: Path):
    cfg = tmp_path / "baseline.yml"
    cfg.write_text("suppressions:\n  - paths: [foo/]\n")
    with pytest.raises(BaselineError):
        load_baseline(cfg)


def test_load_rejects_invalid_yaml(tmp_path: Path):
    cfg = tmp_path / "baseline.yml"
    cfg.write_text("suppressions:\n  - rule: foo\n  paths: [\n")
    with pytest.raises(BaselineError):
        load_baseline(cfg)


def test_discover_baseline_finds_target_dir_first(tmp_path: Path, monkeypatch):
    target = tmp_path / "proj"
    target.mkdir()
    target_baseline = target / ".pqc-scan-baseline.yml"
    target_baseline.write_text("suppressions: []\n")
    monkeypatch.chdir(tmp_path)
    found = discover_baseline(target)
    assert found == target_baseline


def test_discover_baseline_falls_back_to_cwd(tmp_path: Path, monkeypatch):
    cwd_baseline = tmp_path / ".pqc-scan-baseline.yml"
    cwd_baseline.write_text("suppressions: []\n")
    monkeypatch.chdir(tmp_path)
    target = tmp_path / "elsewhere"
    target.mkdir()
    found = discover_baseline(target)
    assert found == cwd_baseline


def test_discover_baseline_returns_none_when_absent(tmp_path: Path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert discover_baseline(tmp_path) is None
