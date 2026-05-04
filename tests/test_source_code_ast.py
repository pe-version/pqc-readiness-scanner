"""Tests for the AST-based Python source scanner.

Two complementary checks:

1. Recall — the AST scanner finds the same crypto calls that the regex
   scanner already finds in `vulnerable_code.py`. Same rule_ids by design,
   so the CLI's dedup keeps just one finding per (rule_id, location, line).

2. Precision — the AST scanner does NOT fire on the false-positive
   patterns the regex scanner has historically over-reported (string
   literals, comments, unrelated class names, shadowed identifiers).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from pqc_scan.scanners import source_code, source_code_ast


FIXTURES = Path(__file__).parent / "fixtures"
VULNERABLE = FIXTURES / "vulnerable_code.py"
FALSE_POSITIVES = FIXTURES / "ast_false_positives.py"


def test_ast_finds_md5_call():
    findings = source_code_ast.scan_path(VULNERABLE)
    rule_ids = {f.rule_id for f in findings}
    assert "pqc-scan.source.md5.python-hashlib" in rule_ids


def test_ast_finds_sha1_call():
    findings = source_code_ast.scan_path(VULNERABLE)
    rule_ids = {f.rule_id for f in findings}
    assert "pqc-scan.source.sha1.python-hashlib" in rule_ids


def test_ast_finds_rsa_call_through_aliased_import():
    findings = source_code_ast.scan_path(VULNERABLE)
    rule_ids = {f.rule_id for f in findings}
    assert "pqc-scan.source.rsa.cryptography-rsa-call" in rule_ids


def test_ast_finds_ec_call_through_aliased_import():
    findings = source_code_ast.scan_path(VULNERABLE)
    rule_ids = {f.rule_id for f in findings}
    assert "pqc-scan.source.ecdsa.cryptography-ec-call" in rule_ids


def test_ast_uses_same_rule_ids_as_regex():
    """Critical for CLI dedup: AST and regex must share rule_ids exactly so a
    single (rule_id, location, line) finding is reported once."""
    ast_findings = source_code_ast.scan_path(VULNERABLE)
    regex_findings = source_code.scan_path(VULNERABLE)
    ast_rules = {(f.rule_id, f.line) for f in ast_findings}
    regex_rules = {(f.rule_id, f.line) for f in regex_findings}
    overlap = ast_rules & regex_rules
    assert len(overlap) >= 4, f"expected dedup overlap of at least 4 entries; got {overlap}"


def test_ast_does_not_fire_on_string_literals():
    findings = source_code_ast.scan_path(FALSE_POSITIVES)
    contexts = [f.context for f in findings]
    assert all("md5" not in ctx.lower() for ctx in contexts), (
        f"AST scanner fired on a string literal; findings: {findings}"
    )


def test_ast_does_not_fire_on_comments_or_docstrings():
    """The fixture has 'hashlib.md5' inside a docstring — AST must not match."""
    findings = source_code_ast.scan_path(FALSE_POSITIVES)
    assert not findings or all(
        f.rule_id not in {
            "pqc-scan.source.md5.python-hashlib",
            "pqc-scan.source.sha1.python-hashlib",
        }
        for f in findings
    ), f"AST flagged docstring/comment mentions: {findings}"


def test_ast_does_not_fire_on_shadowed_local_class():
    """`class rsa:` shadows the crypto module name; calls to it must not be
    flagged as RSA."""
    findings = source_code_ast.scan_path(FALSE_POSITIVES)
    rsa_findings = [
        f for f in findings if f.rule_id == "pqc-scan.source.rsa.cryptography-rsa-call"
    ]
    assert rsa_findings == [], f"AST flagged a shadowed local class: {rsa_findings}"


def test_ast_handles_syntax_errors_gracefully(tmp_path: Path):
    """A file that fails to parse should produce no findings, not raise."""
    bad = tmp_path / "bad.py"
    bad.write_text("def broken(:\n    pass\n")  # syntax error
    findings = source_code_ast.scan_path(bad)
    assert findings == []


def test_ast_skips_test_directories_via_in_test_path(tmp_path: Path):
    """`in_test_path` is set when path contains a test/ component."""
    test_dir = tmp_path / "tests"
    test_dir.mkdir()
    test_file = test_dir / "test_x.py"
    test_file.write_text("import hashlib\nhashlib.md5(b'x')\n")
    findings = source_code_ast.scan_path(test_file)
    assert findings
    assert all(f.in_test_path for f in findings)


def test_ast_finds_aliased_import(tmp_path: Path):
    """Regex CANNOT match this; only AST can. This is the main precision win."""
    src = tmp_path / "alias.py"
    src.write_text(
        "from hashlib import md5 as content_hash\n"
        "content_hash(b'x')\n"
    )
    findings = source_code_ast.scan_path(src)
    rule_ids = {f.rule_id for f in findings}
    assert "pqc-scan.source.md5.python-hashlib" in rule_ids


def test_ast_respects_inline_suppression(tmp_path: Path):
    src = tmp_path / "suppressed.py"
    src.write_text("import hashlib\nhashlib.md5(b'x')  # pqc-scan: ignore\n")
    findings = source_code_ast.scan_path(src)
    assert findings == []


def test_ast_respects_specific_rule_suppression(tmp_path: Path):
    src = tmp_path / "specific.py"
    src.write_text(
        "import hashlib\n"
        "hashlib.md5(b'x'); hashlib.sha1(b'y')  "
        "# pqc-scan: ignore[pqc-scan.source.md5.python-hashlib]\n"
    )
    findings = source_code_ast.scan_path(src)
    rule_ids = {f.rule_id for f in findings}
    assert "pqc-scan.source.md5.python-hashlib" not in rule_ids
    assert "pqc-scan.source.sha1.python-hashlib" in rule_ids
