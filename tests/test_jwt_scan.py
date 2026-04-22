"""Tests for the JWT scanner."""

from __future__ import annotations

from pathlib import Path

from pqc_scan.scanners import jwt_scan


def _write(tmp_path: Path, name: str, body: str) -> Path:
    path = tmp_path / name
    path.write_text(body)
    return path


def test_alg_none_token_in_json_payload(tmp_path: Path):
    path = _write(tmp_path, "config.json", '{"alg": "none", "typ": "JWT"}\n')
    findings = jwt_scan.scan_path(path)
    rule_ids = {f.rule_id for f in findings}
    assert "pqc-scan.jwt.alg-none.token" in rule_ids


def test_alg_none_keyword_in_python(tmp_path: Path):
    body = 'jwt.encode(payload, key, algorithm="none")\n'
    path = _write(tmp_path, "auth.py", body)
    findings = jwt_scan.scan_path(path)
    assert any(f.algorithm_id == "jwt_alg_none" for f in findings)


def test_verify_false_in_pyjwt_decode(tmp_path: Path):
    body = 'data = jwt.decode(token, key, verify=False)\n'
    path = _write(tmp_path, "verify.py", body)
    findings = jwt_scan.scan_path(path)
    assert any(f.algorithm_id == "jwt_verify_disabled" for f in findings)


def test_rs256_string_literal_flagged_as_pqc_migration(tmp_path: Path):
    body = 'jwt.encode(payload, key, algorithm="RS256")\n'
    path = _write(tmp_path, "sign.py", body)
    findings = jwt_scan.scan_path(path)
    assert any(
        f.algorithm_id == "jwt_rs256" and f.category == "jwt_pqc_migration"
        for f in findings
    )


def test_es256_es384_es512_all_flagged(tmp_path: Path):
    for alg in ("ES256", "ES384", "ES512"):
        body = f'jwt.encode(payload, key, algorithm="{alg}")\n'
        path = _write(tmp_path, f"{alg.lower()}.py", body)
        findings = jwt_scan.scan_path(path)
        assert any(f.algorithm_id == "jwt_es256" for f in findings), alg


def test_eddsa_token_flagged(tmp_path: Path):
    body = 'jwt.encode(payload, key, algorithm="EdDSA")\n'
    path = _write(tmp_path, "ed.py", body)
    findings = jwt_scan.scan_path(path)
    assert any(f.algorithm_id == "jwt_eddsa" for f in findings)


def test_weak_hmac_secret_only_flagged_with_jwt_call(tmp_path: Path):
    # Same line, no JWT call: should NOT fire (avoid false positives on constants).
    no_call = 'X = "HS256"; secret = "short"\n'
    path = _write(tmp_path, "noncall.py", no_call)
    findings = jwt_scan.scan_path(path)
    assert not any(f.algorithm_id == "jwt_weak_hmac_secret" for f in findings)

    # Same line WITH a JWT call and a short literal: should fire.
    call = 'jwt.encode(payload, "short", algorithm="HS256")\n'
    path = _write(tmp_path, "call.py", call)
    findings = jwt_scan.scan_path(path)
    assert any(f.algorithm_id == "jwt_weak_hmac_secret" for f in findings)


def test_suppression_silences_specific_rule(tmp_path: Path):
    body = 'jwt.encode(payload, key, algorithm="RS256")  # pqc-scan: ignore[pqc-scan.jwt.rs256.token]\n'
    path = _write(tmp_path, "supp.py", body)
    findings = jwt_scan.scan_path(path)
    assert not any(f.rule_id == "pqc-scan.jwt.rs256.token" for f in findings)


def test_suppression_blanket_silences_all_rules_on_line(tmp_path: Path):
    body = 'jwt.encode(payload, "short", algorithm="HS256")  # pqc-scan: ignore\n'
    path = _write(tmp_path, "blanket.py", body)
    findings = jwt_scan.scan_path(path)
    assert findings == []


def test_jwt_finding_includes_rule_id_and_in_test_path_metadata(tmp_path: Path):
    test_dir = tmp_path / "tests"
    test_dir.mkdir()
    body = 'jwt.encode(payload, key, algorithm="RS256")\n'
    path = _write(test_dir, "test_x.py", body)
    findings = jwt_scan.scan_path(path)
    assert findings
    assert all(f.in_test_path for f in findings)
    assert all(f.rule_id.startswith("pqc-scan.jwt.") for f in findings)


def test_no_double_finding_for_same_rule_on_same_line(tmp_path: Path):
    # Two RS256 tokens on the same call site shouldn't both fire — we group per line.
    body = 'jwt.encode(payload, key, algorithm="RS256", header={"alg": "RS256"})\n'
    path = _write(tmp_path, "double.py", body)
    findings = jwt_scan.scan_path(path)
    rs256 = [f for f in findings if f.rule_id == "pqc-scan.jwt.rs256.token"]
    assert len(rs256) == 1
