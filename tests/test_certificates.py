from pqc_scan.scanners.certificates import scan_file


def test_rsa_cert_flagged(rsa_cert):
    findings = scan_file(rsa_cert)
    assert any(f.algorithm_id == "rsa" for f in findings)


def test_ed25519_cert_flagged(ed25519_cert):
    findings = scan_file(ed25519_cert)
    assert any(f.algorithm_id == "ed25519" for f in findings)


def test_non_cert_file_returns_empty(tmp_path):
    p = tmp_path / "nope.txt"
    p.write_text("not a cert")
    assert scan_file(p) == []
