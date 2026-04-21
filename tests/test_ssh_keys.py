from pathlib import Path

from pqc_scan.scanners.ssh_keys import scan_file


def test_authorized_keys_detection(tmp_path: Path):
    p = tmp_path / "authorized_keys"
    p.write_text(
        "ssh-rsa AAAAB3NzaC1yc2E user@host\n"
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 user@host\n"
        "# a comment line, ignored\n"
    )
    findings = scan_file(p)
    algs = {f.algorithm_id for f in findings}
    assert "rsa" in algs
    assert "ed25519" in algs


def test_known_hosts_detection(tmp_path: Path):
    p = tmp_path / "known_hosts"
    p.write_text("github.com,140.82.0.0 ssh-rsa AAAAB3NzaC1yc2E\n")
    findings = scan_file(p)
    assert any(f.algorithm_id == "rsa" for f in findings)


def test_ecdsa_pub_key(tmp_path: Path):
    p = tmp_path / "id_ecdsa.pub"
    p.write_text("ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHA= user@host\n")
    findings = scan_file(p)
    assert any(f.algorithm_id == "ecdsa" for f in findings)
