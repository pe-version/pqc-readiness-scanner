"""Tests for the KEM-detection half of the TLS endpoint scanner.

Patches `probe_endpoint` to return canned ServerHelloInfo values, so the
findings-shaping logic can be tested without any network. The TLS record
parser itself is tested separately in `test_tls_records.py`.
"""

from __future__ import annotations

import pytest

from pqc_scan.findings import Severity
from pqc_scan.scanners import tls_endpoint
from pqc_scan.tls_records import TLS_1_3, ServerHelloInfo, TLSAlert, TLSParseError


def _make_info(
    *,
    is_hrr: bool = False,
    selected_group: int | None = 0x001D,
    selected_version: int | None = TLS_1_3,
    cipher_suite: int = 0x1301,
    legacy_version: int = 0x0303,
) -> ServerHelloInfo:
    return ServerHelloInfo(
        is_hello_retry_request=is_hrr,
        legacy_version=legacy_version,
        cipher_suite=cipher_suite,
        selected_group=selected_group,
        selected_version=selected_version,
    )


@pytest.fixture
def patch_probe(monkeypatch):
    def _set(result_or_exc):
        def fake(host, port, advertised_groups, timeout):
            if isinstance(result_or_exc, BaseException):
                raise result_or_exc
            return result_or_exc

        monkeypatch.setattr(tls_endpoint, "probe_endpoint", fake)

    return _set


@pytest.fixture
def patch_cert_probe_to_noop(monkeypatch):
    """Replace _scan_certificate with a no-op so we test only the KEM probe path."""
    monkeypatch.setattr(tls_endpoint, "_scan_certificate", lambda *a, **kw: [])


def test_classical_x25519_emits_high_kem_classical_finding(
    patch_probe, patch_cert_probe_to_noop
):
    patch_probe(_make_info(selected_group=0x001D))
    findings = tls_endpoint.scan_endpoint("example.com", 443)
    kem = [f for f in findings if f.rule_id == "pqc-scan.tls.kem-classical"]
    assert len(kem) == 1
    assert kem[0].severity == Severity.HIGH
    assert "X25519" in kem[0].algorithm_display


def test_pqc_hybrid_x25519mlkem768_emits_info_finding(
    patch_probe, patch_cert_probe_to_noop
):
    patch_probe(_make_info(is_hrr=True, selected_group=0x11EC))
    findings = tls_endpoint.scan_endpoint("pq.example.com", 443)
    kem = [f for f in findings if f.rule_id == "pqc-scan.tls.kem-pqc-hybrid"]
    assert len(kem) == 1
    assert kem[0].severity == Severity.INFO
    assert "X25519MLKEM768" in kem[0].algorithm_display


def test_unknown_group_emits_info_finding_for_review(
    patch_probe, patch_cert_probe_to_noop
):
    """A group code not in the registry should be reported INFO so a human
    can decide whether to update the registry."""
    patch_probe(_make_info(selected_group=0xFEED))
    findings = tls_endpoint.scan_endpoint("example.com", 443)
    unknown = [f for f in findings if f.rule_id == "pqc-scan.tls.kem-unknown"]
    assert len(unknown) == 1
    assert unknown[0].severity == Severity.INFO
    assert "0xfeed" in unknown[0].algorithm_display.lower()


def test_tls_12_emits_legacy_protocol_finding(patch_probe, patch_cert_probe_to_noop):
    """TLS 1.2 has no KeyShare; expect a legacy-protocol finding and a
    kem-not-observed finding."""
    patch_probe(_make_info(selected_group=None, selected_version=None,
                           legacy_version=0x0303))
    findings = tls_endpoint.scan_endpoint("legacy.example.com", 443)
    rule_ids = {f.rule_id for f in findings}
    assert "pqc-scan.tls.protocol-pre-1.3" in rule_ids
    assert "pqc-scan.tls.kem-not-observed" in rule_ids


def test_alert_does_not_raise_emits_info_finding(
    patch_probe, patch_cert_probe_to_noop
):
    patch_probe(TLSAlert(level=2, description=70))
    findings = tls_endpoint.scan_endpoint("example.com", 443)
    alerts = [f for f in findings if f.rule_id == "pqc-scan.tls.handshake-alert"]
    assert len(alerts) == 1
    assert alerts[0].severity == Severity.INFO


def test_parse_error_does_not_raise(patch_probe, patch_cert_probe_to_noop):
    patch_probe(TLSParseError("garbage"))
    findings = tls_endpoint.scan_endpoint("example.com", 443)
    parse_errs = [f for f in findings if f.rule_id == "pqc-scan.tls.parse-error"]
    assert len(parse_errs) == 1


def test_network_error_does_not_raise(patch_probe, patch_cert_probe_to_noop):
    patch_probe(ConnectionRefusedError("nope"))
    findings = tls_endpoint.scan_endpoint("example.com", 443)
    net = [f for f in findings if f.rule_id == "pqc-scan.tls.kem-probe-network-error"]
    assert len(net) == 1


def test_pqc_hybrid_via_serverhello_not_hrr(patch_probe, patch_cert_probe_to_noop):
    """If a server has the matching PQC key share already, it sends a regular
    ServerHello (is_hrr=False) with the group in the KeyShare — same finding
    shape as the HRR case."""
    patch_probe(_make_info(is_hrr=False, selected_group=0x11EC))
    findings = tls_endpoint.scan_endpoint("pq.example.com", 443)
    kem = [f for f in findings if f.rule_id == "pqc-scan.tls.kem-pqc-hybrid"]
    assert len(kem) == 1


def test_legacy_draft_kyber_codepoint_recognized_as_pqc_hybrid(
    patch_probe, patch_cert_probe_to_noop
):
    """0x6399 X25519Kyber768Draft00 — the pre-FIPS-203 deployment codepoint —
    should still be flagged as PQC hybrid for inventory purposes."""
    patch_probe(_make_info(selected_group=0x6399))
    findings = tls_endpoint.scan_endpoint("legacy-pq.example.com", 443)
    kem = [f for f in findings if f.rule_id == "pqc-scan.tls.kem-pqc-hybrid"]
    assert len(kem) == 1
    assert "Kyber768" in kem[0].algorithm_display
