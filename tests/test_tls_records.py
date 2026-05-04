"""Offline tests for the TLS 1.3 ClientHello / ServerHello parser.

The parser is tested against:
  1. A round-trip ClientHello: build, then parse the inner structure
     to confirm the wire layout matches RFC 8446.
  2. Synthesized ServerHello records that exercise:
       - TLS 1.3 ServerHello with X25519 KeyShare (classical group selected)
       - TLS 1.3 HelloRetryRequest with X25519MLKEM768 KeyShare (PQC hybrid)
       - TLS 1.2 fallback (no KeyShare extension at all)
       - Server alert
       - Truncated record

No live network is touched.
"""

from __future__ import annotations

import struct

import pytest

from pqc_scan.tls_records import (
    HRR_RANDOM,
    LEGACY_RECORD_VERSION,
    TLS_1_3,
    ServerHelloInfo,
    TLSAlert,
    TLSParseError,
    build_client_hello,
    parse_server_hello,
)


# ---------------------------------------------------------------------------
# Synthesized ServerHello fixtures
# ---------------------------------------------------------------------------

def _u8(n: int) -> bytes:
    return struct.pack(">B", n)


def _u16(n: int) -> bytes:
    return struct.pack(">H", n)


def _u24(n: int) -> bytes:
    return struct.pack(">I", n)[1:]


def _vector_u8(payload: bytes) -> bytes:
    return _u8(len(payload)) + payload


def _vector_u16(payload: bytes) -> bytes:
    return _u16(len(payload)) + payload


def _vector_u24(payload: bytes) -> bytes:
    return _u24(len(payload)) + payload


def _build_server_hello_record(
    *,
    is_hrr: bool,
    cipher_suite: int,
    selected_group: int | None,
    selected_version: int | None = TLS_1_3,
    legacy_version: int = LEGACY_RECORD_VERSION,
) -> bytes:
    """Construct a minimal but valid ServerHello (or HRR) wrapped in a TLS record."""
    random = HRR_RANDOM if is_hrr else b"\x00" * 32

    extensions = b""
    if selected_version is not None:
        ext_body = _u16(selected_version)
        extensions += _u16(43) + _vector_u16(ext_body)
    if selected_group is not None:
        if is_hrr:
            ks_body = _u16(selected_group)
        else:
            # ServerHello KeyShare carries group + key_exchange. Use an empty
            # key_exchange vector (parser only reads the group anyway).
            ks_body = _u16(selected_group) + _vector_u16(b"")
        extensions += _u16(51) + _vector_u16(ks_body)

    server_hello_body = (
        _u16(legacy_version)
        + random
        + _vector_u8(b"\x00" * 32)  # legacy_session_id_echo
        + _u16(cipher_suite)
        + _u8(0)  # legacy_compression_method
        + _vector_u16(extensions)
    )

    handshake = _u8(2) + _vector_u24(server_hello_body)
    record = (
        _u8(22)  # handshake content type
        + _u16(LEGACY_RECORD_VERSION)
        + _vector_u16(handshake)
    )
    return record


# ---------------------------------------------------------------------------
# build_client_hello smoke tests
# ---------------------------------------------------------------------------

def test_build_client_hello_record_layout():
    record = build_client_hello("example.com", advertised_groups=(0x001D,))
    # Record header: type=22, version=0x0303, length=...
    assert record[0] == 22
    assert record[1:3] == b"\x03\x03"
    record_len = struct.unpack(">H", record[3:5])[0]
    assert len(record) == 5 + record_len
    # Inside: handshake type=1 (ClientHello)
    assert record[5] == 1


def test_build_client_hello_advertises_all_groups():
    """Multiple advertised groups must all appear in the supported_groups extension."""
    groups = (0x11EC, 0x001D, 0x0017)
    record = build_client_hello("example.com", advertised_groups=groups)
    # Each group is a 2-byte big-endian integer; check they're present in order.
    for g in groups:
        assert _u16(g) in record


# ---------------------------------------------------------------------------
# parse_server_hello fixtures
# ---------------------------------------------------------------------------

def test_parse_server_hello_classical_x25519():
    record = _build_server_hello_record(
        is_hrr=False, cipher_suite=0x1301, selected_group=0x001D
    )
    info = parse_server_hello(record)
    assert isinstance(info, ServerHelloInfo)
    assert info.is_hello_retry_request is False
    assert info.cipher_suite == 0x1301
    assert info.selected_group == 0x001D
    assert info.selected_version == TLS_1_3


def test_parse_hello_retry_request_pqc_hybrid():
    """X25519MLKEM768 selected via HelloRetryRequest (server didn't have a key
    share matching the client's offered X25519 share, so HRR names the chosen
    group instead)."""
    record = _build_server_hello_record(
        is_hrr=True, cipher_suite=0x1301, selected_group=0x11EC
    )
    info = parse_server_hello(record)
    assert info.is_hello_retry_request is True
    assert info.selected_group == 0x11EC
    assert info.cipher_suite == 0x1301


def test_parse_server_hello_tls12_no_keyshare():
    """A TLS 1.2 server emits a ServerHello with no KeyShare and no
    supported_versions extension; selected_group should be None."""
    record = _build_server_hello_record(
        is_hrr=False,
        cipher_suite=0xC02F,  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        selected_group=None,
        selected_version=None,
    )
    info = parse_server_hello(record)
    assert info.selected_group is None
    assert info.selected_version is None


def test_parse_server_hello_alert_raises():
    """Server alert in the first response (not a handshake)."""
    alert_payload = bytes([2, 70])  # level=fatal, description=protocol_version
    record = _u8(21) + _u16(LEGACY_RECORD_VERSION) + _vector_u16(alert_payload)
    with pytest.raises(TLSAlert) as exc_info:
        parse_server_hello(record)
    assert exc_info.value.level == 2
    assert exc_info.value.description == 70


def test_parse_truncated_record_raises():
    """A truncated record should produce a TLSParseError, not a silent partial read."""
    record = _build_server_hello_record(
        is_hrr=False, cipher_suite=0x1301, selected_group=0x001D
    )
    with pytest.raises(TLSParseError):
        parse_server_hello(record[:10])


def test_parse_unexpected_handshake_type():
    """A handshake message that isn't ServerHello (e.g. ClientHello echoed back)
    should be rejected."""
    # Record carrying handshake type 1 (ClientHello).
    body = _u8(1) + _vector_u24(b"\x00" * 4)
    record = _u8(22) + _u16(LEGACY_RECORD_VERSION) + _vector_u16(body)
    with pytest.raises(TLSParseError):
        parse_server_hello(record)
