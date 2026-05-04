"""Minimal TLS 1.3 ClientHello / ServerHello parser.

Implements just enough of RFC 8446 to:
  1. Build a TLS 1.3 ClientHello that advertises classical and PQC hybrid
     groups, with a real X25519 key share.
  2. Read the server's first response (either a ServerHello or a
     HelloRetryRequest) and extract the negotiated key-exchange group from
     its KeyShare extension.
  3. Extract the negotiated cipher suite and TLS protocol version.

This is a deliberate hand roll — Python's stdlib `ssl` module performs the
TLS handshake but does not expose the negotiated group, which is the core
operational signal for PQC readiness. We need direct record-level visibility.

This module performs NO cryptographic work beyond generating an ephemeral
X25519 keypair for the ClientHello. We never derive a session key, never
read application data, and close the socket as soon as the ServerHello is
parsed.

Constants and field layouts reference RFC 8446 by section.
"""

from __future__ import annotations

import io
import os
import socket
import struct
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


# ---------------------------------------------------------------------------
# Constants (RFC 8446)
# ---------------------------------------------------------------------------

CONTENT_TYPE_HANDSHAKE = 22  # §5.1
CONTENT_TYPE_ALERT = 21
HANDSHAKE_TYPE_CLIENT_HELLO = 1  # §4.1.2
HANDSHAKE_TYPE_SERVER_HELLO = 2  # §4.1.3

LEGACY_RECORD_VERSION = 0x0303  # TLS 1.2; TLS 1.3 hides under this on the wire
TLS_1_3 = 0x0304

# Extension types (§4.2)
EXT_SERVER_NAME = 0
EXT_SUPPORTED_GROUPS = 10
EXT_SIGNATURE_ALGORITHMS = 13
EXT_SUPPORTED_VERSIONS = 43
EXT_KEY_SHARE = 51

# Cipher suites we advertise (TLS 1.3 only). §B.4
CIPHER_TLS_AES_128_GCM_SHA256 = 0x1301
CIPHER_TLS_AES_256_GCM_SHA384 = 0x1302
CIPHER_TLS_CHACHA20_POLY1305_SHA256 = 0x1303

# RFC 8446 §4.1.4: HelloRetryRequest is signaled by a magic random value.
HRR_RANDOM = bytes.fromhex(
    "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c"
)

# Minimal SignatureScheme list (§4.2.3). Every TLS 1.3 server expects at least
# one of these; we list the common ones (RSA-PSS and ECDSA over P-256/P-384).
SIGNATURE_SCHEMES: tuple[int, ...] = (
    0x0804,  # rsa_pss_rsae_sha256
    0x0805,  # rsa_pss_rsae_sha384
    0x0806,  # rsa_pss_rsae_sha512
    0x0403,  # ecdsa_secp256r1_sha256
    0x0503,  # ecdsa_secp384r1_sha384
    0x0603,  # ecdsa_secp521r1_sha512
    0x0807,  # ed25519
)


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ServerHelloInfo:
    """Decoded fields from the server's first handshake message."""
    is_hello_retry_request: bool
    legacy_version: int
    cipher_suite: int
    selected_group: int | None         # from KeyShare extension
    selected_version: int | None       # from supported_versions extension
    raw_extensions_seen: tuple[int, ...] = field(default_factory=tuple)


class TLSParseError(ValueError):
    """Raised when the server response is not a parseable handshake."""


class TLSAlert(ValueError):
    """Raised when the server returned an alert instead of a handshake."""

    def __init__(self, level: int, description: int):
        super().__init__(f"TLS alert level={level} description={description}")
        self.level = level
        self.description = description


# ---------------------------------------------------------------------------
# Encoding helpers
# ---------------------------------------------------------------------------

def _u8(n: int) -> bytes:
    return struct.pack(">B", n)


def _u16(n: int) -> bytes:
    return struct.pack(">H", n)


def _u24(n: int) -> bytes:
    return struct.pack(">I", n)[1:]


def _vector_u8(payload: bytes) -> bytes:
    """Length-prefixed vector with a 1-byte length (RFC 8446 §3.4)."""
    if len(payload) > 0xFF:
        raise ValueError("payload too long for u8 length")
    return _u8(len(payload)) + payload


def _vector_u16(payload: bytes) -> bytes:
    """Length-prefixed vector with a 2-byte length."""
    if len(payload) > 0xFFFF:
        raise ValueError("payload too long for u16 length")
    return _u16(len(payload)) + payload


def _vector_u24(payload: bytes) -> bytes:
    """Length-prefixed vector with a 3-byte length."""
    if len(payload) > 0xFFFFFF:
        raise ValueError("payload too long for u24 length")
    return _u24(len(payload)) + payload


# ---------------------------------------------------------------------------
# ClientHello construction
# ---------------------------------------------------------------------------

def build_client_hello(
    host: str,
    advertised_groups: tuple[int, ...],
) -> bytes:
    """Build a TLS 1.3 ClientHello record.

    The advertised key share carries an ephemeral X25519 public key. If the
    server selects a group other than X25519 from `advertised_groups`, it
    will respond with HelloRetryRequest naming the chosen group — which is
    the answer this scanner is looking for. We don't need to complete the
    handshake; we just need the first server response.
    """
    # Generate an ephemeral X25519 keypair for the key share
    x25519_priv = X25519PrivateKey.generate()
    x25519_pub = x25519_priv.public_key().public_bytes(
        encoding=Encoding.Raw, format=PublicFormat.Raw
    )

    # supported_versions extension (§4.2.1): list of versions, each 2 bytes
    supported_versions_body = _vector_u8(_u16(TLS_1_3))
    ext_supported_versions = _u16(EXT_SUPPORTED_VERSIONS) + _vector_u16(
        supported_versions_body
    )

    # supported_groups extension (§4.2.7): list of named groups
    groups_body = _vector_u16(b"".join(_u16(g) for g in advertised_groups))
    ext_supported_groups = _u16(EXT_SUPPORTED_GROUPS) + _vector_u16(groups_body)

    # signature_algorithms extension (§4.2.3): list of signature schemes
    sig_body = _vector_u16(b"".join(_u16(s) for s in SIGNATURE_SCHEMES))
    ext_signature_algorithms = _u16(EXT_SIGNATURE_ALGORITHMS) + _vector_u16(sig_body)

    # key_share extension (§4.2.8): one X25519 KeyShareEntry
    x25519_entry = _u16(0x001D) + _vector_u16(x25519_pub)  # group + key_exchange
    key_share_body = _vector_u16(x25519_entry)  # client_shares vector
    ext_key_share = _u16(EXT_KEY_SHARE) + _vector_u16(key_share_body)

    # server_name extension (§3 of RFC 6066): SNI
    sni_host = host.encode("idna")
    sni_entry = _u8(0) + _vector_u16(sni_host)  # name_type=0 (host_name)
    sni_body = _vector_u16(sni_entry)  # ServerNameList
    ext_server_name = _u16(EXT_SERVER_NAME) + _vector_u16(sni_body)

    extensions = (
        ext_server_name
        + ext_supported_versions
        + ext_supported_groups
        + ext_signature_algorithms
        + ext_key_share
    )

    # ClientHello body (§4.1.2)
    client_hello_body = (
        _u16(LEGACY_RECORD_VERSION)
        + os.urandom(32)  # random
        + _vector_u8(os.urandom(32))  # legacy_session_id (32 bytes for compatibility)
        + _vector_u16(
            _u16(CIPHER_TLS_AES_128_GCM_SHA256)
            + _u16(CIPHER_TLS_AES_256_GCM_SHA384)
            + _u16(CIPHER_TLS_CHACHA20_POLY1305_SHA256)
        )
        + _vector_u8(b"\x00")  # legacy_compression_methods: null only
        + _vector_u16(extensions)
    )

    # Wrap in handshake header and TLS record
    handshake = _u8(HANDSHAKE_TYPE_CLIENT_HELLO) + _vector_u24(client_hello_body)
    record = (
        _u8(CONTENT_TYPE_HANDSHAKE)
        + _u16(LEGACY_RECORD_VERSION)
        + _vector_u16(handshake)
    )
    return record


# ---------------------------------------------------------------------------
# ServerHello parsing
# ---------------------------------------------------------------------------

class _Reader:
    """Stream-oriented reader for TLS wire-format fields."""

    def __init__(self, data: bytes):
        self._buf = io.BytesIO(data)
        self._len = len(data)

    def read(self, n: int) -> bytes:
        chunk = self._buf.read(n)
        if len(chunk) < n:
            raise TLSParseError(
                f"truncated read: wanted {n} bytes, got {len(chunk)}"
            )
        return chunk

    def u8(self) -> int:
        return self.read(1)[0]

    def u16(self) -> int:
        return struct.unpack(">H", self.read(2))[0]

    def u24(self) -> int:
        return struct.unpack(">I", b"\x00" + self.read(3))[0]

    def vector_u8(self) -> bytes:
        return self.read(self.u8())

    def vector_u16(self) -> bytes:
        return self.read(self.u16())

    def remaining(self) -> int:
        pos = self._buf.tell()
        return self._len - pos


def _parse_extension_key_share_server(body: bytes) -> int:
    """Server-side KeyShare: a single KeyShareEntry (§4.2.8.2).

    HelloRetryRequest carries only the selected group (no public key); regular
    ServerHello carries the group + the server's public key.
    """
    r = _Reader(body)
    if len(body) == 2:
        # HRR shape: just the 2-byte selected_group
        return r.u16()
    group = r.u16()
    # KeyShareEntry continues with key_exchange<1..2^16-1>; we don't need it
    return group


def _parse_extension_supported_versions_server(body: bytes) -> int:
    """Server-side supported_versions: a single 2-byte selected_version (§4.2.1)."""
    r = _Reader(body)
    return r.u16()


def parse_server_hello(record_bytes: bytes) -> ServerHelloInfo:
    """Parse a TLS record containing a ServerHello (or HelloRetryRequest).

    Raises TLSAlert if the server sent an alert instead. Raises TLSParseError
    on any structural issue.
    """
    r = _Reader(record_bytes)
    content_type = r.u8()
    legacy_version = r.u16()  # noqa: F841
    record_len = r.u16()
    record_payload = r.read(record_len)

    if content_type == CONTENT_TYPE_ALERT:
        ar = _Reader(record_payload)
        level = ar.u8()
        desc = ar.u8()
        raise TLSAlert(level, desc)
    if content_type != CONTENT_TYPE_HANDSHAKE:
        raise TLSParseError(f"unexpected content_type {content_type}")

    hr = _Reader(record_payload)
    handshake_type = hr.u8()
    handshake_len = hr.u24()
    body = hr.read(handshake_len)

    if handshake_type != HANDSHAKE_TYPE_SERVER_HELLO:
        raise TLSParseError(
            f"expected ServerHello (2), got handshake type {handshake_type}"
        )

    sh = _Reader(body)
    sh_legacy_version = sh.u16()
    random = sh.read(32)
    is_hrr = random == HRR_RANDOM
    _ = sh.vector_u8()  # legacy_session_id_echo
    cipher_suite = sh.u16()
    _ = sh.u8()  # legacy_compression_method
    extensions_data = sh.vector_u16()

    selected_group: int | None = None
    selected_version: int | None = None
    seen: list[int] = []
    er = _Reader(extensions_data)
    while er.remaining() > 0:
        ext_type = er.u16()
        ext_body = er.vector_u16()
        seen.append(ext_type)
        if ext_type == EXT_KEY_SHARE:
            try:
                selected_group = _parse_extension_key_share_server(ext_body)
            except TLSParseError:
                pass
        elif ext_type == EXT_SUPPORTED_VERSIONS:
            try:
                selected_version = _parse_extension_supported_versions_server(ext_body)
            except TLSParseError:
                pass

    return ServerHelloInfo(
        is_hello_retry_request=is_hrr,
        legacy_version=sh_legacy_version,
        cipher_suite=cipher_suite,
        selected_group=selected_group,
        selected_version=selected_version,
        raw_extensions_seen=tuple(seen),
    )


# ---------------------------------------------------------------------------
# Network probe
# ---------------------------------------------------------------------------

def probe_endpoint(
    host: str,
    port: int,
    advertised_groups: tuple[int, ...],
    timeout: float = 5.0,
) -> ServerHelloInfo:
    """Send a TLS 1.3 ClientHello and return the parsed server response.

    Caller is responsible for converting any raised exceptions into Findings.
    """
    client_hello = build_client_hello(host, advertised_groups)
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.sendall(client_hello)
        # Read the record header (5 bytes), then the full record body.
        header = _read_exactly(sock, 5)
        if len(header) < 5:
            raise TLSParseError("server closed connection before sending a record")
        record_len = struct.unpack(">H", header[3:5])[0]
        body = _read_exactly(sock, record_len)
        if len(body) < record_len:
            raise TLSParseError("server truncated TLS record")
    return parse_server_hello(header + body)


def _read_exactly(sock: socket.socket, n: int) -> bytes:
    chunks: list[bytes] = []
    remaining = n
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)
