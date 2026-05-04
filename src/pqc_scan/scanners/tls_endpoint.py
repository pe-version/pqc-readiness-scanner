from __future__ import annotations

import socket
import ssl

from cryptography import x509

from pqc_scan.algorithms import ALGORITHMS
from pqc_scan.findings import Finding, Severity
from pqc_scan.scanners.certificates import findings_for_cert
from pqc_scan.tls_groups import (
    ALL_GROUPS,
    CLASSICAL_GROUPS,
    PQC_HYBRID_GROUPS,
    TLSGroup,
    describe,
    lookup,
)
from pqc_scan.tls_records import (
    TLS_1_3,
    ServerHelloInfo,
    TLSAlert,
    TLSParseError,
    probe_endpoint,
)


# Order matters: PQC hybrid groups first so the server prefers them when
# negotiating, then classical groups as fallback. Both are "advertised" so
# the server can select any of them; whichever it picks is what we report.
_ADVERTISED_GROUPS: tuple[int, ...] = tuple(
    g.code for g in (*PQC_HYBRID_GROUPS, *CLASSICAL_GROUPS)
)


def scan_endpoint(host: str, port: int = 443, timeout: float = 5.0) -> list[Finding]:
    """Connect to host:port over TLS and inspect both the certificate and
    the negotiated key-exchange group.

    Two independent probes are performed:

    1. A standard TLS handshake via the stdlib `ssl` module to fetch the
       server certificate (existing behavior; produces RSA / ECDSA findings).
    2. A direct TLS 1.3 ClientHello via raw socket so we can read the
       ServerHello and extract the negotiated group from its KeyShare
       extension. This is the operational PQC-readiness signal the stdlib
       does not expose.
    """
    findings: list[Finding] = []
    findings.extend(_scan_certificate(host, port, timeout))
    findings.extend(_scan_negotiated_group(host, port, timeout))
    return findings


def _scan_certificate(host: str, port: int, timeout: float) -> list[Finding]:
    """Original cert-based probe: extracts the leaf cert and reports on its
    public-key algorithm and signature hash."""
    location = f"{host}:{port}"
    try:
        # Audit context, not a connection we trust for data. We need to inspect
        # any certificate the server presents (including self-signed, expired,
        # or otherwise untrusted ones) to report on its algorithm choices —
        # that is the scanner's whole purpose. CERT_NONE / check_hostname=False
        # are deliberate and must not be copied into production TLS code.
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as sock:
                der = sock.getpeercert(binary_form=True)
                cipher = sock.cipher()
                tls_version = sock.version()
    except (OSError, ssl.SSLError) as exc:
        return [
            Finding(
                rule_id="pqc-scan.tls.connection-error",
                algorithm_id="connection_error",
                algorithm_display="Connection error",
                severity=Severity.INFO,
                category="error",
                location=location,
                line=None,
                context=f"{type(exc).__name__}: {exc}",
                scanner="tls_endpoint",
                replacement="N/A",
                notes="Could not connect; check host, port, and network access.",
                in_test_path=False,
            )
        ]
    if der is None:
        return []
    cert = x509.load_der_x509_certificate(der)
    cert_findings = findings_for_cert(cert, location=location)
    rewritten: list[Finding] = []
    for idx, f in enumerate(cert_findings):
        rule_id = f.rule_id.replace("pqc-scan.cert.", "pqc-scan.tls.", 1)
        context = f.context
        if idx == 0 and cipher is not None:
            context = f"{context} tls={tls_version} cipher={cipher[0]}"
        rewritten.append(
            Finding(
                rule_id=rule_id,
                algorithm_id=f.algorithm_id,
                algorithm_display=f.algorithm_display,
                severity=f.severity,
                category=f.category,
                location=f.location,
                line=f.line,
                context=context,
                scanner="tls_endpoint",
                replacement=f.replacement,
                notes=f.notes,
                in_test_path=False,
            )
        )
    return rewritten


def _scan_negotiated_group(host: str, port: int, timeout: float) -> list[Finding]:
    """Send a TLS 1.3 ClientHello, parse the server response, and emit a
    finding describing the negotiated key-exchange group.

    Failures here are reported as an INFO finding rather than an exception,
    so cert-based findings still ship even if this probe trips.
    """
    location = f"{host}:{port}"
    try:
        info = probe_endpoint(host, port, _ADVERTISED_GROUPS, timeout=timeout)
    except TLSAlert as alert:
        return [_alert_finding(location, alert)]
    except TLSParseError as exc:
        return [_parse_error_finding(location, exc)]
    except (OSError, socket.timeout) as exc:
        return [_network_error_finding(location, exc)]

    findings: list[Finding] = []

    # TLS version finding (only emitted if not TLS 1.3, since that's the
    # baseline for PQC migration).
    selected_version = info.selected_version or info.legacy_version
    if selected_version != TLS_1_3:
        meta = ALGORITHMS["tls_protocol_legacy"]
        findings.append(
            Finding(
                rule_id="pqc-scan.tls.protocol-pre-1.3",
                algorithm_id=meta.id,
                algorithm_display=meta.display,
                severity=meta.severity,
                category=meta.category,
                location=location,
                line=None,
                context=f"selected_version=0x{selected_version:04x}",
                scanner="tls_endpoint",
                replacement=meta.replacement,
                notes=meta.notes,
                in_test_path=False,
            )
        )

    # Key-exchange group finding
    if info.selected_group is None:
        meta = ALGORITHMS["tls_protocol_legacy"]
        findings.append(
            Finding(
                rule_id="pqc-scan.tls.kem-not-observed",
                algorithm_id=meta.id,
                algorithm_display="No KeyShare extension in ServerHello",
                severity=Severity.INFO,
                category="tls_protocol",
                location=location,
                line=None,
                context=f"extensions={[hex(t) for t in info.raw_extensions_seen]}",
                scanner="tls_endpoint",
                replacement="Upgrade endpoint to TLS 1.3.",
                notes=(
                    "The server response did not include a KeyShare. This usually "
                    "means TLS 1.2 was negotiated (no KeyShare in TLS 1.2)."
                ),
                in_test_path=False,
            )
        )
        return findings

    group: TLSGroup | None = lookup(info.selected_group)
    selected_label = describe(info.selected_group)
    cipher_label = f"0x{info.cipher_suite:04x}"
    context = (
        f"selected_group={selected_label}, "
        f"cipher_suite={cipher_label}, "
        f"hello_retry={info.is_hello_retry_request}"
    )

    if group is None:
        # Unknown group code — report it INFO, with the raw code in context,
        # so a human can decide whether the IANA registry has moved.
        findings.append(
            Finding(
                rule_id="pqc-scan.tls.kem-unknown",
                algorithm_id="tls_kem_classical",
                algorithm_display=f"Unknown TLS group 0x{info.selected_group:04x}",
                severity=Severity.INFO,
                category="tls_kem_classical",
                location=location,
                line=None,
                context=context,
                scanner="tls_endpoint",
                replacement="Verify the group ID against the IANA TLS Supported "
                "Groups registry; update tls_groups.py if a new entry is needed.",
                notes="Group ID was not in the scanner's registry. May indicate a "
                "newer PQC group not yet listed here.",
                in_test_path=False,
            )
        )
        return findings

    if group.family == "pqc_hybrid":
        meta = ALGORITHMS["tls_kem_pqc_hybrid"]
        rule_id = "pqc-scan.tls.kem-pqc-hybrid"
    else:
        meta = ALGORITHMS["tls_kem_classical"]
        rule_id = "pqc-scan.tls.kem-classical"

    findings.append(
        Finding(
            rule_id=rule_id,
            algorithm_id=meta.id,
            algorithm_display=f"{meta.display}: {group.name}",
            severity=meta.severity,
            category=meta.category,
            location=location,
            line=None,
            context=context,
            scanner="tls_endpoint",
            replacement=meta.replacement,
            notes=f"{meta.notes} {group.notes}".strip(),
            in_test_path=False,
        )
    )
    return findings


def _alert_finding(location: str, alert: TLSAlert) -> Finding:
    return Finding(
        rule_id="pqc-scan.tls.handshake-alert",
        algorithm_id="connection_error",
        algorithm_display=f"TLS alert: level={alert.level} description={alert.description}",
        severity=Severity.INFO,
        category="error",
        location=location,
        line=None,
        context=str(alert),
        scanner="tls_endpoint",
        replacement="N/A",
        notes="Server rejected the ClientHello. May not support TLS 1.3, or "
        "may require client authentication.",
        in_test_path=False,
    )


def _parse_error_finding(location: str, exc: TLSParseError) -> Finding:
    return Finding(
        rule_id="pqc-scan.tls.parse-error",
        algorithm_id="connection_error",
        algorithm_display="ServerHello parse error",
        severity=Severity.INFO,
        category="error",
        location=location,
        line=None,
        context=f"TLSParseError: {exc}",
        scanner="tls_endpoint",
        replacement="N/A",
        notes="Could not parse the server's first response as a TLS handshake.",
        in_test_path=False,
    )


def _network_error_finding(location: str, exc: BaseException) -> Finding:
    return Finding(
        rule_id="pqc-scan.tls.kem-probe-network-error",
        algorithm_id="connection_error",
        algorithm_display="KEM probe network error",
        severity=Severity.INFO,
        category="error",
        location=location,
        line=None,
        context=f"{type(exc).__name__}: {exc}",
        scanner="tls_endpoint",
        replacement="N/A",
        notes="Could not complete the secondary TLS 1.3 probe; "
        "certificate findings (if any) are unaffected.",
        in_test_path=False,
    )


__all__ = ["scan_endpoint"]


# Touch unused names so static analysers don't flag the registry import as dead.
_ = ALL_GROUPS
