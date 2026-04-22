from __future__ import annotations

import socket
import ssl

from cryptography import x509

from pqc_scan.findings import Finding, Severity
from pqc_scan.scanners.certificates import findings_for_cert


def scan_endpoint(host: str, port: int = 443, timeout: float = 5.0) -> list[Finding]:
    """Connect to host:port over TLS and inspect the server certificate."""
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
    findings = findings_for_cert(cert, location=location)
    # Re-tag findings as tls_endpoint scanner output and rewrite rule IDs to the
    # tls.* namespace so consumers can suppress endpoint findings independently
    # of certificate-file findings.
    rewritten: list[Finding] = []
    for idx, f in enumerate(findings):
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
