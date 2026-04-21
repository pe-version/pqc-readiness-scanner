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
            )
        ]
    if der is None:
        return []
    cert = x509.load_der_x509_certificate(der)
    findings = findings_for_cert(cert, location=location)
    # Annotate the first finding with the negotiated TLS context for visibility.
    if findings and cipher is not None:
        first = findings[0]
        suffix = f" tls={tls_version} cipher={cipher[0]}"
        findings[0] = Finding(
            algorithm_id=first.algorithm_id,
            algorithm_display=first.algorithm_display,
            severity=first.severity,
            category=first.category,
            location=first.location,
            line=first.line,
            context=first.context + suffix,
            scanner=first.scanner.replace("certificates", "tls_endpoint"),
            replacement=first.replacement,
            notes=first.notes,
        )
    return findings
