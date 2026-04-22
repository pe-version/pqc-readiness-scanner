# Security Policy

## Reporting a vulnerability

If you discover a security vulnerability in `pqc-scan`, please report it through [GitHub's private vulnerability reporting](https://github.com/pe-version/pqc-readiness-scanner/security/advisories/new) rather than opening a public issue.

(The GitHub repository is named `pqc-readiness-scanner` for historical reasons; the package and CLI were renamed to `pqc-scan` in v0.2. The URL above is correct.)

Reports will be acknowledged within seven days where possible.

## Scope

This is a portfolio and learning project. Reports will be taken seriously, but the code is not production-supported software. Assess its appropriateness for your environment before relying on it for inventory of regulated systems.

The scanner produces *advisory* findings only — it is not a substitute for a full cryptographic-bill-of-materials process, and its detections are pattern-based with known false-positive ceilings.

## Non-claims

`pqc-scan` makes no claim of alignment, validation, or certification under:

- **FIPS 140-3 / CMVP.** The scanner is not a cryptographic module and is not a substitute for one.
- **FedRAMP.** No FedRAMP authorization, no claim of FedRAMP-aligned controls.
- **Common Criteria (CC) / EAL.** No evaluation has been performed under any CC scheme.
- **ISO 27001 / SOC 2.** No audited control mappings; do not rely on `pqc-scan` output as an ISMS or SOC artifact.
- **OMB M-23-02 / NSM-10 agency acceptance.** The CSV inventory format is a *template* in the spirit of those guidance documents; agencies use their own current submission templates, which should be the source of truth.
- **NIST SP 800-208 state-management compliance.** XMSS / LMS findings are inventory only — they do not certify that state management is implemented correctly. See SP 800-208 §6 for the operational requirements.
- **RFC 8725 (JWT BCP) coverage.** The JWT scanner detects a subset of RFC 8725's recommendations, specifically those that overlap PQC migration. It is not a complete JWT-BCP linter.

If your environment requires any of the above, validate `pqc-scan` against your specific framework before use, or use a tool with the relevant attestation.

## Supported versions

| Version | Supported |
| --- | --- |
| 0.2.x | ✓ |
| 0.1.x | Bug-fix backports only on request |
| < 0.1 | ✗ |
