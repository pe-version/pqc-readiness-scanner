# Scope

`pqc-scan` is a **post-quantum-cryptography (PQC) inventory tool**. It helps engineering teams find quantum-vulnerable algorithms in code, certificates, SSH keys, and live TLS endpoints, and points at NIST-recommended replacements. It is intentionally narrow.

## The four-criteria test for inclusion

A new feature belongs in `pqc-scan` if **all four** hold:

1. It addresses an algorithm or asset that a PQC migration plan must inventory.
2. The output of the feature would naturally appear in a CycloneDX CBOM.
3. There isn't already a mature, free, dedicated tool that does this better.
4. It can be implemented without external API credentials, paid services, or heavyweight runtime dependencies.

Anything that fails the test belongs in another project.

## In scope

- **Quantum-vulnerable primitives.** RSA, ECDSA, ECDH, DH, DSA, X25519, Ed25519 (broken by Shor's algorithm); AES-128 (weakened by Grover's).
- **Classically-broken primitives** that show up in any real audit alongside PQC findings: MD5, SHA-1, DES, 3DES, RC4. Reported because excluding them would make findings tables less useful, not because the project is in the general crypto-hygiene business.
- **PQC-safe stateful hash-based signatures with caveats.** XMSS / XMSSMT / LMS / HSS-LMS per NIST SP 800-208 — informational findings flagging that state-management correctness must be verified separately.
- **JWT algorithm surface.** RS256 / ES256 / EdDSA (PQC-migration surface) and the canonical classical-failure cases that co-occur with that surface (`alg: none`, signature verification disabled, weak HMAC literal secrets). The JWT scanner is *not* a complete RFC 8725 implementation — it covers the subset that overlaps PQC migration.
- **Inventory-friendly output formats.** SARIF v2.1.0, CycloneDX 1.6 CBOM, OMB M-23-02-style CSV, JSON, Markdown, console.

## Explicitly out of scope: broader crypto hygiene

`pqc-scan` will not detect:

- IV / nonce reuse
- ECB block cipher mode usage
- Hardcoded cryptographic keys or secrets
- Weak PBKDF2 / Argon2 / scrypt iteration counts
- Use of `random.random()` / `Math.random()` for security-sensitive randomness
- Missing constant-time comparison (`==` on MAC tags, etc.)
- TLS protocol-version misconfigurations beyond cert-level findings
- Side-channel vulnerabilities in source code

**Why:** these are well-served by Bandit, Semgrep `p/security-audit`, CodeQL, Snyk Code, and similar tools. Adding them would dilute `pqc-scan`'s identity into a worse competitor in a crowded market. A tool with a sharp purpose is more credible than a tool with a fuzzy one.

If your audit needs both PQC inventory and broader crypto hygiene, run `pqc-scan` alongside one of those tools. The SARIF / JSON outputs combine cleanly.

## Explicitly out of scope: adjacent non-crypto

`pqc-scan` will not detect:

- Secrets / credentials in source (gitleaks, trufflehog, GitHub secret scanning)
- Dependency vulnerabilities / CVEs (Dependabot, Snyk, OSV-Scanner, Trivy)
- License compliance (FOSSA, Scancode)
- General SAST findings — SQL injection, XSS, command injection, etc. (Semgrep, CodeQL, Snyk Code)
- Container / image scanning (Trivy, Grype)
- IaC misconfigurations (Checkov, tfsec, Terrascan)

**Why:** scope creep. These tools all exist, are mature, and are good. `pqc-scan`'s value is being the best at one specific task, not okay at many.

## What we may add later (not yet in scope)

These have been considered and deferred until there's clear demand and a clean implementation path:

- AST-based source detection (libcst for Python; tree-sitter for others). Pending evidence from `EVALUATION.md` that regex-based false-positive rates justify the refactor.
- KMS / cloud-config adapters (AWS KMS, GCP KMS, HashiCorp Vault).
- Compiled binary OID detection (ELF / PE / Mach-O).
- HTML / dashboard report.
- Per-rule baseline file (`.pqc-scan-baseline.yml`).
- **Full XMSS / LMS variant split.** v0.2 groups XMSS + XMSSMT into `xmss_family` and LMS + HSS-LMS into `lms_family`. NIST SP 800-208 distinguishes four variants and their OIDs are separate; the certificate scanner already keys on those distinct OIDs internally. Splitting the user-facing algorithm entries to four will happen when a real codebase surfaces the need. Until then, two families keeps the registry proportional to observed usage.

## What this means for users

If `pqc-scan` doesn't flag something that you think it should, check the four-criteria test. If the missing detection passes the test, file an issue. If it fails the test, the right tool is somewhere else — and we'd rather point you to that tool than pretend to cover it.
