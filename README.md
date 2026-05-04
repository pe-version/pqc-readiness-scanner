# pqc-scan

> Find quantum-vulnerable cryptography in your code, certificates, and TLS endpoints — and learn what to migrate to.

NIST finalized the first post-quantum cryptography standards in 2024 (FIPS 203 / 204 / 205). At the same time, **harvest-now-decrypt-later** attacks mean that traffic and data protected today by RSA, ECDSA, ECDH, and Diffie-Hellman are already at risk: an adversary recording encrypted traffic now can decrypt it once a sufficiently large fault-tolerant quantum computer (CRQC) exists. CISA, NSA, and NIST are pushing organizations to **inventory their cryptography** as the first step of migration ([CNSA 2.0](https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF), [OMB M-23-02](https://www.whitehouse.gov/wp-content/uploads/2022/11/M-23-02-M-Memo-on-Migrating-to-Post-Quantum-Cryptography.pdf)).

The findings produced by this scanner map to **OWASP Top 10 A02:2021 (Cryptographic Failures)**. The underlying weaknesses are catalogued as **CWE-326 (Inadequate Encryption Strength)** for quantum-broken primitives and **CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)** for classically-broken primitives. The SARIF and CycloneDX 1.6 CBOM reports include these mappings so they pass through to GitHub code scanning, GitLab dashboards, and SBOM-aware tooling.

`pqc-scan` is a small, dependency-light CLI that does that inventory for a repository or live host. It flags quantum-vulnerable algorithms in:

- **Source code** — Python, JavaScript/TypeScript, Go, Rust, Java/Kotlin/Scala, C/C++, C#, Ruby, PHP, shell, Terraform, configuration files, and others
- **X.509 certificates** — `.pem`, `.crt`, `.cer`, `.der` (including XMSS / HSS-LMS signature OIDs per NIST SP 800-208)
- **SSH keys, `authorized_keys`, `known_hosts`**
- **Live TLS endpoints** — server certificate public key + signature hash, plus the **negotiated TLS 1.3 key-exchange group** (so you can tell whether the endpoint is already running a PQC hybrid like `X25519MLKEM768`)
- **JSON Web Token usage** — RS256 / ES256 / EdDSA (PQC-migration surface) plus `alg: none`, signature verification disabled, and weak HMAC secrets (the classical-failure cases that co-occur with PQC migration work)

For each finding it reports the **NIST-recommended replacement** (ML-KEM, ML-DSA, SLH-DSA, AES-256, etc.) and a stable **rule ID** that supports inline suppression and SARIF dedup.

> **Scope.** `pqc-scan` is a starting-point inventory tool. It detects algorithm *usage*, not whether that usage is actually protecting sensitive data. Real cryptographic-bill-of-materials work also covers compiled binaries, HSMs / KMS, network captures, and data-flow analysis. Use this tool for a fast first pass. See [SCOPE.md](SCOPE.md) for what is — and is not — in scope, and why.

## Install

```bash
pip install -e .
```

## Usage

```bash
# Scan a directory
pqc-scan ./my-project

# Scan a directory and a live TLS endpoint, write multiple report formats
pqc-scan ./my-project --endpoint api.example.com \
    --md report.md \
    --json report.json \
    --sarif report.sarif \
    --cbom report.cdx.json \
    --csv report.csv

# Probe several endpoints
pqc-scan --endpoint github.com --endpoint imap.gmail.com:993

# Fail CI if anything HIGH or worse is found
pqc-scan . --fail-on high
```

Run `pqc-scan --help` for the full option list.

## Output formats

| Flag | Format | Use case |
| --- | --- | --- |
| (default) | Rich console table | Human inspection at the terminal |
| `--json` | JSON | Programmatic ingestion, custom dashboards |
| `--md` | Markdown | Drop-in PR comments and engagement reports |
| `--sarif` | SARIF v2.1.0 | GitHub code scanning, GitLab security dashboard, Snyk ASOC, Defect Dojo |
| `--cbom` | CycloneDX 1.6 (cryptographic-asset components) | SBOM workflows; ingestion by DependencyTrack and other CBOM-aware tools |
| `--csv` | Inventory CSV | Federal PQC inventory (template based on OMB M-23-02 / NSM-10 guidance — verify against your agency's current submission template) |

## Sample output

```
Findings: 2 critical 5 high 1 low

Sev       Algorithm                      Location                            Recommended replacement
critical  MD5                            src/auth.py:42                      SHA-256 / SHA-3-256 ...
critical  DES                            src/legacy.py:17                    AES-256-GCM
high      RSA                            src/keys.py:8                       ML-KEM (FIPS 203) ...
high      ECDSA (server cert)            api.example.com:443                 ML-DSA (FIPS 204) ...
...
```

A full sample report (Markdown) lives in [`examples/sample_report.md`](examples/sample_report.md).

### Detecting whether an endpoint is already PQC

```bash
$ pqc-scan --endpoint pq.cloudflareresearch.com:443
high  ECDSA (public key)                              ML-DSA / SLH-DSA
info  TLS post-quantum hybrid: X25519MLKEM768         N/A — already PQC-ready

$ pqc-scan --endpoint github.com:443
high  ECDSA (public key)                              ML-DSA / SLH-DSA
high  TLS classical key-exchange group: X25519        Hybrid PQC group (e.g. X25519MLKEM768)
```

The endpoint scanner sends a TLS 1.3 ClientHello directly via raw socket and parses the server's response (a ServerHello or HelloRetryRequest) to extract the negotiated key-exchange group from its `KeyShare` extension. Python's stdlib `ssl` module does not expose the group, so this scanner ships its own minimal RFC 8446 record parser.

## What it flags

| Category | Algorithms | Why |
| --- | --- | --- |
| Broken by Shor's algorithm | RSA, ECDSA, ECDH, DH, DSA, X25519, Ed25519 | Polynomial-time on a CRQC; subject to harvest-now-decrypt-later. All flagged HIGH — primitive risk is identical, regardless of whether the algorithm is also retained as the classical half of a hybrid construction during migration. |
| Weakened by Grover's algorithm | AES-128 | Effective key strength halved |
| Already broken classically | MD5, SHA-1, DES, 3DES, RC4 | Unsafe today, regardless of quantum. Note: bare MD5/SHA-1 used for non-cryptographic content addressing (cache keys, ETags, dedup) is fine cryptographically but migrating changes output bytes — coordinate with downstream consumers. |
| PQC-safe with caveats | XMSS, XMSSMT, LMS, HSS-LMS | Stateful hash-based signatures per NIST SP 800-208. Quantum-safe at the primitive level but require careful state management; flagged INFO so you can verify state-management correctness separately (SP 800-208 §6). |
| JWT — PQC migration surface | RS256/RS384/RS512, ES256/ES384/ES512, EdDSA | Signature algorithms inside JWS. Same Shor's-algorithm exposure as the underlying primitives; flagged HIGH so they appear next to other RSA/ECDSA/Ed25519 findings during planning. |
| JWT — classical misuse | `alg: none`, `verify=False`, weak HMAC literal secrets | Co-occur with the JWT migration surface and block migration sanity (you can't migrate signing if signing isn't verified). The JWT scanner is *not* a complete RFC 8725 (BCP) implementation — see [SCOPE.md](SCOPE.md). |

## How to triage findings

Across three OSS targets (`requests` v2.32.3, `django` 5.0.10, `ansible` v2.17.7), `pqc-scan` v0.2 produced **132 findings, 0 false positives, ~6 production-code migration items.** The rest are test fixtures, legacy-compatibility helpers, or protocol-mandated usages. See [EVALUATION.md](EVALUATION.md) for the methodology and caveats (precision is not recall; precision is not actionability).

Most `pqc-scan` findings on a real codebase are *correctly identified* but *not actionable as production migration items*. Use the following triage order:

1. **Run with `--skip-tests`.** `tests/`, `__tests__/`, `fixtures/`, `testdata/`, etc. are excluded from the default-on report. Findings under those paths are flagged with `in_test_path: true` in JSON / SARIF / CSV output and dropped entirely with `--skip-tests`. Most real codebases see 60–80% of findings drop here.
2. **Identify protocol-mandated cases.** Some algorithms are required by the protocols they implement (RFC 7616 HTTP Digest Auth requires MD5/SHA-1; some legacy SSH integrations require ssh-rsa). The local fix is "deprecate the protocol surface or accept the dependency," not "swap the hash function." Suppress with `# pqc-scan: ignore[<rule-id>]` on the line and link to the spec in the comment above.
3. **Group by rule ID, not by file.** Each finding carries a stable `rule_id` (e.g. `pqc-scan.source.rsa.cryptography-rsa-call`). One unfamiliar rule firing 30 times is one decision to make, not 30; baseline-ack the whole rule once you've understood what it covers.
4. **Production code remaining is your inventory.** Whatever survives steps 1–3 is the real PQC migration surface for the repo. For each: identify the upstream library, check whether it has a PQC migration story, and capture the dependency in your CBOM.

Worked numbers from real OSS targets are in [EVALUATION.md](EVALUATION.md).

### Suppressing a finding

Inline, on the line that produced the finding:

```python
hashlib.md5(content_bytes)  # pqc-scan: ignore[pqc-scan.source.md5.python-hashlib]  # cache key, not crypto
```

Or, suppress all rules on that line:

```python
hashlib.md5(content_bytes)  # pqc-scan: ignore  # used by HTTP Digest Auth (RFC 7616)
```

The inline syntax is intentionally minimal: line-trailing only, no expiration, no required justification.

For project-wide suppression, drop a `.pqc-scan-baseline.yml` at the project root:

```yaml
suppressions:
  - rule: pqc-scan.source.md5.python-hashlib
    paths: [src/legacy_etag.py]
    reason: "non-cryptographic content addressing; SHA-256 migration tracked in #234"
  - rule: pqc-scan.source.rsa.ssh-rsa
    paths: ["tests/", "build/"]
    reason: "test fixtures; not production code"
  - rule: pqc-scan.jwt.rs256.token
    # paths omitted → suppress this rule everywhere
    reason: "tracked in #234, migration deferred to Q3"
```

`paths` matches at path-component boundaries (so `tests/` matches `tests/x.py` and `proj/tests/x.py` but not `mytests/x.py`). The CLI auto-discovers `.pqc-scan-baseline.yml` from the scanned directory or current working directory; pass `--baseline PATH` to override or `--no-baseline` to disable discovery. The number of findings suppressed by the baseline is reported on stderr each run.

## Limitations

- **Regex-based source scan**, not full AST analysis. False positives in comments and string literals are possible; minified files and very large files are skipped. AST-based detection is on the roadmap, gated on `EVALUATION.md` precision data justifying the refactor.
- **No binary scan.** Compiled artifacts are not analyzed.
- **TLS endpoint scan covers the cert and the negotiated TLS 1.3 key-exchange group** via a hand-rolled record parser ([`tls_records.py`](src/pqc_scan/tls_records.py), [`tls_groups.py`](src/pqc_scan/tls_groups.py)). The advertised-group list and group-ID registry must be kept current as new PQC hybrid codepoints are deployed; out-of-date → false negatives.
- **JWT scanner is intentionally narrow.** Covers PQC-migration surface plus the canonical classical-failure cases. Not a complete RFC 8725 (BCP) implementation — see [SCOPE.md](SCOPE.md).
- **XMSS / LMS detection is inventory only.** The scanner identifies use of stateful hash-based signatures but does not analyze state-management correctness. See NIST SP 800-208 §6 for the operational requirements.
- **The taxonomy is opinionated.** "Migrate before a CRQC exists" reflects current NIST/NSA/CISA guidance but the timeline is a moving target.

## Development

```bash
pip install -e ".[dev]"
pytest
```

The CI workflow at [`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs `pytest` on Python 3.10–3.12 and self-scans the source tree as a smoke test.

## Roadmap

- AST-based source detection (libcst for Python, tree-sitter for others) — gated on EVALUATION.md showing real precision gaps
- Cipher-suite analysis for TLS endpoints (KEM-group analysis already shipped; cipher suites are captured but not yet emitted as their own findings)
- KMS / HSM inventory adapters (AWS KMS, GCP KMS, HashiCorp Vault)
- Per-rule baseline file (`.pqc-scan-baseline.yml`) for project-wide suppression
- Detection inside compiled binaries (parsing OIDs in ELF / PE / Mach-O)
- Auto-generated migration patches (planned as a separate companion tool, `pqc-fix`)

## Related work

- [`pqc-semgrep-rules`](https://github.com/pe-version/pqc-semgrep-rules) — Semgrep ruleset covering the same algorithms across Python, JavaScript/TypeScript, Go, and Java. Use this if your team already runs Semgrep in CI; use `pqc-scan` for the cert / SSH key / TLS endpoint dimensions Semgrep doesn't cover.
- [`pqc-hybrid-handshake`](https://github.com/pe-version/pqc-hybrid-handshake) — End-to-end hybrid X25519 + ML-KEM-768 key exchange demo using `liboqs`, illustrating what a migration target actually looks like in working code.

## Acknowledgments

Built with assistance from [Claude Code](https://claude.ai/code).

## License

MIT — see [LICENSE](LICENSE).
