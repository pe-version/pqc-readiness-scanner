# pqc-scan

> Find quantum-vulnerable cryptography in your code, certificates, and TLS endpoints — and learn what to migrate to.

NIST finalized the first post-quantum cryptography standards in 2024 (FIPS 203 / 204 / 205). At the same time, **harvest-now-decrypt-later** attacks mean that traffic and data protected today by RSA, ECDSA, ECDH, and Diffie-Hellman are already at risk: an adversary recording encrypted traffic now can decrypt it once a sufficiently large fault-tolerant quantum computer (CRQC) exists. CISA, NSA, and NIST are pushing organizations to **inventory their cryptography** as the first step of migration ([CNSA 2.0](https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF), [OMB M-23-02](https://www.whitehouse.gov/wp-content/uploads/2022/11/M-23-02-M-Memo-on-Migrating-to-Post-Quantum-Cryptography.pdf)).

`pqc-scan` is a small, dependency-light CLI that does that inventory for a repository or live host. It flags quantum-vulnerable algorithms in:

- **Source code** — Python, JavaScript/TypeScript, Go, Rust, Java/Kotlin/Scala, C/C++, C#, Ruby, PHP, shell, Terraform, configuration files, and others
- **X.509 certificates** — `.pem`, `.crt`, `.cer`, `.der`
- **SSH keys, `authorized_keys`, `known_hosts`**
- **Live TLS endpoints** — server certificate public key + signature hash

For each finding it reports the **NIST-recommended replacement** (ML-KEM, ML-DSA, SLH-DSA, AES-256, etc.).

> **Scope.** `pqc-scan` is a starting-point inventory tool. It detects algorithm *usage*, not whether that usage is actually protecting sensitive data. Real cryptographic-bill-of-materials work also covers compiled binaries, HSMs / KMS, network captures, and data-flow analysis. Use this tool for a fast first pass.

## Install

```bash
pip install -e .
```

## Usage

```bash
# Scan a directory
pqc-scan ./my-project

# Scan a directory and a live TLS endpoint, write reports
pqc-scan ./my-project --endpoint api.example.com --md report.md --json report.json

# Probe several endpoints
pqc-scan --endpoint github.com --endpoint imap.gmail.com:993

# Fail CI if anything HIGH or worse is found
pqc-scan . --fail-on high
```

Run `pqc-scan --help` for the full option list.

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

## What it flags

| Category | Algorithms | Why |
| --- | --- | --- |
| Broken by Shor's algorithm | RSA, ECDSA, ECDH, DH, DSA, X25519, Ed25519 | Polynomial-time on a CRQC; subject to harvest-now-decrypt-later |
| Weakened by Grover's algorithm | AES-128 | Effective key strength halved |
| Already broken classically | MD5, SHA-1, DES, 3DES, RC4 | Unsafe today, regardless of quantum |

## Limitations

- **Regex-based source scan**, not full AST analysis. False positives in comments and string literals are possible; minified files and very large files are skipped.
- **No binary scan.** Compiled artifacts are not analyzed.
- **TLS endpoint scan is informational** — only the leaf certificate's public key and signature hash are checked, not the negotiated cipher suite or KEM.
- **The taxonomy is opinionated.** "Migrate before a CRQC exists" reflects current NIST/NSA/CISA guidance but the timeline is a moving target.

## Development

```bash
pip install -e ".[dev]"
pytest
```

The CI workflow at [`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs `pytest` on Python 3.10–3.12 and self-scans the source tree as a smoke test.

## Roadmap

- Cipher-suite + KEM analysis for TLS endpoints (currently leaf-cert only)
- Detection inside compiled binaries (parsing OIDs in ELF / PE / Mach-O)
- KMS / HSM inventory adapters (AWS KMS, GCP KMS, HashiCorp Vault)
- Auto-generated migration patches (planned as a separate companion tool)

## Acknowledgments

Built with assistance from [Claude Code](https://claude.ai/code).

## License

MIT — see [LICENSE](LICENSE).
