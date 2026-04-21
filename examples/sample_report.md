# PQC Readiness Report

**Target:** `tests/fixtures`

## Summary

| Severity | Count |
| --- | --- |
| critical | 2 |
| high | 10 |

## Findings

| Severity | Algorithm | Location | Recommended replacement |
| --- | --- | --- | --- |
| critical | MD5 | `tests/fixtures/vulnerable_app.js:8` | SHA-256 / SHA-3-256 (or SHA-384+ for long-term assurance) |
| critical | MD5 | `tests/fixtures/vulnerable_code.py:10` | SHA-256 / SHA-3-256 (or SHA-384+ for long-term assurance) |
| high | RSA | `tests/fixtures/vulnerable_app.go:12` | ML-KEM (FIPS 203) for key encapsulation; ML-DSA (FIPS 204) for signatures |
| high | ECDSA | `tests/fixtures/vulnerable_app.go:13` | ML-DSA (FIPS 204, Dilithium) or SLH-DSA (FIPS 205, SPHINCS+) |
| high | RSA | `tests/fixtures/vulnerable_app.js:4` | ML-KEM (FIPS 203) for key encapsulation; ML-DSA (FIPS 204) for signatures |
| high | SHA-1 | `tests/fixtures/vulnerable_app.js:9` | SHA-256 / SHA-3-256 (or SHA-384+ for long-term assurance) |
| high | ECDH | `tests/fixtures/vulnerable_app.js:11` | Hybrid X25519 + ML-KEM, or pure ML-KEM (FIPS 203) |
| high | RSA | `tests/fixtures/vulnerable_code.py:5` | ML-KEM (FIPS 203) for key encapsulation; ML-DSA (FIPS 204) for signatures |
| high | ECDSA | `tests/fixtures/vulnerable_code.py:5` | ML-DSA (FIPS 204, Dilithium) or SLH-DSA (FIPS 205, SPHINCS+) |
| high | RSA | `tests/fixtures/vulnerable_code.py:7` | ML-KEM (FIPS 203) for key encapsulation; ML-DSA (FIPS 204) for signatures |
| high | ECDSA | `tests/fixtures/vulnerable_code.py:8` | ML-DSA (FIPS 204, Dilithium) or SLH-DSA (FIPS 205, SPHINCS+) |
| high | SHA-1 | `tests/fixtures/vulnerable_code.py:11` | SHA-256 / SHA-3-256 (or SHA-384+ for long-term assurance) |

## Algorithm notes

- **MD5** — Collisions trivially producible. Unsafe for any security purpose.
- **RSA** — Broken by Shor's algorithm on a CRQC. Migrate before long-lived secrets are at risk.
- **ECDSA** — Elliptic-curve discrete-log is broken by Shor's algorithm.
- **SHA-1** — Practical collisions demonstrated (SHAttered, 2017). Deprecated by NIST.
- **ECDH** — Long-lived ECDH-protected secrets are subject to harvest-now-decrypt-later.
