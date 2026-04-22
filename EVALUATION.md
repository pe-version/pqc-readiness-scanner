# Evaluation

This document is a **methodology demonstration**, not a benchmark. Its purpose is to make the scanner's behavior on real codebases auditable and reproducible — not to rank `pqc-scan` against other tools, and not to characterize the security posture of any of the named projects.

## What this measures

For three pinned open-source releases, this evaluation reports:

- The total number of `pqc-scan` findings produced.
- Each finding's classification under a small rubric (below).
- Per-rule precision, defined as `TP / (TP + FP)` where TP is "the scanner correctly identified the algorithm or pattern that the rule documents as detecting" and FP is "the scanner matched something that is not actually the documented algorithm or pattern."

This is not a measurement of:

- Whether the named projects have security vulnerabilities. They don't, in any sense relevant to PQC migration; the algorithms flagged are either deliberate compatibility code, test fixtures, or protocol-mandated.
- Whether `pqc-scan` is "better" or "worse" than another tool. Different tools have different scopes and different definitions of a finding.
- How long migration would take. That depends on the project, not on the scanner.

## Targets (pinned)

Raw scan outputs are committed at `evaluation/raw/{project}.json`.

| Project | Pinned tag | Pinned commit |
| --- | --- | --- |
| psf/requests | v2.32.3 | `0e322af87745eff34caffe4df68456ebc20d9068` |
| django/django | 5.0.10 | `3b3a5f4efbf93692557b7f473519bd0ad8f04c6a` |
| ansible/ansible | v2.17.7 | `dc0e3bd16cc7ded081bc46c88e4e3d1997ca9bb0` |

Scanner version: `pqc-scan 0.2.0`.

To reproduce:

```bash
git clone --depth 1 --branch v2.32.3 https://github.com/psf/requests.git /tmp/requests
git clone --depth 1 --branch 5.0.10 https://github.com/django/django.git /tmp/django
git clone --depth 1 --branch v2.17.7 https://github.com/ansible/ansible.git /tmp/ansible
pqc-scan /tmp/requests --json out/requests.json
pqc-scan /tmp/django   --json out/django.json
pqc-scan /tmp/ansible  --json out/ansible.json
```

## Classification rubric

Each finding is hand-classified into one of:

| Class | Meaning |
| --- | --- |
| `true-positive` | Scanner correctly identified the algorithm in production code. Migration is the right next step. |
| `true-positive-mixed` | Scanner correctly identified the algorithm. Some occurrences are production code, others are tests / legacy compatibility helpers; consumer judgment required. |
| `true-positive-test-only-mostly` | Predominantly in test paths, with a small minority in production code. |
| `true-positive-test-only` | All matches are in `tests/` or fixture directories. The `--skip-tests` flag drops these. |
| `protocol-mandated` | Scanner correctly identified the algorithm, but the algorithm is required by an external protocol or specification (e.g. RFC 7616 HTTP Digest Authentication uses MD5 and SHA-1 by spec). The local fix is not "migrate the algorithm"; it is "deprecate the protocol surface or accept the dependency." |
| `false-positive` | Scanner matched something that is not actually the documented algorithm or pattern. |

The classification spreadsheet is at `evaluation/classification.csv`.

> **Classification methodology note.** The spreadsheet's characterizations of code in `requests`, `django`, and `ansible` reflect the author's reading of public source and documentation at the pinned commits. Maintainers of those projects were not contacted. Where the spreadsheet calls a usage "test-only," "protocol-mandated," or a "legacy migration helper," that is a reviewer inference from the code's location and surrounding context — it is not a maintainer-confirmed statement about intent.

## Results

### Overall

| Metric | Count |
| --- | --- |
| Total findings | 132 |
| True positives (any class) | 132 |
| False positives | 0 |
| Protocol-mandated | 3 |
| Findings in `tests/` or fixture paths (`in_test_path: true`) | 103 of 132 |

**Aggregate precision on these three targets: 132 / 132 = 1.00 — but read this number with three caveats adjacent to it.**

1. **Precision, not accuracy.** Every finding correctly identifies the algorithm its rule claims to detect. That is a narrow claim.
2. **No recall measurement.** We do not know how many real quantum-vulnerable uses the scanner *missed* on these targets. Conservative patterns buy high precision at some cost in recall; that cost is not quantified here.
3. **Precision is not actionability.** Of 132 true positives, only ~6 are production-code migration items you would act on this sprint. The rest are test fixtures, legacy-compatibility helpers, or protocol-mandated usages. Triage is the work; detection is the easy part.

This is the honest framing: the scanner's patterns match what they say they match, on these three codebases, at these three pinned commits. Generalizing beyond that is the reader's call.

### Per project

| Project | Findings | In test paths | Production-relevant (estimated) |
| --- | --- | --- | --- |
| requests | 7 | 4 | 3 (all `protocol-mandated`) |
| django | 22 | 14 | ~8 (legacy hash hashers + deliberate SHA-1 helpers) |
| ansible | 103 | 85 | ~18 (real `cryptography.ec`, real ssh-rsa runtime, JWT RS256/ES256) |

The production-relevant column is an estimate from the classification spreadsheet, not a count derived from the rubric. The point of separating it from the raw total is to make clear that **most findings on a typical repository are not "things to migrate this sprint."** The triage burden is real, and the `--skip-tests` flag exists to make it manageable.

### Per rule

The full per-rule breakdown is in `evaluation/classification.csv`. Highlights:

- **`pqc-scan.source.md5.python-hashlib` in `requests`:** 1 finding, classified `protocol-mandated` (HTTP Digest Auth). The scanner is correct; the algorithm cannot be migrated locally without breaking RFC 7616 interop.
- **`pqc-scan.source.rsa.ssh-rsa` in `ansible`:** 40 findings, predominantly in test inventory files. A real codebase using ansible-runner doesn't have 40 RSA migration items; it has ~5, in the playbook templates that touch SSH.
- **`pqc-scan.jwt.rs256.token` in `ansible`:** 1 finding in production code (Pulp/Galaxy integration). Genuine PQC-migration surface — the JWT library will eventually need ML-DSA support.

## What this evaluation does NOT cover

- **Recall.** This evaluation does not measure how many true positives the scanner *missed*. Doing so would require a hand-built ground-truth annotation of each project's cryptography surface, which is a substantial undertaking and out of scope for this release.
- **Performance.** No latency, memory, or scan-throughput numbers are reported.
- **Stability across versions.** The classification reflects one pinned commit per project; subsequent releases of those projects may shift the numbers.
- **Comparison to other tools.** Different scopes; comparing aggregate counts would be misleading.

## How this evaluation should be used

Treat it as evidence that:

1. The scanner's patterns match what they say they match (precision is real, not asserted).
2. Most findings on real-world Python projects are *correctly identified* but *not actionable as production migration items* — they are tests, fixtures, or protocol-mandated. The output is not a punch list; it is an inventory.
3. The `--skip-tests` flag and `# pqc-scan: ignore[rule-id]` suppression are responses to the actual finding distribution observed here, not hypothetical needs.

## Reproducibility checklist

- [x] Pinned commit SHA per target.
- [x] Pinned scanner version.
- [x] Raw JSON output committed at `evaluation/raw/`.
- [x] Hand-classification committed at `evaluation/classification.csv`.
- [x] Classification rubric documented above.
- [ ] Recall measurement (deferred; would require ground-truth annotation).
