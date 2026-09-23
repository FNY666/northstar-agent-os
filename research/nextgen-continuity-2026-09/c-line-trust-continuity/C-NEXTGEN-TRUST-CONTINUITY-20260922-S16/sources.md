# Sources and execution log

## Source policy

No network, browser, real service, SDK, credential, shared/P0, accident directory, D10/L12/D14, canonical/staging/140/tri-line/systemd, or S1–S15 artifact was read. The only input data is the local synthetic `fixtures/cases.json`; implementation is `harness.py` in this directory. Therefore all conclusions in the manifest are `inferred`, not externally confirmed.

## Deterministic local execution

Commands executed from this directory:

```text
$ python3 harness.py
PASS: generated 22 fixtures / 44 rule-set runs
PASS: deterministic canonical SHA-256 output written to outputs/results.json
PASS: statuses restricted to RECOVERED, UNKNOWN, REJECT

$ python3 validator.py
PASS: 22 fixtures, 44 runs, statuses mutually exclusive
PASS: provenance, reasons, blockers, hashes, rule_set, drift, synthetic flags present
PASS: conservative version-conflict handling verified

$ python3 manifest_validator.py
PASS: manifest local scope, 7 claims, 22 fixtures, v1+v2

$ python3 /var/minis/skills/evidence-first-research/scripts/validate_research.py research-manifest.json
PASS: 7 claims; manifest schema is valid (2026-09-22)

$ sha256sum -c SHA256SUMS
harness.py: OK
validator.py: OK
manifest_validator.py: OK
REPORT.md: OK
sources.md: OK
research-manifest.json: OK
fixtures/cases.json: OK
outputs/results.json: OK
```

The date in the generic validator output is the host execution date. All files are local artifacts for this slice.
