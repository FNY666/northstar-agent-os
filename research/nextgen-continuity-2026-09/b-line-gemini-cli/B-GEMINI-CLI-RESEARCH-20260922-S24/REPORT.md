# S24 — attempt boundary under repeated arrival (synthetic-only)

**Slice:** B line, S24  
**Scope:** completely offline; synthetic-only; one worker; one `op_id`; attempts 1 and 2; repeated arrivals and attempt boundary.  
**Date:** 2026-09-22  
**Flags:** `synthetic_only=true`; `production_verified=false`.

## Executive result

The deterministic local model ran **14 fixtures**, containing **33 arrivals**. It produced:

| outcome | count |
|---|---:|
| accepted | 17 |
| rejected | 5 |
| UNKNOWN | 11 |

All fixtures passed their expected outcomes. An exact repeated arrival within the same attempt is accepted when the complete local tuple (`attempt`, value, response reference, durable reference) matches. A changed value, response reference, or durable reference within an already-recorded attempt is rejected. Crossing from attempt 1 to attempt 2 creates a separate local attempt record; matching fields across the boundary are not collapsed into one record by this model. `UNKNOWN` is preserved as the local observation for the attempt that received it. Thus attempt 1 `UNKNOWN` followed by an attempt 2 local record does not retroactively become accepted, and a later exact attempt 1 replay remains `UNKNOWN`.

These are properties of the synthetic contract and harness only, not observations of Gemini CLI.

## Deterministic fixture coverage

| fixture | coverage | expected result |
|---|---|---|
| S24-01 | attempt 1; exact same value/response/durable refs | accepted, accepted |
| S24-02 | attempt 1; value changes | accepted, rejected |
| S24-03 | attempt 1; response ref changes | accepted, rejected |
| S24-04 | attempt 1; durable ref changes | accepted, rejected |
| S24-05 | attempt 1 `UNKNOWN`; exact replay | UNKNOWN, UNKNOWN |
| S24-06 | attempt 1 `UNKNOWN` → attempt 2 same tuple | UNKNOWN, accepted |
| S24-07 | attempt 1 `UNKNOWN` → attempt 2 different tuple | UNKNOWN, accepted |
| S24-08 | attempt 1 accepted → attempt 2 same tuple | accepted, accepted |
| S24-09 | attempt 1 accepted → attempt 2 different tuple | accepted, accepted |
| S24-10 | attempt 1 `UNKNOWN`; attempt 2 exact replay | UNKNOWN, accepted, accepted |
| S24-11 | attempt 2 response ref changes | UNKNOWN, accepted, rejected |
| S24-12 | attempt 2 durable ref changes | UNKNOWN, accepted, rejected |
| S24-13 | attempt 1 `UNKNOWN`, attempt 2 record, then attempt 1 replay | UNKNOWN, accepted, UNKNOWN |
| S24-14 | attempt 1 accepted; attempt 2 `UNKNOWN` exact replay | accepted, UNKNOWN, UNKNOWN |

Coverage explicitly includes same/different values, consistent/inconsistent response and durable references, attempt 1 `UNKNOWN` followed by attempt 2 local recording, and whether `UNKNOWN` persists at the boundary.

## Rule under test

For one worker and one `op_id`, the model keeps an attempt-local first tuple:

`(attempt, value, response_ref, durable_ref)`

1. First arrival for an attempt records the tuple and returns its supplied local observation (`accepted` or `UNKNOWN`).
2. An exact repeated tuple in that attempt repeats the supplied local observation.
3. A changed field in that attempt is `rejected`.
4. A new attempt is a new local record, even if its value and references equal the previous attempt; no cross-attempt deduplication is inferred.
5. A later replay of an attempt 1 `UNKNOWN` remains `UNKNOWN`; attempt 2 does not rewrite attempt 1 history.

This is a deliberately narrow boundary model. It does not test ordering permutations beyond the listed deterministic arrivals, concurrency, more than one worker, more than one `op_id`, key collisions, reconciliation, or exhaustive state space.

## Evidence classification

- **Confirmed:** 14/14 synthetic fixtures pass; 33 deterministic arrival outcomes equal the fixture expectations; counts are 17 accepted, 5 rejected, 11 `UNKNOWN`. File generation and checksum validation are local execution facts.
- **Inferred:** attempt is treated as a local record boundary; exact same-attempt replay is stable; `UNKNOWN` is sticky for the attempt-local history. These follow from the synthetic contract, not from product evidence.
- **Unverified:** Gemini CLI's actual persistence, crash durability, retry semantics, remote state, delivery semantics, rollback behavior, and production safety.
- **Conflicting:** any assertion that the synthetic rule proves external Gemini CLI behavior; the slice has no external product evidence and therefore such an assertion conflicts with the evidence boundary.
- **Inaccessible:** real Gemini CLI, real service endpoints, credentials, remote state, production logs/telemetry, prior research and prohibited local artifacts (S1–S23, shared/P0, incident directories, D10, L12, D14, canonical, staging, 140, tri-line, systemd).

## Explicit non-claims

This model **cannot prove** Gemini CLI real crash durability, remote state, exactly-once behavior, rollback, or production safety. It cannot establish that any remote write occurred, survived a crash, was applied once, or was safely reversible. It also cannot substitute for service or CLI testing; those activities are excluded from S24.

## Reproduction and validation

Commands executed in the new directory only:

```sh
python3 harness.py
python3 - <<'PY'
import json
p='outputs/results.json'
d=json.load(open(p))
assert d['synthetic_only'] is True
assert d['production_verified'] is False
assert d['fixture_count'] == 14
assert d['arrival_count'] == 33
assert d['outcome_counts'] == {'accepted': 17, 'rejected': 5, 'UNKNOWN': 11}
assert all(x['status'] == 'PASS' for x in d['results'])
print('VALIDATOR: PASS (14 fixtures, 33 arrivals, counts match)')
PY
(cd /tmp/B-GEMINI-CLI-RESEARCH-20260922-S24 && sha256sum -c SHA256SUMS)
```

Expected/observed validation output:

```text
VALIDATOR: PASS (14 fixtures, 33 arrivals, counts match)
harness.py: OK
fixtures/cases.json: OK
outputs/results.json: OK
REPORT.md: OK
sources.md: OK
research-manifest.json: OK
```

`SHA256SUMS` is generated after all content is written; the checksum file does not self-hash.

## Scope exclusions and integrity

No multi-worker behavior, state-space enumeration, dedup-key collision, manual reconciliation, real Gemini CLI invocation, real service test, credentials, or prohibited research artifact was used. All output files in this slice explicitly carry `synthetic_only=true` and `production_verified=false` either as a machine-readable field or, for this Markdown report and checksum list, in this report's metadata and manifest.

## Next independent slice recommendation — do not stop the line

**S25: offline synthetic restart-window slice.** Keep one worker and one `op_id`, but add a deterministic crash/restart *simulation* around the local write boundary (before-record, record-before-response, response-before-record), with attempts 1/2, same/different value, and response/durable references. Record only local simulated journal states and classify `accepted`/`rejected`/`UNKNOWN`; do not claim real crash durability, remote state, exactly-once, rollback, or production safety. Keep S25 in a fresh directory, with its own fixtures, harness, validator, manifest, and checksums; do not read S24 or any other prior research artifacts. This is a suggested independent test design, not production evidence.
