# S10 — Offline Synthetic Crash-Window / Restart-Recovery Report

`synthetic_only=true`
`production_verified=false`
`explicit_flags=synthetic_only=true; production_verified=false`

## Scope and safety boundary

This is C-line independent slice S10. It is a deterministic, local-only simulation of crash windows and restart replay. It covers: crash before write, partial record, torn record, response-before-record, record-before-response, restart replay/recovery, duplicate, loss, conflict, and inaccessible journal state. No network, real service, credential, SDK, shared/P0, accident directory, D10, L12, D14, canonical, staging, 140, tri-line, systemd, S1–S9, or existing research artifact was accessed or read. `forbidden_inputs_read=[]` is recorded in `research-manifest.json`.

The model stores an encoded record `REC|record_id|payload|checksum`, where the checksum is a deterministic truncated SHA-256 over `record_id|payload`. Replay parses bytes that were placed in the synthetic journal; malformed, partial, torn, inaccessible, duplicate, and conflicting states are retained as explicit local observations.

## Decision semantics

- **Fail-closed:** accepts only the clean positive control, rejects a confirmed contradiction, and returns `UNKNOWN` whenever local evidence cannot establish continuity. `UNKNOWN` is not interpreted as success or failure of any real system.
- **Fail-open:** accepts unresolved states to demonstrate the safety cost of assuming success; it rejects the explicit contradictory fixture. This is an intentionally unsafe comparison, not a recommendation.
- Evidence labels are assigned per fixture and are strictly one of `confirmed`, `inferred`, `unverified`, `conflicting`, or `inaccessible`. “Confirmed” means confirmed inside this deterministic simulator only.

## Complete harness output

```text
{"evidence_status_counts": {"confirmed": 5, "conflicting": 1, "inaccessible": 1, "inferred": 3, "unverified": 4}, "fail_closed_counts": {"ACCEPT": 1, "REJECT": 1, "UNKNOWN": 12}, "fail_open_counts": {"ACCEPT": 13, "REJECT": 1, "UNKNOWN": 0}, "fixtures": 14, "residual_unknown_fixture_count": 12}
S10-01: fail_closed=UNKNOWN fail_open=ACCEPT status=confirmed residual=2
S10-02: fail_closed=UNKNOWN fail_open=ACCEPT status=confirmed residual=2
S10-03: fail_closed=UNKNOWN fail_open=ACCEPT status=confirmed residual=2
S10-04: fail_closed=UNKNOWN fail_open=ACCEPT status=inferred residual=2
S10-05: fail_closed=UNKNOWN fail_open=ACCEPT status=inferred residual=2
S10-06: fail_closed=ACCEPT fail_open=ACCEPT status=confirmed residual=0
S10-07: fail_closed=UNKNOWN fail_open=ACCEPT status=unverified residual=3
S10-08: fail_closed=REJECT fail_open=REJECT status=conflicting residual=0
S10-09: fail_closed=UNKNOWN fail_open=ACCEPT status=unverified residual=2
S10-10: fail_closed=UNKNOWN fail_open=ACCEPT status=inaccessible residual=2
S10-11: fail_closed=UNKNOWN fail_open=ACCEPT status=confirmed residual=2
S10-12: fail_closed=UNKNOWN fail_open=ACCEPT status=unverified residual=3
S10-13: fail_closed=UNKNOWN fail_open=ACCEPT status=inferred residual=2
S10-14: fail_closed=UNKNOWN fail_open=ACCEPT status=unverified residual=2
```

## Fixture-by-fixture findings

| ID | Scenario | Evidence | Fail-closed | Fail-open | Residual unknown |
|---|---|---|---|---|---:|
| S10-01 | crash before write | confirmed | UNKNOWN | ACCEPT | 2 |
| S10-02 | partial record after interrupted write | confirmed | UNKNOWN | ACCEPT | 2 |
| S10-03 | torn record/checksum mismatch | confirmed | UNKNOWN | ACCEPT | 2 |
| S10-04 | response before record | inferred | UNKNOWN | ACCEPT | 2 |
| S10-05 | record before response | inferred | UNKNOWN | ACCEPT | 2 |
| S10-06 | complete record and response (positive control) | confirmed | ACCEPT | ACCEPT | 0 |
| S10-07 | duplicate replay, identical payload | unverified | UNKNOWN | ACCEPT | 3 |
| S10-08 | conflicting duplicate payloads | conflicting | REJECT | REJECT | 0 |
| S10-09 | response with lost record | unverified | UNKNOWN | ACCEPT | 2 |
| S10-10 | inaccessible journal segment | inaccessible | UNKNOWN | ACCEPT | 2 |
| S10-11 | partial record plus success response | confirmed | UNKNOWN | ACCEPT | 2 |
| S10-12 | duplicate record with response | unverified | UNKNOWN | ACCEPT | 3 |
| S10-13 | record then negative response | inferred | UNKNOWN | ACCEPT | 2 |
| S10-14 | replayable record without response | unverified | UNKNOWN | ACCEPT | 2 |

### Interpretation of edge classes

- **Before-write / loss:** no local record is not proof that no remote or caller-side effect happened.
- **Partial/torn:** parser rejection identifies local byte inconsistency; it does not identify the durable boundary of a real filesystem or storage device.
- **Response-before-record:** a response is not a local durability receipt in this model.
- **Record-before-response:** a record is intent/evidence in the local model, not proof that a response was observed or that a remote operation happened.
- **Restart replay:** re-reading a complete local record is replay capability, not proof replay is safe, idempotent, or non-duplicating.
- **Duplicate:** identical entries do not prove exactly-once; conflicting entries are rejected rather than arbitrarily selected.
- **Inaccessible:** unavailable evidence remains unknown; absence of replay output must not be treated as absence of state.

## What this does not prove

This local journal/replay result **cannot prove real crash durability**, filesystem/device write ordering, fsync semantics, process or kernel behavior, remote state, delivery, exactly-once processing, rollback, immutable audit, tamper resistance, recovery correctness in a production topology, or production readiness. It also does not prove a remote commit from a local response, and it cannot distinguish an unobserved effect from a lost record. All ACCEPT/REJECT/UNKNOWN results are simulator decisions only.

## Verification record

The harness was run from the S10 directory. The artifact validator and research-manifest validator were run, and checksums were checked with the required command. The exact verification output is:

```text
VALIDATOR PASS: required artifacts, flags, fixtures, labels, and result shape
MANIFEST VALIDATOR PASS: offline scope, provenance flags, forbidden-input declaration, and coverage
SHA256SUMS: all listed files verified successfully
```

## Artifact paths

All paths are under the fresh directory `/tmp/C-NEXTGEN-TRUST-CONTINUITY-20260922-S10/`:

- `REPORT.md`
- `sources.md`
- `research-manifest.json`
- `SHA256SUMS`
- `harness.py`
- `fixtures/cases.json`
- `outputs/results.json`
- `validator.py` and `manifest_validator.py` (verification helpers)

Every generated artifact explicitly contains `synthetic_only=true` and `production_verified=false` (JSON uses boolean `true`/`false`, with the same semantics).

## Next independent slice suggestion — keep the line running

**S11: deterministic checkpoint/ack state-machine model.** Independently model `prepared → journaled → acknowledged → replayed → reconciled` with explicit crash cuts at every transition, bounded retry budgets, idempotency-key collision, stale checkpoint, and operator-abort states. Require an evidence ledger that keeps `UNKNOWN` distinct from `REJECT`, and compare conservative replay against fail-open replay. Keep it offline synthetic-only; do not infer filesystem durability, remote state, exactly-once, rollback, immutable audit, or production readiness from the model.
