# S11 — Offline Synthetic Checkpoint/Ack State-Machine Model

synthetic_only=true  
production_verified=false  

## Scope and method

This is a deterministic, local-only simulation. It models the nominal sequence:

`prepared -> journaled -> acknowledged -> replayed -> reconciled`

The harness inserts a crash cut after each successful state transition and records the raw outcome. It also exercises bounded retry budget, idempotency-key collision, stale checkpoint, operator abort, duplicate replay (same and conflicting digest), missing acknowledgement, and conflicting acknowledgement. It compares two boundary policies:

* **fail-closed:** `UNKNOWN -> REJECT`; raw `UNKNOWN` remains visible in the trace.
* **fail-open:** `UNKNOWN -> ACCEPT`; raw `UNKNOWN` remains visible in the trace.

`UNKNOWN` is not equivalent to `REJECT`. `REJECT` means a simulated contradiction, explicit abort, collision, stale checkpoint, or conflicting input. `UNKNOWN` means the local model cannot establish the required fact (for example, a crash cut or missing acknowledgement).

## Deterministic result

The harness ran 15 fixtures. Final raw outcomes: **ACCEPT=3, REJECT=5, UNKNOWN=7**. Full event traces and every crash-cut result are in `outputs/results.json`.

| Fixture | Scenario | Evidence class | Raw | Reason | Fail-closed | Fail-open |
|---|---|---|---|---|---|---|
| S11-01 | clean path | confirmed | ACCEPT | consistent local trace | ACCEPT | ACCEPT |
| S11-02 | cut after prepared→journaled | confirmed | UNKNOWN | crash cut | REJECT | ACCEPT |
| S11-03 | cut after journaled→acknowledged | inferred | UNKNOWN | crash cut | REJECT | ACCEPT |
| S11-04 | cut after acknowledged→replayed | unverified | UNKNOWN | crash cut | REJECT | ACCEPT |
| S11-05 | cut after replayed→reconciled | inferred | UNKNOWN | crash cut | REJECT | ACCEPT |
| S11-06 | bounded retry exhausted | confirmed | UNKNOWN | retry budget exhausted | REJECT | ACCEPT |
| S11-07 | idempotency-key collision | conflicting | REJECT | collision | REJECT | REJECT |
| S11-08 | stale checkpoint | conflicting | REJECT | stale checkpoint | REJECT | REJECT |
| S11-09 | operator abort | confirmed | REJECT | operator abort | REJECT | REJECT |
| S11-10 | duplicate replay, same digest | confirmed | ACCEPT | idempotent duplicate | ACCEPT | ACCEPT |
| S11-11 | duplicate replay, conflicting digest | conflicting | REJECT | replay conflict | REJECT | REJECT |
| S11-12 | missing acknowledgement | unverified | UNKNOWN | acknowledgement unobserved | REJECT | ACCEPT |
| S11-13 | conflicting acknowledgement | conflicting | REJECT | conflicting acknowledgement | REJECT | REJECT |
| S11-14 | external durability unavailable (represented as cut) | inaccessible | UNKNOWN | crash cut / inaccessible fact | REJECT | ACCEPT |
| S11-15 | retry succeeds before budget | inferred | ACCEPT | consistent local trace | ACCEPT | ACCEPT |

## Claims and evidence classification

1. **confirmed:** Within this executable model, clean progression reaches `reconciled`; explicit abort and same-digest duplicate replay have deterministic outcomes; retry exhaustion yields `UNKNOWN`.
2. **inferred:** A successful retry before the configured budget allows the modeled path to continue; crash cuts make completion unobservable.
3. **unverified:** Missing acknowledgement and a cut around acknowledgement cannot be resolved by this local trace.
4. **conflicting:** Collision, stale checkpoint, conflicting replay digest, and conflicting acknowledgement are modeled as `REJECT`.
5. **inaccessible:** Filesystem durability, remote state, and external acknowledgement are outside this local-only model and are not asserted.

These labels describe model fixture epistemics, not production evidence.

## Explicit non-claims / limitations

This local state machine **cannot prove** filesystem durability, remote state, exactly-once processing, rollback, immutable audit, crash-recovery completeness, cross-process ordering, clock correctness, network behavior, or production readiness. It uses no network, real service, credentials, SDK, or external system. A successful local simulation is not an operational approval and does not establish a safety guarantee.

The crash cut is a deterministic observation boundary, not a power-loss test. The retry budget is an integer model parameter, not a service SLA. Fail-open is included for comparison only and can convert uncertainty into acceptance; it must not be read as evidence that such a policy is safe.

## Reproduction

From this directory:

```sh
python3 harness.py
python3 validator.py
python3 manifest_validator.py
(cd /tmp/C-NEXTGEN-TRUST-CONTINUITY-20260922-S11 && sha256sum -c SHA256SUMS)
```

Expected validator status is PASS. The generated result is deterministic JSON with sorted keys and two-space indentation.

## Next independent slice; keep running

**S12 proposal:** offline synthetic recovery-window model: enumerate restart points between journal write, acknowledgement observation, replay application, and reconciliation; vary only deterministic recovery evidence (present, absent, contradictory), with bounded replay budget and an explicit `UNKNOWN` preservation check. Keep it isolated from production artifacts and do not infer durability or exactly-once behavior.
