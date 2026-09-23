# S9 — synthetic-only trace integrity and deterministic replay

`synthetic_only=true`  
`production_verified=false`

## Scope and isolation

This is a fully offline, deterministic experiment. Inputs are only the locally authored `fixtures/cases.json`; execution uses the Python standard library. No network, real service, credential, SDK, shared/P0, accident/incident directory, D10, L12, D14, canonical, staging, 140, tri-line, systemd, S1–S8, or prior research artifact was accessed. The experiment does not claim or test production behavior.

## Method

Each synthetic evidence record contains an event ID, integer timestamp, validator ID, authorization context, payload, previous-record hash, synthetic signature, and record hash. Canonical JSON (sorted keys, compact separators) is hashed with SHA-256. A synthetic keyed digest is used as a signature stand-in so tampering is detectable inside the fixture; it is explicitly not a production signature. The chain starts at `GENESIS-S9`. The harness checks links, duplicate IDs, count changes, synthetic signature consistency, known validator IDs, monotonic timestamps, declared/undeclared validator rotation, authorization-context transitions, and replay outcomes.

Policy comparison:

- **fail-closed**: REJECT on `conflicting`, `inaccessible`, or `unverified`; otherwise ACCEPT.
- **fail-open**: REJECT on `conflicting`/`inaccessible`; return `ACCEPT_WITH_UNKNOWN` on `unverified`; otherwise ACCEPT.

## Execution and complete result table

Command 1: `cd /tmp/C-NEXTGEN-TRUST-CONTINUITY-20260922-S9 && python3 harness.py run`  
Command 2: `cd /tmp/C-NEXTGEN-TRUST-CONTINUITY-20260922-S9 && python3 harness.py validate`  
Command 3: `cd /tmp/C-NEXTGEN-TRUST-CONTINUITY-20260922-S9 && sha256sum -c SHA256SUMS`

The run generated 14 cases. Complete per-case outcomes:

| Case | Scenario | Classification | Fail-closed | Fail-open |
|---|---|---|---|---|
| C01 | valid append-only chain | confirmed | ACCEPT | ACCEPT |
| C02 | records reordered | conflicting | REJECT | REJECT |
| C03 | exact record duplicate | conflicting | REJECT | REJECT |
| C04 | middle record dropped | conflicting | REJECT | REJECT |
| C05 | signed payload tampered | conflicting | REJECT | REJECT |
| C06 | timestamp rollback | conflicting | REJECT | REJECT |
| C07 | unknown validator material | inaccessible | REJECT | REJECT |
| C08 | declared validator rotation | confirmed | ACCEPT | ACCEPT |
| C09 | undeclared validator rotation | conflicting | REJECT | REJECT |
| C10 | unexpected authorization-context change | conflicting | REJECT | REJECT |
| C11 | declared authorization-context transition | confirmed | ACCEPT | ACCEPT |
| C12 | deterministic same-trace replay | confirmed | ACCEPT | ACCEPT |
| C13 | divergent same-ID replay | conflicting | REJECT | REJECT |
| C14 | crash durability not tested | inferred; unverified | REJECT | ACCEPT_WITH_UNKNOWN |

Per-case results with observations are in `outputs/results.json`; this report table is intentionally complete for all 14 cases.

## Coverage and residual UNKNOWN

- Case coverage: **14/14 = 100% executed**.
- Confirmed classification appears in 4/14 cases = **28.57% confirmed-case fraction**. This low fraction is expected because negative cases are `conflicting` or `inaccessible`, and C14 intentionally leaves a property unverified.
- Residual UNKNOWN: **2 cases** under the conservative count (`C07` inaccessible validator material and `C14` unverified crash-durability property). C14 additionally records `inferred`; it is not silently promoted to confirmed.
- Fail-open differs from fail-closed only for C14: `ACCEPT_WITH_UNKNOWN` versus `REJECT`.

## Findings and limits

1. In this model, reordering, duplication, loss, payload alteration, clock rollback, divergent replay, and undeclared context/validator changes are detectable as conflicting (or inaccessible where the validator material is unavailable).
2. A declared validator rotation and declared authorization transition can be represented as accepted synthetic state transitions. The fixture declaration is not authorization proof.
3. Replaying the same fixture deterministically reproduces the same decision in this process; this does not establish distributed replay safety or exactly-once semantics.
4. Hash-chain verification is not evidence of a real immutable audit log. It does not establish signature authorization, key custody, crash durability, storage atomicity, remote state, availability, freshness, or production readiness.
5. The synthetic keyed digest is not a signature scheme, and known validator IDs are not a trust root. “Inaccessible” means unavailable to this offline fixture, not compromised or invalid in a real system.
6. Clock monotonicity is checked over supplied integer timestamps only; it does not establish a trustworthy clock.
7. Fail-open can admit C14 as `ACCEPT_WITH_UNKNOWN`; that outcome is intentionally not equivalent to verified acceptance.

## Reproducibility

The harness writes `outputs/results.json` deterministically from the fixtures. `harness.py validate` checks the required flags, case count, allowed classifications, and expected policy outcomes. `SHA256SUMS` authenticates this local experiment bundle only after generation; it is not a remote or immutable attestation.

## Next independent slice recommendation (keep service running)

建议下一独立切片 S10：在同样 `synthetic_only=true`、`production_verified=false` 和完全离线约束下，专门构造 crash-window / partial-write / torn-record / restart-recovery fixtures，比较 prefix recovery、quarantine、fail-closed 与 fail-open，并继续把 exactly-once、durability、远端一致性保留为 `unverified`，不得接入真实服务或既有研究产物。保持不停线。

`synthetic_only=true`  
`production_verified=false`
