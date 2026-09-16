# Continuation admission

## Gap

`verify_checkpoint` binds a checkpoint to the current host observation but never
checks how old that observation is, and neither the checkpoint store nor the
runtime adapter had any admission concept. A checkpoint observed long ago still
verified as `current`, so an unattended loop could resume an arbitrarily stale
continuation with every existing check green.

## Task 1: Host-owned admission policy and admission record

**Files:**
- Create: `components/northstar-agent-runtime/continuation_admission.py`
- Create: `components/northstar-agent-runtime/tests/test_continuation_admission.py`

**Interfaces:**
- Produces: `ContinuationPolicy`, `ContinuationAdmission`, `ContinuationAdmissionError`, `evaluate_continuation_admission(checkpoint, verdict, *, policy, now)`.

- [x] Write RED tests for admit, freshness refusal, policy pin refusal, stale, unknown, future observation, wire round trip, and invalid policy.
- [x] Implement a non-authorizing, fail-closed evaluation.
- [x] Mutation-check both decision branches.
- [x] Commit.

## Task 2: Runtime admission adapter

**Files:**
- Modify: `components/northstar-agent-runtime/loop.py`

**Interfaces:**
- Add `admit_persisted_continuation_checkpoint(store, *, goal, now, policy, expected_record_digest=None) -> ContinuationAdmission`.
- Compose the persisted verdict through the same private helper as the existing
  resolve API, so each call performs exactly one store read.

- [x] Add the adapter method.
- [x] Assert the provider stays untouched by admission.
- [x] Mutation-check and run both suites.
- [x] Commit.

## States

| State | Meaning |
| --- | --- |
| `admit-continuation` | Verdict is `current`, age is inside the policy window, and no pin requirement is outstanding. |
| `admit-continuation-unpinned` | Same predicates agree, but the host explicitly opted out of requiring a pinned checkpoint digest. |
| `blocked-continuation-stale` | The checkpoint no longer matches the current host observation. |
| `blocked-continuation-age` | The age of the observation exceeds `max_age_seconds`. |
| `blocked-continuation-policy` | The policy requires a pinned checkpoint and the verdict is unpinned. |
| `unknown` | The verdict or checkpoint is unreadable, or the observation is dated in the future. |

Every admission carries `execution_authorized=False`, and a wire form that claims
authorization is refused.

## What this does not prove

- That `admit-continuation` permits a run. It means the freshness, pin, and
  host-state predicates the host declared agree; permission, budget, capability,
  and the actual action still need their own gates.
- That the timestamps are meaningful. `now` and `observed_at` are both
  host-supplied, so a wrong clock can make a stale continuation look fresh.
- That continuing is desirable, or that the loop can be finished. Completion is
  a separate contract.

## Verification

- Focused admission tests: 12/12.
- Runtime suite: 438/438.
- Interop suite: 620/620 on six consecutive runs. One earlier run in this
  session reported a single failure with no captured name; it did not reproduce
  across six later runs and matches the previously recorded timing sensitivity
  of that suite.
- Mutation: removing the freshness comparison fails exactly the two freshness
  tests; dropping the pin requirement fails exactly the policy opt-in test.
