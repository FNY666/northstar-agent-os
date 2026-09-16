# Continuation admission witness

## Gap

The admission layer could evaluate a decision, but an admission carried no
self digest. A host could re-evaluate a continuation and compare the two
decisions by hand, and nothing could prove that the decision a host saw earlier
is the decision now in hand. A self-consistent replacement admission — for
example a blocked continuation replaced by an admitting one built from the same
inputs — was indistinguishable from the original.

## Task 1: Bind every decision field into an admission digest

**Files:**
- Modify: `components/northstar-agent-runtime/continuation_admission.py`
- Modify: `components/northstar-agent-runtime/tests/test_continuation_admission.py`

**Interfaces:**
- Produces: `ContinuationAdmission.unsigned_dict()`, `.computed_digest`, `.admission_digest`; `ContinuationAdmission.from_dict` revalidates the digest.

- [x] Write RED tests: the digest changes with the policy, the age, the
      observation time, and the state; tampering with any single wire field
      fails the round trip.
- [x] Implement the digest and its revalidation.
- [x] Mutation-check.

## Task 2: Record and verify an admission witness

**Files:**
- Modify: `components/northstar-agent-runtime/continuation_admission.py`

**Interfaces:**
- Produces: `ContinuationAdmissionWitness`, `capture_admission_witness(admission, *, observed_at)`, `verify_admission_witness(witness, admission, *, now, expected_witness_digest=None) -> ContinuationVerdict`.

- [x] Write RED tests for current, current-unpinned, replaced admission,
      replaced witness, future observation, unreadable inputs, wire round trip.
- [x] Implement capture and verification, reusing `ContinuationVerdict` so the
      witness states mirror the checkpoint verdict states.
- [x] Mutation-check: dropping the replacement comparison fails the replaced
      admission test; dropping admission digest revalidation fails the wire tests.
- [x] Run the focused, runtime, and interop suites and commit.

## Semantics

| state | meaning |
|---|---|
| `current` | the witness and the supplied admission agree, and the caller pinned the witness digest |
| `current-unpinned` | they agree, but no external pin was supplied, so the witness itself can be replaced undetected |
| `stale` | the admission was replaced (`admission_replaced`), or the witness no longer matches the caller's pin (`witness_digest_changed`) |
| `unknown` | witness or admission unreadable, or the observation is dated in the future |

Wave order: readability, then future observation, then replacement, then the
pin. The verdict is always `execution_authorized=False`.

## What this does not prove

- A witness records one observation. It says nothing about whether the
  continuation should proceed, and it grants nothing: `current` means the
  declared predicates agree, not that execution is permitted.
- Without an external pin the witness is trust-on-first-use: a rewritten
  witness paired with a matching admission verifies as `current-unpinned`.
- Host clocks are not trusted. `observed_at` and `now` are both supplied by the
  caller, so a wrong clock can hide a stale continuation.
- The witness binds the admission decision, not the semantic truth of the
  underlying checkpoint.

## Verification

- focused: 21/21 (was 12/12 before this slice)
- mutations: dropping the replacement comparison fails exactly the replaced
  admission test; dropping admission digest revalidation fails exactly the wire
  revalidation tests
- runtime: 447 tests, **9 runs clean and 2 runs failed** (1 failure plus 1–2
  errors, names not captured) inside a narrow window while the parallel session
  was running its own suites on the same device. The failure did not reproduce
  in 7 subsequent runs. Recorded as an uncharacterised intermittent failure and
  an open question, not as a clean pass.
- interop: 620/620
