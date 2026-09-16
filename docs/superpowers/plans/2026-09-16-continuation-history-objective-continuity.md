# Continuation history and objective continuity

## Gap

The store exposed only the newest record per session, so a host could verify a
continuation but could not see that the objective had silently changed between
persisted checkpoints. Every record is verified against the goal the caller
supplies, so an objective swap left all existing checks green.

## Deliverable

- `AutonomyCheckpointStore.history(session_id, expected_head_digest=None)`:
  a read-only chain view with sequence, record digest, checkpoint digest,
  objective digest and observation time per record.
- `ContinuationHistory` states: `continuous`, `objective_changed` (with the
  first sequence where it changed), `unrecorded`, `unverifiable`.
- `AgentRuntime.continuation_objective_history(...)` as the host entry point.

## Semantics

Report, never enforce: a changed objective is surfaced, not blocked. An
unreadable, truncated or non-contiguous chain is `unverifiable` and yields no
entries. Head drift is reported as `history_head_changed`, and a missing
external head pin as `history_head_unpinned` in `unverified`.

## Boundaries

- The objective digest is read from the checkpoint's own bound goal digest, so a
  caller-supplied goal can never make a swapped objective look continuous.
- A report is derived, not authored: it carries no self digest, so rewriting a
  field with another valid value is detectable only by recomputation from the
  store chain or by pinning `head_digest`. This is asserted as a negative
  control in the tests instead of being papered over.
- Continuity is neither authority nor desirability: `execution_authorized` is
  always false, nothing resumes, and `continue_session()` is untouched.

## Verification

- focused 8/8; mutation A (objective comparison dropped) fails the objective and
  runtime tests; mutation B (unreadable chain reported as continuous) fails the
  tamper test.
- runtime 455/455.
- interop 620/620 on six consecutive runs at 13-17s. Two later runs took 64.9s
  and 90.1s and each reported one failure, in two different subprocess and
  concurrency tests (`test_process_adapter...`, `test_concurrent_writers...`),
  each passing 3/3 when run alone. The device is known to be memory bound, so
  load is the leading explanation; both failures are outside this change, which
  touches the runtime component only.
