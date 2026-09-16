# Objective-aware continuation admission

## Gap

The gate composed only the newest record, so when the objective changed between
two persisted continuations it still returned `admit-continuation`: the caller
supplies the new goal, every digest agrees, and `history()` reported the change
while nothing consulted it.

## Deliverable

- `ContinuationPolicy.require_objective_continuity`, defaulting to the safe value,
  with a strict wire form: a policy dict without the flag is refused.
- New state `blocked-continuation-objective`, reason
  `continuation_objective_changed`, and the first changed sequence surfaced on the
  admission and bound into its digest.
- `AutonomyCheckpointStore.resolve_with_history()` resolves the newest record and
  the objective history from a single locked read, so the gate cannot combine a
  newer history with an older record. `resolve` and `history` delegate to shared
  helpers, keeping their behaviour identical.

## Semantics

Precedence: unreadable inputs and a tampered chain stay `unknown`; a stale record
blocks as stale; then freshness, then a changed objective, then the pin
requirement. The changed sequence is surfaced even when the host opts out, so the
fact stays visible without being enforced.

## Boundaries

- The store still only reports; only the host policy may block.
- Nothing resumes, `continue_session()` is untouched, the provider is never
  called, and `execution_authorized` stays false.
- An objective change is only as trustworthy as the chain: continuity comes from
  the checkpoint's own bound goal digest, and a chain that cannot be read fails
  closed instead of being treated as continuous.

## Verification

- focused 43/43.
- mutation A (history not consulted) fails the two objective tests; mutation B
  (unsafe default) fails the default-policy and wire-form tests.
- runtime 462/462, interop 620/620 at 14.5s (device load was low; earlier
  load-sensitive failures are recorded in the history slice note).
