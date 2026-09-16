# Admission history head pin

## Gap

The store already accepted `expected_head_digest` and reported head drift, but
the runtime admission API did not accept the pin and discarded the history
reasons and unresolved fields it had computed. A host could not express "no
new continuation records since I looked", and a detected drift vanished before
the admission decision.

## Design

`admit_persisted_continuation_checkpoint` now accepts `expected_head_digest` and
passes it into `resolve_with_history`, which obtains the record and history
under one lock. History signals are bound into the admission digest.

- `history_head_changed` is `blocked-continuation-head`: an explicit host pin
  is a required precondition, so a mismatch must not be report-only.
- `history_head_unpinned` is exposed in `unresolved` but does not silently
  block. The host did not make the stronger pin claim.
- Unreadable history remains `unknown`; all outcomes keep
  `execution_authorized=False` and never resume or call the provider.

## Verification

- focused 46/46.
- mutation A removes head-pin pass-through: matching and drift tests fail.
- mutation B drops history unverified propagation: unpinned-head test fails.
- runtime 465/465 in 68.064s; interop 620/620 in 63.776s. The long durations
  confirm device load; the test-only 6s process-timeout correction keeps the
  interop suite meaningful while retaining a bound below the child's 10s sleep.
