# A status outside the declared set is a protocol breach

## Problem

`SIDECAR_STATUSES` is documented as the contract — "statuses the sidecar itself
may return; anything else is a protocol breach" — but `SidecarClient._normalise`
only checked that the status was a non-empty string, so an undeclared status was
accepted and surfaced to callers as if it were a legitimate sidecar verdict.

Measured before the fix, with the test transport returning the payload:

| response status | result.status |
| --- | --- |
| `made_up_status` | `made_up_status` (passed through) |
| `ok` | `ok` |

## Fix

- `_normalise` refuses a status outside `SIDECAR_STATUSES`; the existing handler
  turns that into the local `protocol_error` result, so callers keep getting data
  rather than an exception.
- Local statuses are unaffected: `_failure` builds results directly, and
  `_normalise` has a single caller on the real response path.

## Mutation check

Injected into a throwaway copy only: removing the guard fails the new test. The
same run also errored on `test_the_sidecar_limits_are_mirrored_exactly`, which is
an artifact of copying only this component into `/tmp` without its sibling
sidecar component, not a signal about the change. Runtime suite 388/388, interop
suite 620/620.

## Tasks

- [x] Add the failing test first, plus a pass-through test for every declared status.
- [x] Enforce the declared status set on the response path only.
- [x] Mutation-check the guard, and explain the unrelated error rather than ignore it.
- [x] Commit locally only; no push, remote stays frozen at c371a15.
