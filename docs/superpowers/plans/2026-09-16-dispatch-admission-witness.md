# Dispatch admission witness

## Problem

Dispatch admission combined evidence readiness and route liveness, but the
combined verdict itself was not bound to either source snapshot. A caller could
retain an admission artifact while replacing one of its source verdicts.

## Design

`DispatchAdmissionWitness` binds admission, preflight, and liveness digests with
plan/route identifiers and an injected observation time. Verification returns
`current`, `current-unpinned`, `stale`, or `unknown`; all results are
non-authorizing. Wire parsing rejects tampering and `execution_authorized=true`.

## Tasks

- [x] Test source binding, external pinning, changed preflight/liveness, unknown
  source, wire tampering, and false authorization.
- [x] Document that the witness proves consistency, not permission or freshness
  without the source pin/witness/cursor mechanisms.
- [x] Run focused tests, full Interop regression, `py_compile`,
  `git diff --check`, and sensitive scan.
- [x] Commit locally only; do not push or notify other sessions.
