# Dispatch admission

## Problem

Evidence preflight and route liveness answered different necessary questions but
were never composed. A caller could treat ready evidence as sufficient even when
the route was already in flight or terminal.

## Design

`evaluate_dispatch_admission(preflight, liveness, plan_id=...)` returns a
canonical, digested, non-authorizing artifact:

- `admit`: clean evidence and an open route.
- `admit-unpinned`: an open route but evidence or lineage is unpinned/unverified.
- `blocked-evidence`, `blocked-route`, `blocked-both`: explicit failed sides.
- `unknown`: either source is unknown, fail-closed.

The wire form rejects `execution_authorized=True` and carries only identifiers,
states, reasons, unresolved fields, and its digest.

## Tasks

- [x] Eight tests covering every state branch, downgrade semantics, digest round
  trip, authorization rejection, and tamper rejection.
- [x] Keep the composition non-authorizing.
- [x] Run focused tests, full Interop regression, `py_compile`,
  `git diff --check`, and sensitive scan.
- [x] Commit locally only; do not push or notify other sessions.
