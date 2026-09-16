# Verification must not ignore an unaccounted attempt branch

## Problem

Route liveness was fixed to fail closed on an open dispatch branch, but
`verify_lineage` — the other consumer of the same lineage — still returned
`verified` for such a route, using a concluded terminal while a sibling branch of
the same causal root was unaccounted for.

## Fix

- `unresolved_attempt_branches(graph, route_id)` moves into `route_lineage` as the
  single implementation; `route_liveness` delegates to it instead of keeping a
  private copy.
- `verify_lineage` consults it and reports `unknown` with
  `unresolved attempt branch` rather than verifying around the gap.

## Mutation check

Injected into a throwaway copy only, asserting the edit applied first: removing
the verification guard fails one test; removing the same-root guard in the single
implementation fails four. Full interop suite 605/605.

## Tasks

- [x] Add the failing test first.
- [x] Single implementation, two consumers.
- [x] Mutation-check both guards.
- [x] Commit locally only; no push, remote stays frozen at c371a15.
