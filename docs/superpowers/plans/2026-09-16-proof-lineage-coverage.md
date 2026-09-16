# The proof composition must actually verify the lineage layer

## Problem

`verify_route_evidence_proof` imported `verify_lineage` and never called it. The
proof therefore composed the bundle, checkpoint chain, merkle proof, and
cross-layer identity while the lineage layer was only assumed: a route with an
unaccounted dispatch branch still produced a `verified` proof, even though
`verify_lineage` now reports `unknown` for exactly that shape.

## Fix

- Run `verify_lineage` against the route record, handoff, and the route named by
  the record, before the cross-layer comparison.
- A lineage that is not `verified` makes the proof `unknown` with the lineage's
  reasons; `failed` semantics stay with the cross-layer check so existing
  behaviour is unchanged.

## Note on the first test

The first version of the regression test passed for the wrong reason: the bundle
covered only the terminal event, so `verify_lineage_bundle` rejected it as a
binding mismatch. The fixture now bundles every event so the unresolved branch is
the only difference; without the fix that version fails, which is the evidence
that the gap was real.

## Mutation check

Injected into a throwaway copy only: removing the lineage verdict check fails the
new test. Full interop suite 615/615.

## Tasks

- [x] Establish the RED for the right reason, not a vacuous pass.
- [x] Call the imported verification; keep `failed` semantics unchanged.
- [x] Mutation-check the guard.
- [x] Commit locally only; no push, remote stays frozen at c371a15.
