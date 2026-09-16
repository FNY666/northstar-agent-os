# Route identity corroboration

## Problem

`evaluate_route_liveness` reported `dispatchable` for any route with no lineage.
A typo, or a route belonging to a different graph, therefore looked exactly like
a legitimate new route and could support a clean admission.

## Fix

- A route with no lineage keeps `dispatchable` (new routes must be dispatchable)
  but is reported as `route_identity_unverified`, so no clean `admit` can rest on
  an identity that nothing corroborates.
- A host-owned `declared_routes` collection corroborates the identity; a route
  outside that set is refused rather than silently reported dispatchable.
- Lineage is itself corroboration: a route with events carries no marker.

## Mutation check

Injected into a throwaway copy only: dropping the marker fails one test;
dropping the declared-set refusal fails one test. Baseline 10/10.

## Tasks

- [x] Add RED tests for uncorroborated, lineage-corroborated, declared, refused.
- [x] Propagate the marker through the admission layer and pin the downgrade.
- [x] Mutation-check both guards.
- [x] Run focused and full Interop regressions, `py_compile`, `git diff --check`.
- [x] Commit locally only; do not push or notify other sessions.
