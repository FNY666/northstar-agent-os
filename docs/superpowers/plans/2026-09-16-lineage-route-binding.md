# Lineage verification must be bound to its route

## Problem

`verify_lineage` took the last event of the whole graph as the terminal receipt
and never named a route. In a store holding more than one route, another route's
successful receipt could therefore satisfy a verification that claimed to be
about a different, still-running route.

## Fix

- `route_id` may be passed to scope the lineage to the route under verification;
  a route with no lineage reports `unknown` rather than falling back to others.
- Without `route_id`, a multi-route lineage reports `unknown` instead of using
  the last event, which pinning nothing about which route was verified.
- A single-route lineage keeps its previous behaviour, so existing callers are
  unaffected.

## Mutation check

Injected into a throwaway copy only: dropping the multi-route guard, and dropping
the scoping filter, each fail a test. Full interop suite 601/601.

## Tasks

- [x] Add the failing tests first.
- [x] Bind verification to a route; fail closed when it is ambiguous.
- [x] Mutation-check both guards.
- [x] Commit locally only; no push, remote stays frozen at c371a15.
