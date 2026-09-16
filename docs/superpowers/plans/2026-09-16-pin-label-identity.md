# Pin label must be the derived plan identity

## Problem

`pin_preflight(plan_id, ...)` validated the label's format only and stored the
record under it. Readiness leases and resolution agendas both refuse a plan_id
that is not the host-owned derived identity, so the pin store was the one layer
where an arbitrary label could stand in for a plan.

## Fix

- Pinning refuses a label that is not `derive_plan_id(preflight.manifest_digest)`,
  matching the lease and agenda layers.
- Querying (`resolve`) stays permissive: an unknown label reports
  `pins-unrecorded` rather than raising.

## Test updates

Tests that pinned under free labels now derive the label from the manifest the
preflight was actually built from; synthetic fixtures use a separate derived
label from the real-manifest fixtures, so the two no longer share a key.

## Mutation check

Injected into a throwaway copy only: dropping the guard fails the label test.
Full interop suite 596/596. Two failures seen on one run were the known
process-adapter timing flake: the module passes 3/3 standalone and the full
suite passes on re-run.

## Tasks

- [x] Add the failing test first.
- [x] Enforce the derived identity at write time only.
- [x] Mutation-check the guard; rerun the full suite.
- [x] Commit locally only; no push, remote stays frozen at c371a15.
