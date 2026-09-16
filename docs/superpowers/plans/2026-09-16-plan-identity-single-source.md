# Plan identity single source

## Problem

The host-owned plan identity `plan-evidence:<manifest digest prefix>` was written
literally in four modules: plan evidence decisions, readiness leases, resolution
agendas, and the new dispatch admission. Any change to one copy would let leases,
decisions, gates, agendas, and admissions silently disagree about what plan a
record refers to.

## Fix

- `plan_evidence_decision.derive_plan_id` is now the single implementation.
- Leases, agendas, and dispatch admission delegate to it; the dispatch admission
  keeps its validating wrapper and public name.
- Guards: every call site must agree, the literal may appear in exactly one
  module, and the derived value is pinned because persisted records carry it.

## Mutation check

Injected into a throwaway copy only:

- re-duplicating a literal in the lease fails the single-source guard;
- changing the sole derivation fails the pinned-value guard. Without that pin the
  change would have passed, since a single source keeps all callers consistent
  while persisted records still carry the old identity.

## Tasks

- [x] Add the failing guard first, then converge the derivation.
- [x] Keep behaviour identical; full interop suite 589/589.
- [x] Mutation-check both guards, including the guard that initially missed.
- [x] `py_compile` and `git diff --check`; commit locally only.
