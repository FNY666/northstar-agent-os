# Dispatch admission binds the sources it was composed from

## Problem

DispatchAdmission recorded its states and reasons but neither source digest, so
an admission built from preflight A could be witnessed alongside a different
preflight B that merely had the same state. The witness then presented a
correspondence that nothing backed.

## Fix

- The admission records `preflight_digest` and `liveness_digest`.
- `RouteLivenessVerdict.computed_digest` becomes the single derivation of the
  liveness digest, replacing the witness's private copy.
- `make_admission_witness` refuses a preflight or liveness the admission was not
  built from, so correspondence is verified rather than co-recorded.

## Mutation check

Injected into a throwaway copy only: dropping either correspondence check fails
exactly one test. Baseline 10/10 in the witness module.

## Tasks

- [x] Add the failing tests first (fields absent, substitution accepted).
- [x] Bind the sources and make the witness verify correspondence.
- [x] Mutation-check both new guards.
- [x] Full interop suite 594/594; `py_compile`; `git diff --check`.
- [x] Commit locally only; no push, remote stays frozen at c371a15.
