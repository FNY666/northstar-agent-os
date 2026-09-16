# Plan identity in dispatch admission

## Problem

`evaluate_dispatch_admission(..., plan_id=...)` accepted caller-labelled free
text and recorded it in the admission digest and witness as if it were a bound
identity. Nothing in the preflight or the route liveness verdict corroborated
it, so two callers could label the same preflight differently and obtain
different admission digests that both looked source-bound.

## Fix

- Without corroboration, plan identity is recorded as `plan_id_unverified` and
  the strongest achievable state is `admit-unpinned` (fail-closed).
- A host-owned `EvidencePlanManifest` corroborates it: its digest must equal the
  preflight's manifest digest and the label must equal the derived identity used
  by the plan evidence gate (`plan-evidence:<manifest digest prefix>`).
- A drift test pins that derivation so an upstream change fails loudly instead
  of silently mislabelling plans.

## Mutation check

Injected into a throwaway copy only: dropping the unverified marker, the digest
match, or the label check each fails exactly one test. Baseline 15/15.

## Tasks

- [x] Add RED tests for uncorroborated, corroborated, wrong-plan, wrong-label.
- [x] Implement the smallest fail-closed change; keep the layer non-authorizing.
- [x] Mutation-check each new guard.
- [x] Run focused and full Interop regressions, `py_compile`, `git diff --check`.
- [x] Commit locally only; do not push or notify other sessions.
