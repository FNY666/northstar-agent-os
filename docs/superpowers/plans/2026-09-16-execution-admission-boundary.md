# Execution boundary between research admission and the process executor

## Problem

Dispatch admission, preflight, liveness, and their witness are research-only and
non-authorizing. Nothing stopped a future change from silently importing one of
those snapshot layers into `ProcessAgentAdapter` or from adding an `admission`
parameter, which would let a snapshot-only artifact look like real execution
authority.

## Characterisation

- `ProcessAgentAdapter.execute` accepts only host-owned execution inputs
  (handoff token, context ref, handoff secret, policy revision, now).
- The adapter does not import `dispatch_admission`, `dispatch_admission_witness`,
  `evidence_readiness_preflight`, or `route_liveness`.
- The boundary is deliberate: handoff grant, policy revision, capability subset,
  private workspace, and bounded process execution remain the real gates.

## Mutation check

Injected into a throwaway copy only: adding a research-layer import fails one
test; adding an `admission` parameter to `execute` fails two tests. Baseline is
3/3 passing, so the tests are evidence, not decoration.

## Tasks

- [x] Characterise the executor signature and imports without changing them.
- [x] Confirm the boundary is about execution authority, not missing checks.
- [x] Mutation-check both directions of the boundary.
- [x] Run focused and full Interop regressions, `py_compile`, `git diff --check`.
- [x] Commit locally only; do not push or notify other sessions.
