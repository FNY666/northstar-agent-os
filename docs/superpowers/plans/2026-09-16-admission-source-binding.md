# Admission source binding audit

## Finding

The real process execution boundary is `ProcessAgentAdapter.execute`, which
validates a Handoff Grant, policy revision, capabilities, private workspace, and
bounded process result. It has no safe, explicit DispatchAdmission parameter, so
this research slice does not force a snapshot-only admission artifact into the
executor.

The admission layer itself had two source-binding holes: a liveness verdict for a
different route could be witnessed against an admission, and a manually-created
liveness verdict could claim `execution_authorized=True`.

## Fix

- `make_admission_witness` requires `liveness.route_id == admission.route_id`.
- Both `evaluate_dispatch_admission` and the witness source-digest path reject a
  liveness verdict whose execution flag is not exactly false.
- Existing executor grant/policy checks remain unchanged; admission remains
  research-only and non-authorizing.

## Tasks

- [x] Add RED tests for route mismatch and forged liveness authorization.
- [x] Make the smallest source-boundary fix without changing the executor API.
- [x] Run focused tests, full Interop regression, `py_compile`,
  `git diff --check`, and sensitive scan.
- [x] Commit locally only; do not push or notify other sessions.
