# Route liveness from the lineage

## Problem

Readiness decided whether evidence was current but never asked what the lineage
says about the route, so a route with an unfinished attempt or a terminal outcome
looked exactly like a fresh one.

## Design

`route_liveness.evaluate_route_liveness(graph, route_id)` returns a verdict with
state `dispatchable` / `retryable` / `in_flight` / `blocked` / `unknown`,
`active_status`, `attempt_count`, `unverified`, `reasons`, and
`execution_authorized=False` always.

- No events for the route: `dispatchable` (`no_prior_attempts`).
- Latest event `planned` or `dispatched`: `in_flight`.
- Latest event `failed`: `retryable` when the event is retryable, otherwise
  `blocked`; `succeeded` and `superseded` are `blocked`.
- More than one resolved attempt chain: `unknown` (`multiple_active_attempts`).
- An unmarked log still decides, but reports `lineage_mark_absent`.

## Note on the first attempt

The first implementation classified by `active_attempts`, which only covers
attempts that reached an execution terminal. An unfinished attempt has no chain,
so in-flight work read as `dispatchable`. The library guard for stale writers also
caught a fixture that re-opened the same log without reloading, and
`derive_retry` refused a widened deadline.

## Tasks

- [x] Six tests covering dispatchable, in-flight, blocked, retryable, ambiguity,
  and the unmarked-log case.
- [x] Keep `execution_authorized` false in every verdict.
- [x] Run focused tests, full Interop regression, `py_compile`,
  `git diff --check`, and sensitive scan.
- [x] Commit locally only; do not push or notify other sessions.
