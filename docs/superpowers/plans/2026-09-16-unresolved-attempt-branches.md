# A dispatch branch that never concluded must not look terminal

## Problem

`active_attempts` only returns attempts whose terminal is `succeeded`/`failed`
with no execution children, so a `dispatched` branch that never received a
terminal receipt is invisible. `evaluate_route_liveness` then decided the route
state from the last event alone and reported `blocked` even though one branch of
the same causal root was still unaccounted for.

## Fix

- Detect open branches (`planned`/`dispatched` with no execution children) that
  share a causal root with a concluded attempt and do not descend from one; such
  a route reports `unknown` with `unresolved_attempt_branch`.
- Roots without any concluded attempt keep the ordinary state logic, so a freshly
  planned route is still `in_flight`.

## Mutation check

Injected into a throwaway copy only: dropping the `unresolved` state override
fails one test; dropping the same-root guard fails six. A first attempt at a
retry exemption turned out to be dead code — a terminal with an execution child
is never counted as concluded — so it was removed rather than kept as decoration.

## Tasks

- [x] Add the failing test with a real sibling-branch fixture (the first fixture
  used a linear chain and did not express the gap).
- [x] Fail closed on an unresolved branch; keep retry semantics.
- [x] Mutation-check the remaining guards; remove dead code found by mutation.
- [x] Full interop suite 603/603; commit locally only, no push.
