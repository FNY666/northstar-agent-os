# An explicit unknown hook decision is a protocol breach, not a guess

## Problem

Dict hook results with an explicit unknown decision, such as
`{"decision":"denyy"}`, went through the same inference path as a dict that
omitted `decision`. Without a reason this became `noop`, silently allowing a
veto event; with a reason it was guessed into `deny`. A misspelled explicit
protocol field should not be repaired by inference.

## Fix

- Track whether the dict contained a `decision` field.
- An explicit decision must be a declared string in `HOOK_DECISIONS`; otherwise
  raise `ValueError` and use the dispatcher's existing fail-closed exception path.
- Event-aware inference remains only for a truly omitted decision, so reason-only
  hooks retain their documented convenience behavior.

## Mutation check

Injected into a throwaway copy only: restoring the guessing behavior fails exactly
the two new explicit-decision tests. Runtime 401/401, interop 620/620.

## Tasks

- [x] Add RED tests for direct coercion, veto dispatch, and reason-only compatibility.
- [x] Separate explicit protocol validation from omitted-decision inference.
- [x] Mutation-check and run both suites.
- [x] Commit locally only; no push, remote stays frozen at c371a15.
