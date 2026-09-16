# A reason-only veto hook must not become an ignored block

## Problem

The comment in `coerce_result` said a hook returning only `{"reason": ...}` on
`PreToolUse` would infer `deny`; the implementation inferred `block` for every
event. `block` is not applicable to `PreToolUse`, so the dispatcher recorded it
as ignored and allowed the tool call.

## Fix

- `coerce_result` accepts optional event context.
- For a dict with no explicit decision but a reason: veto events infer `deny`;
  block events infer `block`; observation-only events infer `noop`.
- Direct `coerce_result({...})` retains its old no-context `block` default for
  public compatibility.

## Mutation check

Injected into a throwaway copy only: restoring the unconditional `block`
inference fails the PreToolUse regression. Runtime 396/396, interop 620/620.

## Tasks

- [x] Add RED tests for PreToolUse deny and Stop block.
- [x] Make inference event-aware at the dispatcher call site.
- [x] Mutation-check the key veto behavior and run both suites.
- [x] Commit locally only; no push, remote stays frozen at c371a15.
