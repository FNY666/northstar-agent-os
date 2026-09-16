# An unknown HookResult decision must not silently disappear

## Problem

`HookDecisionKind` is a `Literal`, which Python does not enforce at runtime.
A directly constructed `HookResult(decision="unknown_decision")` reached the
dispatcher, matched no branch, and silently allowed a `PreToolUse` event.

## Fix

- `HOOK_DECISIONS` is the declared runtime decision set.
- `HookResult.__post_init__` refuses an unknown decision at ordinary construction.
- `coerce_result` re-validates an existing HookResult, covering an object that
  was deserialised or otherwise built by bypassing the constructor; the dispatcher
  then reuses its existing exception semantics (veto event deny, observation log).

## Mutation check

Injected into a throwaway copy only: removing the constructor validation fails
the direct-construction test. Runtime 398/398, interop 620/620.

## Tasks

- [x] Add RED tests for ordinary construction and a deliberately bypassed object.
- [x] Validate both construction and coercion boundaries.
- [x] Mutation-check and run both suites.
- [x] Commit locally only; no push, remote stays frozen at c371a15.
