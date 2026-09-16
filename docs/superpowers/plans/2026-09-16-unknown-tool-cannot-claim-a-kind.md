# An unknown tool cannot excuse itself by declaring a kind

## Problem

`PermissionEngine.evaluate` denies a tool the caller reports as unregistered —
but only when its resolved kind is not `task`:

    if not known and resolved_kind != "task":

So `known=False, kind="task"` was allowed as read-only, while every other kind was
refused. A tool could therefore escape the unknown-tool rule by the label it
carried, contradicting the module's stated safety direction that an unknown tool
is denied.

The `Task` exemption was meant to stop the delegation entry point being
blanket-denied, but that concern is already handled: the loop registers
`task_tool_spec()` and both real call sites evaluate with `known=True`
(`loop.py` main path and `check_delegation`, which resolves kinds from the tool
registry and rejects unregistered names before the gate).

## Fix

- Unknown tools are refused whatever kind they declare.
- The module docstring now records why the Task reasoning does not extend to the
  unknown-tool rule.

## Evidence

Probe before the change, `PermissionEngine(mode="default")`:

| call | before |
| --- | --- |
| `evaluate("NotRegistered", kind="task", known=False)` | allowed, source `mode` |
| `evaluate("NotRegistered", kind="other", known=False)` | refused, source `unknown_tool` |
| `evaluate("Task", kind="task", known=True)` after `register_kind` | allowed (unchanged after the fix) |

## Mutation check

Injected into a throwaway copy only: restoring the exemption fails one test.
Runtime suite 386/386, interop suite 620/620.

## Tasks

- [x] Add the failing tests first, including the registered-Task regression case.
- [x] Remove the kind-based exemption; keep the delegation path untouched.
- [x] Mutation-check the guard; run both component suites.
- [x] Commit locally only; no push, remote stays frozen at c371a15.
