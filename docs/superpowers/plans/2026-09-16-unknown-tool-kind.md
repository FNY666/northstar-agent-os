# An unknown tool kind must not read as read-only

## Problem

`ToolSpec.__post_init__` derived the mutation flag as
`self.kind in {"edit", "exec", "network", "other"}` and validated only the tool
name, so a kind outside that set produced `is_mutating=False`. `evaluate_spec`
passes that flag to the permission engine, so a mistyped kind made a state
changing tool look read-only and bypassed the mutating gate.

Measured before the fix, `ToolSpec(kind="totally_unknown_kind")`:

| mode | decision |
| --- | --- |
| `plan` (documented as read-only) | allowed, "read-only, permitted in plan mode" |
| `default` with no host callback | allowed, "read-only, permitted in default mode" |

`PermissionEngine.evaluate` already normalises an unknown kind to `other` (which
is mutating, i.e. fail closed), but that branch is unreachable for spec-driven
calls: `evaluate_spec` supplies `kind` and `is_mutating` explicitly from the spec.

## Fix

- `TOOL_KINDS` becomes the single declared set in `permissions.py`; the engine's
  inline literal is replaced by it.
- `ToolSpec` refuses an undeclared kind at construction and derives the mutation
  flag from `MUTATING_KINDS`, so the tools layer and the policy layer cannot drift.

## Mutation check

Injected into a throwaway copy only: removing the validation fails exactly the two
new tests, with no unrelated failures. Runtime suite 391/391, interop 620/620.

## Tasks

- [x] Add the failing tests first (construction, gate path, and every declared kind).
- [x] Fail closed on an undeclared kind; dedupe the kind sets.
- [x] Mutation-check the guard and run both component suites.
- [x] Commit locally only; no push, remote stays frozen at c371a15.
