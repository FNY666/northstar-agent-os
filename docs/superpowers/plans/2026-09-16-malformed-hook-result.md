# An unsupported hook result must not silently mean noop

## Problem

The hook contract permits `None`, `HookResult`, dict, or bool. `coerce_result`
turned every other return type into `HookResult(decision="noop")`. On `PreToolUse`
and other veto-capable events a broken hook therefore looked like no opinion and
allowed the operation, despite the module's documented rule that an unreadable
veto verdict fails closed.

## Fix

- Unsupported return types now raise `TypeError`.
- The existing hook dispatcher already handles exceptions correctly: veto-capable
events deny and stop the chain; observation-only events record the error but
continue.

## Mutation check

Injected into a throwaway copy only: restoring the silent noop behavior causes
the direct coercion and veto tests to fail; the observation test errors because
`outcome.errors` is correctly empty under the bad behavior. That error is an
expected effect of the mutation, not an environment artifact. Runtime 394/394,
interop 620/620.

## Tasks

- [x] Add the failing tests first for coercion, veto, and observation events.
- [x] Reject unsupported return types and reuse the existing exception path.
- [x] Mutation-check every behavior; identify the error's cause.
- [x] Commit locally only; no push, remote stays frozen at c371a15.
