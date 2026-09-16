# An identity no layer records is not agreement

## Problem

`verify_cross_layer` compared each identity key with `len({x.get(key) for x in
layers}) != 1`. When no layer recorded a key, the set was `{None}` and the key
counted as consistent, so a proof could pass the identity check by omitting the
field everywhere. The deadline check right below it already required a present
integer, so the two halves of the same function disagreed about what absence
means.

## Fix

- Any layer lacking a key, including the empty string, now reports
  `'{key} missing'`, mirroring the deadline handling. Absence takes precedence
  over disagreement between the layers that do record it.
- Existing behaviour for complete identities is unchanged.

## Mutation check

Injected into a throwaway copy only: restoring the lax check fails both new
tests. Full interop suite 617/617.

## Tasks

- [x] Add the failing tests first (all layers omit a key; only one records it).
- [x] Report absence as missing rather than agreement.
- [x] Mutation-check the guard.
- [x] Commit locally only; no push, remote stays frozen at c371a15.
