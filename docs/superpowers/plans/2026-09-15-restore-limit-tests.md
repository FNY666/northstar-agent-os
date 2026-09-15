# Restore limits, pinned by tests

## Problem

Three guarantees were written only in prose: that a whole-store restore is not
locally detectable for pins, the lease registry, and the lineage log, and that an
externally remembered expectation is what catches it. Prose limits drift silently
when code changes.

## Design

Characterisation tests, one per store, that perform the restore and then assert
both halves: the local reader accepts the older state, and the mitigation
reports drift.

- pins: copy the store, pin once more, restore the copy, then
  `verify_pin_resolution` against the remembered head returns `pins-stale`.
- lease registry: copy the store after registering, revoke, take a witness,
  restore the copy, then `inspect` says `active` while the witness says `stale`.
- lineage: copy the log and mark, append, restore, then the reload is
  `verified` with fewer events than the writer had.

## Tasks

- [x] Write the three characterisation tests.
- [x] Keep the assertions honest: they pin the limit and the mitigation, not a
  guaranteed defence.
- [x] Run the new tests, full Interop regression, `py_compile`,
  `git diff --check`, and sensitive scan.
- [x] Commit locally only; do not push or notify other sessions.
