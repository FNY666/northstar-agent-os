# Lineage append locking

## Problem

Appending to the lineage log computed the next sequence from in-memory state and
wrote without a lock. Two writers on the same log could therefore emit the same
sequence, which silently breaks the chain the mark was added to protect.

## Design

- Serialise append with a same-directory `flock` (`<log>.lock`), matching the pin
  store and the lease registry.
- Inside the lock, re-read the on-disk tail and refuse a graph that is behind the
  file, rather than writing a duplicate sequence. The caller reloads and retries.
- Keep the mark write inside the same lock so log and mark cannot be interleaved
  by two writers.

## Tasks

- [x] Test that a stale writer is refused and writes nothing.
- [x] Test that several concurrent writers leave a loadable log with contiguous
  sequences and a verified mark.
- [x] Verify the guard by mutation: removing it must fail these tests.
- [x] Run focused tests, full Interop regression, `py_compile`,
  `git diff --check`, and sensitive scan.
- [x] Commit locally only; do not push or notify other sessions.
