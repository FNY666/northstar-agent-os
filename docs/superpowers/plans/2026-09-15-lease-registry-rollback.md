# Lease registry rollback detection

## Problem

The lease registry verified a hash chain, but any prefix of a hash chain also
verifies. Truncating the log to the register-only record made a revoked lease
read as `active` again: revocation, the one monotonic fact this registry exists
to keep, could be silently rolled back.

## Design

- Add the high-water mark (`sequence`, `head_digest`) to the registry metadata,
  written atomically after each append and created at `sequence: 0` before the
  first append.
- Apply the mark on read: shorter than the mark is `history_truncated`, an
  equal-length log with a different tail is `high_water_mismatch`, a missing or
  malformed mark beside an existing log is unverifiable, and a log ahead of its
  mark is the crash window and is repaired forward.
- Keep `history_started` derivable from the mark so an empty store still reads
  as `unknown` while a deleted log with a non-zero mark reads as unverifiable.

## Tasks

- [x] Reproduce the silent un-revocation with a failing test before the fix.
- [x] Test truncated revocation, truncated registration, mark ahead of log, log
  ahead of mark, and whole-store removal.
- [x] Keep revocation monotonic across a repair and every verdict
  non-authorizing.
- [x] Run focused tests, full Interop regression, `py_compile`,
  `git diff --check`, and sensitive scan.
- [x] Commit locally only; do not push or notify other sessions.
