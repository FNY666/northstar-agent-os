# Preflight pin rollback detection

## Problem

The pin store verifies its hash chain, but a chain prefix is also
self-consistent. Dropping the newest records left `resolve` reporting
`pins-current` for an older pin: a silent rollback that only an externally
remembered chain head could catch.

## Goal

Detect a log that shrank, without requiring the caller to remember a head, while
still healing the narrow crash window between appending a record and updating
its mark.

## Design

- Keep a high-water mark of the log (`sequence`, `head_digest`) in the store's
  metadata file, written atomically after every append (temp file, fsync,
  `os.replace`, directory fsync).
- Create the metadata with `sequence: 0` before the first append, so a log never
  exists without a mark.
- Reading applies the mark: fewer records than marked is `pin history truncated`;
- equal length with a different tail digest is `pin high-water mismatch`; a
  malformed or missing mark beside an existing log is unverifiable; a log ahead
  of the mark is the crash window and is repaired forward, and the resolution
  says `pin_high_water_repaired`.
- Missing log and missing mark together read as a freshly initialised store
  (`pins-unrecorded`).

## Tasks

- [x] Test prefix truncation, empty log, mark ahead of log, mark missing, and
  wrong tail digest as non-current.
- [x] Test crash-window repair and that a repair is reported once and persists.
- [x] Test that removing the whole store still reads as unrecorded, and record
  that limit explicitly.
- [x] Keep every resolution and verdict non-authorizing.
- [x] Run focused tests, full Interop regression, `py_compile`,
  `git diff --check`, and sensitive scan.
- [x] Commit locally only; do not push or notify other sessions.
