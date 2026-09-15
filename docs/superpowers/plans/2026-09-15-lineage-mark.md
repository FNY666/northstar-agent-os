# Lineage log rollback detection

## Problem

The lineage log decides which route state is active, but it only verified its
hash chain. Any prefix of a chain verifies, so truncating the terminal event
rolled a route back to an earlier state that still looked plausible, and
`cursor()` could not notice because it was derived from the same log.

## Design

- `LineageGraph` writes a sibling mark (`<log>.mark.json`) holding the
  high-water mark (`sequence`, `head_digest`) after each append, atomically
  (temp file, fsync, `os.replace`).
- `from_path` validates the mark: a shorter log raises
  `lineage history is truncated`; an equal-length log whose tail digest differs
  raises `lineage mark mismatch`; a log ahead of its mark is the crash window and
  is repaired forward (`mark_state == "repaired"`).
- A log with no mark loads as `mark_absent`, because hand-built and migrated v1
  logs are a real workflow; v1 logs carry no chain and are never marked.

## Audit note

The same structure was found in three places. The pin store and the lease
registry were fixed first; `route_lineage.py` was found by asking where else the
pattern appears, and `audit_export.py` was audited and left unchanged because its
manifest already anchors exports.

## Tasks

- [x] Test a truncated terminal event, a truncated route, mark absent, log ahead
  of mark (repair), and mark kept in sync by appends.
- [x] Keep existing migration, replay, and persistence behaviour passing.
- [x] Run focused tests, full Interop regression, `py_compile`,
  `git diff --check`, and sensitive scan.
- [x] Commit locally only; do not push or notify other sessions.
