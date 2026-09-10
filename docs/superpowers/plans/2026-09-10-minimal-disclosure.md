# Plan: minimal-disclosure inclusion for evidence

Research worktree only. Push is held until the cross-session discussion closes.

## Goal

`verify_proof` reads only the root and the leaf count, yet it demands the whole
bundle. Let a verifier check one event's membership with a path-sized payload,
and state honestly what that payload still exposes.

## Architecture

- `Disclosure` — root, leaf count, index, sibling path. No events, no bundle.
- `make_disclosure(bundle, index)` — same path as `make_proof`, so the two cannot
  drift apart.
- `verify_disclosure(disclosure, *, subject, expected_root=None)` — recomputes the
  root from the subject and the path, then separates what was proven from what
  was merely asserted.

## Findings

- `leaf_count` and `index` do not enter the merkle computation, so they cannot be
  verified. The verdict reports them as `unverified` metadata.
- A sibling node that is itself a leaf is exposed by construction. Padding the
  tree to a power of two removes it; this slice records the exposure rather than
  hiding it.
- A disclosure carries its own root, so an unpinned verification is
  `verified-unpinned`, never `verified`.

## Tasks

- [x] Task 1: pin the expected root and refuse a contradiction.
- [x] Task 2: check the path length against the declared leaf count.
- [x] Task 3: reuse `make_proof` so disclosure and proof cannot diverge.
- [x] Task 4: report unverified metadata and unpinned roots.

## Boundaries

Not proven: that the root is honest, that the bounds are true, that non-path
leaves stay hidden. This is a disclosure format, not a privacy mechanism.
