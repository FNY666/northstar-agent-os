---
name: northstar-verify
description: Independently verify a Northstar batch before it is pushed: fresh clone or worktree, re-run tests and bench, review the diff commit by commit, check the bundle. Use when asked to verify, review, or check a batch, bundle, or branch.
---

# Northstar batch verification

Verify work you did not produce (or work from a previous session) before it
goes to `main`. Never verify in the working tree that produced the work.

## Steps

1. **Fresh ground.** Clone fresh or `git worktree add` a clean directory at
   the reported branch. Fetch the bundle if one was delivered:
   `git bundle verify <file>.bundle`, `git bundle list-heads`, then fetch
   from it and check out the branch. Confirm HEAD matches the reported SHA.
2. **Re-run the tests yourself.** Run the same suite the batch claims
   (`make test`, component suite, interop suite). Record pass/fail counts
   exactly — do not trust the batch's numbers, reproduce them.
3. **Re-run the bench / score** where the batch claims one. Confirm the
   score (e.g. interop 6/6) yourself.
4. **Review the diff commit by commit.** `git log --oneline main..HEAD`,
   `git diff main...HEAD --stat`, then read each commit's diff. Check:
   - No version string changes, no tags, no Release artifacts.
   - No unrelated files swept in; no leftover debug/probe scripts.
   - Executable files keep their mode (`git ls-tree <commit> -- <path>`).
   - Tests actually cover the change (not just renamed or skipped).
5. **Confirm the bundle.** `git bundle verify` clean, heads match, and the
   branch fast-forwards cleanly from `main` (no merge conflicts, no
   divergent history).
6. **Report.** Commits verified (SHAs), test/bench numbers reproduced,
   diff findings (if any), and a clear go / no-go for pushing. If anything
   fails, say exactly what and where — don't paper over gaps.

## Rules

- Read code, not just docs or the batch's own summary.
- If a failure predates the batch, prove it on `main` before blaming the
  batch.
- Never push, never fix the batch's code yourself during verification —
  report findings and let the batch (or the parent) fix them.
