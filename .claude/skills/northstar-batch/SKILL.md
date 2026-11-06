---
name: northstar-batch
description: Run a Northstar AgentOS development batch on 140: branch from main, baseline tests and bench, implement the brief, re-run tests and bench, deliver a git bundle. Use when asked to do a numbered batch (batch-NNN), implement a feature or fix in Northstar, or continue batch work.
---

# Northstar batch workflow

You are working in the Northstar AgentOS repo on 140. The repo is at
`~/northstar-agent-os`. You are on a batch branch (`batch-<n>-<topic>`,
branched from `main`). The parent (VM side) reviews and pushes; you never
push `main`.

## Iron rules (also in CLAUDE.md — they outrank the brief)

- No version changes, no tags, no Releases, no publishing.
- Never `git push origin main`, never force-push, never delete branches.
- Baseline first, re-verify after. No batch is done without a re-check.
- Code first, not docs. Prove the existing end-to-end path before adding
  modules. Don't stack new modules.
- Token efficiency: search the web / read the code before guessing.

## Steps

1. **Confirm the starting point.** `git branch --show-current` (must be the
   batch branch), `git log --oneline -3`, `git status --short`. If the tree
   is dirty with someone else's work, stop and report.
2. **Baseline.** Run the test suite the brief names (default `make test`)
   and, where the brief says so, `make bench`. Record pass/fail counts and
   the score. Do not skip this.
3. **Implement.** Smallest diff that does the job. One logical change per
   commit, message style `<area>: <what>` (e.g. `fix: ...`, `test: ...`,
   `docs: ...`). Do not commit unrelated files. Do not touch files outside
   the brief's scope.
4. **Re-verify.** Re-run the same tests + bench. Record before/after
   numbers. If a live-leg bench failure appears, diagnose the root cause
   (check the run evidence, reproduce it) and write it up — do not just
   re-run hoping it passes.
5. **Deliver a bundle.** `git bundle create <branch>.bundle <branch>`
   (full history, not a snapshot). Verify it with
   `git bundle verify <branch>.bundle` and `git bundle list-heads`.
   Report: commit list (SHAs + messages), files changed (+/- lines),
   test/bench results before and after, open items. Hand the bundle path to
   the parent. Do not push anything yourself.

## If you get stuck

- A single component failing repeatedly: stop that item, report it, keep
  the rest of the batch moving. Do not burn tokens retrying the same
  failing step.
- A genuine fork (two viable approaches, user must decide): stop, present
  both options with evidence, and wait. Do not guess.
- If a test failure predates your change, prove it (run it on `main` in a
  clean worktree) and say so — don't silently fix unrelated failures.
