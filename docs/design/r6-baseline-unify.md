# r6-baseline-unify: one baseline per commit sha, with the sha recorded

**Slice:** B173 r6-baseline-unify
**Date:** 2026-11-15
**Status:** implemented on `batch-173-moltbook-absorb`

## 1. Why this slice exists

The round-6 candidates file (R6-6) recorded the problem in one line: *the
baseline has three different versions and they are all stale*. The
coordinator's decision was that the baseline must **follow `main`**.

The measured shape of the problem in this batch: 38 files matching
`b173-*baseline*.txt` live outside the repository (in `/home/muse-newapi`),
and they are not interchangeable. Twelve of them are named
`*-baseline-failures.txt`, which reads as "the baseline", but they are
several different things at several different times:

* `b173-refusal-row-baseline-failures.txt` holds **27** `FAIL:`/`ERROR:`
  lines — **17 `FAIL:` and 10 `ERROR:`**. The round-6 candidates file says
  "17". That is not wrong so much as *ambiguous*: 17 is the failure count
  the suite's own verdict line reports (`FAILED (failures=17, errors=10)`),
  while the file holds 17 + 10 = **27** items. Both numbers are quoted
  around the batch as "the baseline", and they count different things.
  This document uses **27 items** and always says which it means.
* `b173-baseline-failures-2026-11-14.txt` holds **30** lines — the same
  kind of file, a different time point, and a *different set*.
* `b173-refusal-row-baseline-full.txt` holds the complete suite output
  (20509 tests). It contains the same 27 failure items *plus* the whole
  log, so it is not substitutable for a failure set, and vice versa.
* `b173-bench-baseline-failures.txt` and
  `b173-bench-baseline-failures-2026-11-14.txt` are byte-identical copies
  of the same 8 bench items.

Nothing in any of these files records the commit they were produced from.
`b173-baseline-failures-2026-11-14.txt` starts with an `ERROR:` line — there
is no header at all. So the sentence *"identical to the baseline"* had no
referent: it did not say *which* baseline, and the baseline files did not
say *which tree*.

## 2. The definition

> A baseline is the **failure set of the full runtime unittest suite at one
> named commit sha**. "Identical to the baseline" therefore means:
> *identical, item for item, to the failure set of commit `<sha>`.*

The sha is the whole content of the comparison. A baseline is therefore a
function of exactly one tree, and the tree is recoverable from the file
itself.

### 2.1 What the baseline is *not*

* It is **not** a frozen snapshot taken at the start of the batch. See §6.
* It is **not** the complete suite output. A full log (thousands of lines,
  including the progress dots) and a failure set (one line per failing
  item) are different artifacts and are not interchangeable.
* It is **not** the bench artifact. The governance bench has its own
  baseline, with the same defects and the same treatment (§5.2).

## 3. File naming and format

### 3.1 The baseline file

```
b173-baseline-<commit-sha>.failures.txt
```

One file per sha. The full 40-hex sha, never an abbreviation: an
abbreviation is ambiguous across a batch that contains 171 commits on one
branch.

Content:

```
# baseline of 2db42e939477bc2ceca9f20d35384dfc7731e972 -- northstar-agent-runtime full suite, sorted FAIL:/ERROR: items
ERROR: test_bwrap_cannot_persist_changes_to_workspace_governance (test_os_sandbox.OsSandboxBwrapBackendTests.test_bwrap_cannot_persist_changes_to_workspace_governance)
FAIL: test_the_check_passes_on_the_current_repository (test_runtime_registration.RealRepositoryCheckTests.test_the_check_passes_on_the_current_repository)
```

Rules, all of them testable (`tests/test_r6_baseline_unify.py`):

1. **Line 1 is the sha.** It starts with `# baseline of <sha>`. The file
   carries its own provenance: you never have to ask where it came from,
   and you cannot mistake it for a baseline of a different tree.
2. **The items are sorted.** Byte order (`LC_ALL=C`), so the file diffs
   cleanly and a diff is reproducible.
3. **The items are unique.** `sort -u`.
4. **The items are the raw suite lines.** Each is
   `FAIL: <name> (<module>.<Class>.<method>)` or
   `ERROR: <name> (<module>.<Class>.<method>)`, copied verbatim from the
   suite output. Nothing is reformatted, renamed, or truncated.
5. **No header that varies between runs.** No timestamp, no host name, no
   "ran by" line. This is what makes the generator idempotent: the same
   sha produces a byte-identical file.

### 3.2 The pointer file

```
b173-baseline-CURRENT
```

One line, holding the **file name** of the baseline that is currently in
force:

```
b173-baseline-2db42e939477bc2ceca9f20d35384dfc7731e972.failures.txt
```

It is a plain text file, **not a symlink**. A symlink breaks when the file
is copied into a bundle or an archive without dereferencing, and the
acceptance check would then resolve to nothing.

The pointer is the *only* thing a consumer needs to read to learn which
baseline applies.

### 3.3 Where these files live

Outside the repository, in `/home/muse-newapi`, next to the other
coordination artifacts (`b173-accept.sh`, the `b173-*.files` manifests, the
slice reports). They are coordination state, not source: they are
regenerated, not version-controlled. The slice's own source changes are
`scripts/b173-baseline-gen.sh`, `docs/design/r6-baseline-unify.md` and
`tests/test_r6_baseline_unify.py`.

## 4. The generator

`scripts/b173-baseline-gen.sh <commit-sha> [output-dir]`

```
usage: b173-baseline-gen.sh <commit-sha> [output-dir]
```

Behaviour:

1. Verifies `<commit-sha>` is a commit in this repository; normalises it
   to the full 40-hex sha.
2. Creates a **clean detached worktree** at that sha
   (`git worktree add --detach`). The baseline is always taken from a
   tree that is not a working copy, so uncommitted changes cannot leak
   into it.
3. Clears the `/tmp/nsar-*` scratch residue first. The runtime suite
   leaves roughly 86 000 `nsar-*` directories behind; on a full tmpfs this
   makes three unrelated cases report a spurious
   `Errno 122 Disk quota exceeded`. Clearing before the run is what keeps
   the baseline free of those artefacts.
4. Runs the full runtime suite in that worktree and extracts the
   `FAIL:`/`ERROR:` lines, sorted and de-duplicated.
5. Writes `b173-baseline-<sha>.failures.txt` with the sha on line 1.
6. Removes the worktree (`git worktree remove --force`, then
   `git worktree prune`) and its scratch directory, on every exit path.

Properties, all covered by tests:

* **Idempotent.** The same sha yields a byte-identical file.
* **Self-cleaning.** No worktree is left in `git worktree list`; no
  `/tmp/b173-baseline-gen.*` directory survives; the `nsar-*` residue is
  cleared.
* **Read-only with respect to the repository.** It writes nothing into the
  checkout, and it never touches `main` — it does not merge, push, or
  check out `main`; it only adds a detached worktree and removes it.
* **Portable.** It uses `/usr/bin/grep` explicitly. The interactive shell
  has a `grep` function backed by ugrep, which rejects some BREs; the
  numbers a script produces and the numbers a terminal produces come from
  different greps and are not directly comparable.

Environment overrides (used by the tests to run the generator against a
throwaway repository): `B173_BASELINE_GEN_REPO`, `B173_BASELINE_DIR`.

### 4.1 A note on the suite invocation

The generator runs the suite as a **module list**, not with
`unittest discover`:

```bash
MODS=$(cd "$RUNTIME_DIR" && ls tests/test_*.py | xargs -n1 basename | sed 's/\.py$//' | tr '\n' ' ')
( cd "$RUNTIME_DIR" && PYTHONPATH=.:tests python3 -m unittest $MODS )
```

`tests/` has no `__init__.py`, and Python 3.11+ refuses to discover into a
non-importable start directory (`ImportError: Start directory is not
importable`). This is the same invocation as the pre-existing
`scripts/b173-baseline-check.sh`, so the two agree on what the suite is.

## 5. Lifecycle: who re-takes the baseline, and when

### 5.1 The rule

> The baseline is re-taken **when `main` advances**, and it is re-taken
> **by the coordinator**.

Concretely:

| Event | Who | What |
|---|---|---|
| `main` advances (merge, or a new commit on `main`) | Coordinator | Re-run `scripts/b173-baseline-gen.sh <new-main-sha>`; write `b173-baseline-<sha>.failures.txt`; repoint `b173-baseline-CURRENT` at it. |
| A slice changes its own failure set | Slice author | Nothing. The slice's failure set is compared against the *current* baseline; a slice that legitimately fixes a pre-existing failure will show "fewer items than the baseline", which is a real finding to report, not a reason to re-take the baseline. |
| A slice lands on `main` | Coordinator | The baseline for the new `main` is the one produced above, i.e. the new `main` sha's own failure set. |

**This slice does not implement an automatic hook.** There is no CI job,
no pre-commit hook, no daemon that re-takes the baseline when `main` moves.
The rule is written down; the trigger is a human (the coordinator) running
one command. That is deliberate: an automatic re-take would silently change
the thing that acceptance is measured against, which is precisely the class
of problem this slice exists to remove.

### 5.2 The bench baseline

The governance bench has the same defect and gets the same treatment:

```
b173-bench-baseline-<commit-sha>.failures.txt
b173-bench-baseline-CURRENT
```

The bench baseline file holds the **bench item names** (the failing bench
cases, one per line, without the `✗` prefix), not the runtime failure
lines. The two existing bench baseline files,
`b173-bench-baseline-failures.txt` and
`b173-bench-baseline-failures-2026-11-14.txt`, are byte-identical
(verified: same md5) and hold the same 8 items — they are duplicate copies
of one baseline under two names, which is the same "same name, different
thing" problem in a milder form.

The acceptance patch (§7) reads the bench baseline through the same pointer
mechanism, and reports the bench baseline's sha in its verdict line.

## 6. "Follows main" versus "frozen at batch start"

The alternative was to freeze the baseline once, at the start of the batch,
and compare every slice against it. That was rejected, and the reason is
worth stating precisely, because it is not obvious.

### 6.1 A frozen baseline goes stale *silently*

A frozen baseline is a historical fact: "the failure set at commit X".
`main` is a moving target. The moment `main` advances, the comparison is
no longer measuring what it claims to measure — but nothing signals it.

The measured instance in this batch:

* The frozen-at-the-time baseline was **27 items**.
* The merged tree at the time of measurement was **30 items**.
* Item-by-item diff: **3 new, 0 fixed**.

The 3 new items were all `test_runtime_registration` — the `merged_tree_review.py`
module had not been registered in `pyproject.toml` and
`runtime_registration.py`. In other words: **the tree had a real defect**,
the baseline was stale, and the comparison "27 == 27" would have looked
clean while the defect was present. The drift was visible only because
somebody diffed item by item.

Worse, the drift goes in **both** directions, and "fewer" is just as much a
problem as "more":

* **More items than the baseline** — the tree gained failures. Detectable.
* **Fewer items than the baseline** — the tree *fixed* pre-existing
  failures. Also detectable, but easy to misread as "the check is broken"
  or to "fix" by re-taking the baseline, which would erase the evidence
  that a fix happened.

Both directions are silent without an item-by-item diff against a baseline
that is known to be current.

### 6.2 Following `main` makes the comparison a present-tense fact

If the baseline is "the failure set of current `main`", it is always a
**present-tense** fact, and "identical to the baseline" means "identical to
what `main` does right now". When `main` advances, the baseline is
re-taken, and the re-take is an explicit, recorded act — one command, one
new file with the sha in its name, one pointer update.

The cost of "follows main" is honest and worth stating: **the baseline
moves**, so a comparison against it is not reproducible after `main` has
moved. That is why each baseline is kept as its own file rather than
overwritten: the history of what `main` looked like stays addressable by
sha.

### 6.3 The rule this slice settles

> A baseline is never compared against "the baseline". It is compared
> against **the failure set of a named sha**, and the name of that sha is
> printed in the verdict.

## 7. What the acceptance check must say

The acceptance script `b173-accept.sh` is the judge; changing it is
changing the rules, so this slice does **not** modify it. It produces a
patch (`b173-r6-baseline-unify-fix.patch`) for the coordinator to apply.

The patch changes the two comparisons that today read a hard-coded file
name:

1. `BENCH_DIFF` reads the bench baseline through
   `b173-bench-baseline-CURRENT`.
2. The full-suite failure-set comparison reads the runtime baseline
   through `b173-baseline-CURRENT`.

and makes both verdict lines **name the baseline's sha**, e.g.

```
PASS BENCH_DIFF failing-item set identical to baseline 2db42e93 (8 items), 161/169
```

instead of the current

```
PASS BENCH_DIFF failing-item set identical to baseline (8 items), 161/169
```

which names the baseline by nothing at all.

Three rules the patch obeys:

* **A missing pointer is a SKIP, not a FAIL.** If `b173-baseline-CURRENT` does
  not exist, or names a file that does not exist, the check SKIPs: the
  absence of a baseline means "no comparison was possible", not "the slice
  failed".
* **The number of checks does not change.** The batch's rule is *do not
  change the denominator*; the patch adds no check and removes none.
* **The sha in the verdict comes from the baseline file, not from a
  guess.** It is read from line 1 of the baseline file, so the sha printed
  is the sha the baseline was actually taken at.

## 8. Census of the 38 baseline files

This is the first step of the slice and it is not optional: the
problem is invisible without it. Every file matching
`b173-*baseline*.txt` in `/home/muse-newapi` was measured on
2026-11-15.

The comparison columns are against the new main baseline,
`b173-baseline-2db42e939477bc2ceca9f20d35384dfc7731e972.failures.txt`
(33 items). "new vs main" = items in that file but not in the main
baseline; "fixed vs main" = items in the main baseline that the file
does **not** have.

| # | file | claimed source | lines | `FAIL:`/`ERROR:` items | suite size | kind | common with main | new vs main | fixed vs main |
|---|---|---|---|---|---|---|---|---|---|
| 1 | `b173-acceptance-conformance-baseline-accept.txt` | acceptance-conformance | 70 | 0 | - | other | - | - | - |
| 2 | `b173-ageofagents-baseline-bench.txt` | ageofagents | 219 | 0 | - | bench output | - | - | - |
| 3 | `b173-ageofagents-baseline-failures.txt` | ageofagents | 27 | 27 | - | failure set | 26 | 1 | 7 |
| 4 | `b173-ageofagents-baseline-runtime.txt` | ageofagents | 1239 | 27 | 19388 | full suite log | 26 | 1 | 7 |
| 5 | `b173-asinhhc-baseline-full.txt` | asinhhc | 40 | 0 | - | other | - | - | - |
| 6 | `b173-baseline-attribution-bench-final.txt` | baseline-attribution | 218 | 0 | - | bench output | - | - | - |
| 7 | `b173-baseline-attribution-cc-final.txt` | baseline-attribution | 524 | 0 | - | bench output | - | - | - |
| 8 | `b173-baseline-failures-2026-11-14.txt` | baseline-attribution / merged tree | 30 | 30 | - | failure set | 26 | 4 | 7 |
| 9 | `b173-baseline-failures-attributed-2026-11-14.txt` | baseline-attribution | 46 | 0 | - | other | - | - | - |
| 10 | `b173-bench-baseline-failures-2026-11-14.txt` | batch-wide (bench) | 8 | 0 | - | other | - | - | - |
| 11 | `b173-bench-baseline-failures.txt` | batch-wide (bench) | 8 | 0 | - | other | - | - | - |
| 12 | `b173-c54-baseline-runtime.txt` | c54 | 60 | 0 | - | other | - | - | - |
| 13 | `b173-c54-bench-baseline.txt` | c54 | 218 | 0 | - | bench output | - | - | - |
| 14 | `b173-c54-suite-baseline.txt` | c54 | 1210 | 26 | 18861 | full suite log | 26 | 0 | 7 |
| 15 | `b173-ec-baseline-failures.txt` | ec | 27 | 27 | - | failure set | 26 | 1 | 7 |
| 16 | `b173-ec-baseline-runtime.txt` | ec | 40 | 0 | - | other | - | - | - |
| 17 | `b173-horizon-gate-baseline-failures.txt` | horizon-gate | 27 | 0 | - | other | - | - | - |
| 18 | `b173-horizon-gate-bench-baseline.txt` | horizon-gate | 40 | 0 | - | other | - | - | - |
| 19 | `b173-langgraph-durability-baseline.txt` | langgraph-durability | 1244 | 28 | 20249 | full suite log | 26 | 2 | 7 |
| 20 | `b173-openhands-stuck-detector-baseline-runtime.txt` | openhands-stuck-detector | 1235 | 27 | 20358 | full suite log | 26 | 1 | 7 |
| 21 | `b173-outsideloop-baseline-runtime.txt` | outsideloop | 40 | 0 | - | other | - | - | - |
| 22 | `b173-outsideloop-bench-baseline.txt` | outsideloop | 25 | 0 | - | other | - | - | - |
| 23 | `b173-refusal-hold-baseline-full.txt` | refusal-hold | 1236 | 27 | 20833 | full suite log | 26 | 1 | 7 |
| 24 | `b173-refusal-row-baseline-failures.txt` | refusal-row | 27 | 27 | - | failure set | 26 | 1 | 7 |
| 25 | `b173-refusal-row-baseline-full.txt` | refusal-row | 1235 | 27 | 20509 | full suite log | 26 | 1 | 7 |
| 26 | `b173-refusal-row-bench-baseline-failures.txt` | refusal-row | 8 | 0 | - | other | - | - | - |
| 27 | `b173-refusal-row-bench-baseline.txt` | refusal-row | 30 | 0 | - | other | - | - | - |
| 28 | `b173-session-memory-baseline-failures.txt` | session-memory | 27 | 27 | - | failure set (other item format) | 0 | n/a | n/a |
| 29 | `b173-session-memory-baseline.txt` | session-memory | 80 | 0 | - | other | - | - | - |
| 30 | `b173-step-reliability-budget-baseline-full.txt` | step-reliability-budget | 1235 | 27 | 20438 | full suite log | 26 | 1 | 7 |
| 31 | `b173-step-reliability-budget-baseline.txt` | step-reliability-budget | 40 | 0 | - | other | - | - | - |
| 32 | `b173-step-reliability-budget-bench-baseline.txt` | step-reliability-budget | 218 | 0 | - | bench output | - | - | - |
| 33 | `b173-swe-failure-modes-baseline.txt` | swe-failure-modes | 1248 | 27 | 19601 | full suite log | 26 | 1 | 7 |
| 34 | `b173-tof-baseline-failures.txt` | tof | 27 | 27 | - | failure set | 26 | 1 | 7 |
| 35 | `b173-tof-baseline-runtime-full.txt` | tof | 1245 | 27 | 19515 | full suite log | 26 | 1 | 7 |
| 36 | `b173-tof-baseline-runtime.txt` | tof | 40 | 0 | - | other | - | - | - |
| 37 | `b173-tof-bench-baseline.txt` | tof | 216 | 0 | - | bench output | - | - | - |
| 38 | `b173-tombstone-mutant-blindspots-baseline-failures.txt` | tombstone-mutant-blindspots | 27 | 27 | - | failure set | 26 | 1 | 7 |

TOTAL FILES CENSUSED: 38

### 8.1 What the census shows

**The 38 files are not 38 baselines. They are 5 kinds of thing.**

| kind | count | what it is |
|---|---|---|
| failure set (runtime) | 7 | one `FAIL:`/`ERROR:` line per failing item |
| full suite log (runtime) | 8 | the complete unittest output; contains the failure items *plus* the whole log |
| bench output | 6 | the governance bench scorecard |
| bench failure set | 3 | the 8 failing bench items, one per line |
| other (interop / cli / report output) | 14 | not baselines at all — interop probe output, a slice report, a doc |

Only the first kind is a runtime baseline. The second kind is *not*
interchangeable with it: `b173-refusal-row-baseline-full.txt` is 1235 lines
of which 27 are failure items. Comparing a failure set against a full log
yields a diff of 1208 lines, all of it noise.

**Duplicate groups.** Three groups of files are byte-identical (same md5):

| md5 prefix | files | what it means |
|---|---|---|
| `f5a841e6…` | `b173-ageofagents-baseline-failures.txt`, `b173-ec-baseline-failures.txt`, `b173-refusal-row-baseline-failures.txt`, `b173-tof-baseline-failures.txt`, `b173-tombstone-mutant-blindspots-baseline-failures.txt` | **five names, one baseline.** Five slices each wrote their own copy of the same 27-item set. They are not five independent measurements; they are one measurement copied five times. This is why "17" appears in the round-6 candidates file: the number was never re-measured, it was copied. |
| `60fa19a6…` | `b173-bench-baseline-failures.txt`, `b173-bench-baseline-failures-2026-11-14.txt` | the two bench baselines are the same file under two names. |
| `5cb45ac4…` | `b173-asinhhc-baseline-full.txt`, `b173-ec-baseline-runtime.txt`, `b173-outsideloop-baseline-runtime.txt`, `b173-step-reliability-budget-baseline.txt`, `b173-tof-baseline-runtime.txt` | five copies of the same 40-line interop probe output. |

**The "27 vs 30" difference is exactly the packaging defect.**
`b173-baseline-failures-2026-11-14.txt` (30 items) is the 27-item set plus
three `test_runtime_registration` failures — `test_the_registry_covers_every_module_on_disk`,
`test_the_check_passes_on_the_current_repository`,
`test_the_check_agrees_with_the_layout_test` — minus one item
(`test_every_module_is_installed`, from `test_module_layout`), plus the
`test_integration_sidecar` items. The three `runtime_registration` failures
are the `merged_tree_review.py` module missing from `pyproject.toml` and
`runtime_registration.py`: **the merged tree had a real defect, and a stale
baseline hid it.**

**The measured count is 27 items, of which 17 are `FAIL:` and 10 are
`ERROR:`.** `b173-refusal-row-baseline-failures.txt` contains 27 lines
matching `^(FAIL|ERROR): ` — verified by counting them — and they split
17 / 10. The round-6 candidates file says "17", and so do several slice
reports ("failures=17, errors=10"). The 17 is the **failures-only**
count; the file is a **failure set of 27 items**. Quoting either number
without saying which is what it counts is how a "baseline" ended up with
several versions; the rule in §8.3 requires the item count and the split
to both be stated.

**One file is not even in the shared item format.**
`b173-session-memory-baseline-failures.txt` holds 27 items, but its lines
carry **no module suffix**:

```
ERROR: test_bwrap_cannot_persist_changes_to_workspace_governance
```

whereas the suite emits

```
ERROR: test_bwrap_cannot_persist_changes_to_workspace_governance (test_os_sandbox.OsSandboxBwrapBackendTests.test_bwrap_cannot_persist_changes_to_workspace_governance)
```

This file has **0 items in common** with the main baseline (not 27 — 0),
because the strings differ. An item-by-item comparison against this file
would report 27 new and 33 fixed, and every one of those 60 "differences"
would be a formatting artefact. A file like this cannot be a baseline at
all, and its presence is the clearest single argument for a fixed format.

**The `test_integration_sidecar` items are order-dependent, not tree defects.**
The main baseline contains 5 `test_integration_sidecar` failures. Running
that module alone at main's sha passes (18 tests, OK). Those 5 items are
therefore a consequence of running the whole suite in one process — the
sidecar tests are sensitive to the state left by earlier modules. A
baseline is a property of *how* the suite was run as much as of *which*
tree it was run on, which is why §3.1 pins the invocation (module list,
`PYTHONPATH=.:tests`) and why a baseline file must name the sha it came
from.

### 8.2 Attribution table (summary)

| file | belongs to | verdict |
|---|---|---|
| `b173-baseline-2db42e93….failures.txt` | **main @ `2db42e93`** | **the baseline.** Keep. |
| `b173-baseline-CURRENT` | **main @ `2db42e93`** | **the pointer.** Keep. |
| `b173-baseline-failures-2026-11-14.txt` (30) | merged tree, 2026-11-14 | superseded; a *slice-tree* baseline that drifted from main. Delete or archive. |
| `b173-baseline-failures-attributed-2026-11-14.txt` | baseline-attribution slice | an *attribution* of the 30, not a baseline. |
| `b173-baseline-attribution-cc-final.txt`, `-bench-final.txt` | baseline-attribution slice | reports, not baselines. |
| the 5 md5-identical `*-baseline-failures.txt` | ageofagents / ec / refusal-row / tof / tombstone-mutant-blindspots | one 27-item set, copied five times. All but one superseded. |
| the 5 md5-identical 40-line `*-baseline-runtime.txt` | asinhhc / ec / outsideloop / step-reliability-budget / tof | interop probe output, not runtime baselines at all. Misnamed. |
| the 8 `*-baseline-full.txt` / `-runtime.txt` with a `Ran N tests` line | various slices | full suite logs; keep as evidence, never as a comparison baseline. |
| `b173-c54-suite-baseline.txt` (26 items) | c54 slice | an older, *smaller* set (26). |
| `b173-langgraph-durability-baseline.txt` (28 items) | langgraph-durability slice | 28 items: the 27 plus `test_shell_handler_timeout_is_is_error`. |
| `b173-session-memory-baseline-failures.txt` (27 items) | session-memory slice | **wrong item format** (no module suffix). Not usable as a baseline. |
| `b173-bench-baseline-failures.txt`, `b173-bench-baseline-failures-2026-11-14.txt` | batch-wide (bench) | two names, one 8-item bench baseline. Should become `b173-bench-baseline-<sha>.failures.txt` + `b173-bench-baseline-CURRENT`. |
| `b173-refusal-row-bench-baseline-failures.txt` (8) | refusal-row slice | a copy of the bench failure set under a slice name. |
| `b173-*-bench-baseline.txt` (6 files) | c54 / ageofagents / step-reliability-budget / tof / outsideloop / horizon-gate | bench *outputs* (the whole scorecard), not bench failure sets. |
| `b173-acceptance-conformance-baseline-accept.txt` | acceptance-conformance slice | an accept-log excerpt. |

### 8.3 The rule this census produces

> A file is a baseline only if it is a **failure set** in the **fixed item
> format** and it **names the sha** it was taken at.

Under that rule, exactly one of the 39 files (38 legacy + the new one)
qualifies today: `b173-baseline-2db42e939477bc2ceca9f20d35384dfc7731e972.failures.txt`.

## 9. What the measurement exposed: the suite is not deterministic

This section is the most important part of the document, because it changes
what a baseline can honestly claim to be.

### 9.1 The measurement

The generator was run **three times against the same sha**
(`2db42e939477bc2ceca9f20d35384dfc7731e972`, `main`'s HEAD), each in a
fresh detached worktree, each with the same command:

```bash
PYTHONPATH=.:tests python3 -m unittest <all test modules>
```

| run | items | `FAIL:` | `ERROR:` | verdict line |
|---|---|---|---|---|
| 1 | **33** | 22 | 11 | `FAILED (failures=22, errors=11, skipped=13)` |
| 2 | **26** | 16 | 10 | `FAILED (failures=16, errors=10, skipped=13)` |
| 3 | **27** | 17 | 10 | `FAILED (failures=17, errors=10, skipped=13)` |

The test count is identical every time (`Ran 18703 tests`), so the same
tests ran. The **failure set is not a function of the tree**.

The intersection of all three runs is **26 items**; the union is **34**.
Exactly **8 items are flaky**:

```
ERROR: test_the_sidecar_environment_holds_no_model_credentials (test_integration_sidecar.SidecarIntegrationTest...)
FAIL:  test_a_silent_peer_cannot_hang_the_run_forever (test_integration_sidecar.SidecarIntegrationTest...)
FAIL:  test_a_write_in_the_same_plan_run_is_still_refused (test_integration_sidecar.SidecarIntegrationTest...)
FAIL:  test_the_runtime_never_spawns_codex_itself (test_integration_sidecar.SidecarIntegrationTest...)
FAIL:  test_the_sidecar_listens_on_a_private_unix_socket (test_integration_sidecar.SidecarIntegrationTest...)
FAIL:  test_the_sidecar_only_ever_runs_codex_read_only_and_ephemeral (test_integration_sidecar.SidecarIntegrationTest...)
FAIL:  test_two_parallel_delegations_are_both_served (test_integration_sidecar.SidecarIntegrationTest...)
FAIL:  test_one_mutation_end_to_end_turns_its_test_red (test_tools_verify_invariants.PrepareCopiesTheWholeComponentsTree...)
```

Seven are `test_integration_sidecar` and one is `test_tools_verify_invariants`.

### 9.2 Why they are flaky

`test_integration_sidecar` starts a **background daemon thread** that
serves a Unix socket and waits on a wall-clock deadline
(`deadline = time.monotonic() + 15`, `while not cls.socket_path.exists()
and time.monotonic() < deadline`). Under the full-suite load (18 703 tests,
≈130 s) the socket does not always bind inside the deadline, and the
class-level `setUpClass` raises — which turns **every** test in the class
into an error. Run alone it binds in time every time (18 tests, OK, three
times in a row).

`test_tools_verify_invariants` copies the whole component tree into
`/tmp`; it is the case the batch already knows about — a full tmpfs makes
it report `Errno 122 Disk quota exceeded`. `/tmp` on this machine is a
12 GB tmpfs that was at 76 % during these runs.

Both are **environmental**, not tree defects. Neither is a property of the
commit.

### 9.3 What this means for the baseline

> The failure set of a suite run is a function of **(tree, machine state,
> timing)** — not of the tree alone.

So a baseline taken at sha *S* is a claim about a *run*, not about the
tree *S*. Three consequences, all of which this slice must handle rather
than paper over:

1. **The generator cannot be byte-idempotent on a real tree.** Two runs at
   the same sha differ (33 vs 26 items). The generator's output is
   idempotent *given the same suite result* — which is all any generator
   can promise — and the test suite asserts exactly that, on a
   deterministic fake repository. On the real tree, idempotency is
   defeated by the flakiness, not by the script.
2. **A comparison against a baseline must tolerate a flaky band.** The
   honest form of "identical to the baseline" is: *identical except for
   items known to be flaky at this tree*. The 8 items above are exactly
   that band, and they should be recorded, not silently dropped.
3. **A stale baseline and a flaky baseline are indistinguishable by
   diff alone.** This is the strongest argument for the sha-named file:
   the sha says *what tree* the comparison is against, and the raw suite
   log (now saved alongside the baseline by the generator) says *what
   happened when it was taken*.

### 9.4 The rules this produces

* The generator saves the raw suite log next to the baseline
  (`b173-baseline-<sha>.suite.log`). A surprising item must be
  explainable from the log, not guessed at.
* The baseline file's first line records the sha; a baseline is always
  *some* run's failure set, never claimed to be the canonical one.
* A flaky item is identified by **re-running**: the 8 items above are
  exactly the items that appeared in some but not all runs.
* The baseline in force should be re-taken when `main` advances
  (§5.1) **and** the flaky band should be re-measured then, because the
  band is machine- and load-dependent too.

### 9.5 A caveat on the numbers in §8

The census table in §8 compares each legacy baseline file against the
**run-1** main baseline (33 items). For the files that are themselves
single runs of a flaky suite, the "new vs main" and "fixed vs main"
columns therefore include flaky noise. The columns are still the honest
measurement of *those two files against that one run*; they are not a
claim about tree defects. The stable 26-item core is the part of the
comparison that is meaningful across runs.

### 9.6 Open item for the coordinator

The `test_integration_sidecar` flakiness is a **defect in the test**, not
in the runtime: a class-level `setUpClass` that can time out turns the
whole class red. It is outside this slice's scope (this slice writes no
runtime module and touches no existing test). It is reported here so that
the coordinator can decide whether to:

* fix the sidecar test (give `setUpClass` a longer deadline, or make the
  socket wait not fail the class), and
* decide whether the acceptance check should compare the **stable core**
  rather than the raw failure set.
