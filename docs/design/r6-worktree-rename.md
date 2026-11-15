# R6 — Worktree rename visibility, and NEW_TESTS counting method names

**Slice:** `r6-worktree-rename` — an **integration-and-verification** slice.
**Date:** 2026-11-15.
**Branch:** `batch-173-moltbook-absorb`.

---

## 0. What this slice is, and what it is not

This slice **does not write the patch**. The patch already exists: the
round-6 candidate `r6-check-accuracy` produced
`/home/muse-newapi/b173-r6-check-accuracy-fix.patch`, and that patch
already contains the complete fix for **R6-3** (the rename blind spot) and
**R6-7** (the line-vs-name counting defect).

What this slice does is **install three existing patches onto a COPY of the
live referee**, run the whole batch through both the old and the new
referee, attribute every difference to a specific cause, and hand the
coordinator a reproducible integration report.

> **The live `/home/muse-newapi/b173-accept.sh` was NOT edited by this
> slice.** The coordinator applies the patches. The exact commands are in
> §7.

Two other round-6 patches are integrated in the same copy, because they
are part of the same round and their effects on the batch's verdicts have
to be measured together:

| patch | round-6 item | what it changes |
|---|---|---|
| `b173-r6-manifest-integrity-fix.patch` | R6-1b / R6-4 + R6-2 | `COMMIT` becomes an attribution gate; `HOME_DIR` becomes overridable |
| `b173-r6-check-accuracy-fix.patch` | **R6-3 + R6-7** | `WORKTREE_CLEAN` sees both paths of a rename; `NEW_TESTS` counts distinct method names |
| `b173-r6-12-session-resolution-fix.patch` | R6-12 | `REPORT_NUMBERS` resolves the session deterministically, `SKIP`s when ambiguous |

> **DO NOT apply `b173-r6-12-watch-session-resolution-fix.patch` to
> `b173-accept.sh`.** It targets `b173-watch.sh` and was measured to
> conflict there. See §7.

---

## 1. The rename defect (R6-3), reproduced

`b173-accept.sh` extracted the dirty paths like this (line 94 of the live
script, verbatim):

```bash
DIRTY=$(git -C "$REPO" status --porcelain 2>/dev/null | awk '{print $2}' | sort -u)
OVERLAP=$(comm -12 <(echo "$CFILES") <(echo "$DIRTY") | tr '\n' ' ')
```

Git's porcelain format puts a rename on **one line holding both paths**.
`awk '{print $2}'` returns the **second whitespace-separated field**, i.e.
the **OLD** path only.

### 1.1 The reproduction (throwaway repo, never the real one)

```
$ W=$(mktemp -d); cd "$W"; git init -q; git config user.email a@b; git config user.name t
$ echo x > old.py; git add old.py; git commit -qm init
$ git mv old.py new.py

$ git status --porcelain
R  old.py -> new.py

$ git status --porcelain | awk '{print $2}'
old.py                 <- the OLD path

$ ls
new.py                 <- the name the file ACTUALLY has on disk
```

`CFILES` holds the names the slice **committed**; the dirty set holds the
name on disk **now**. `awk '{print $2}'` yields the old name, the old name
was never committed by anybody, so `comm -12` is empty and
`WORKTREE_CLEAN` reports **PASS** — a dirty rename is completely invisible.

### 1.2 The patched extraction

```bash
DIRTY=$(git -C "$REPO" status --porcelain 2>/dev/null \
  | sed -E 's/^.. //' \
  | awk '{n = index($0, " -> "); if (n > 0) {print substr($0, 1, n - 1); print substr($0, n + 4)} else {print $0}}' \
  | sort -u)
```

Both paths of a rename are emitted: the old name (what the slice
committed) and the new name (what is on disk now).

### 1.3 The four porcelain status codes

Measured in the same throwaway repo, with **all four codes present at
once**:

```
$ git status --porcelain
A  added.py
 M mod.py
R  old.py -> renamed.py
?? untracked.py
```

| code | meaning | patched extraction |
|---|---|---|
| `M` | modified (worktree) | `mod.py` |
| `??` | untracked | `untracked.py` |
| `A` | added (staged) | `added.py` |
| `R` | renamed | `old.py` **and** `renamed.py` |

```
$ git status --porcelain | sed -E 's/^.. //' \
    | awk '{n = index($0, " -> "); if (n > 0) {print substr($0, 1, n - 1); print substr($0, n + 4)} else {print $0}}' \
    | sort -u
added.py
mod.py
old.py
renamed.py
untracked.py
```

The same four lines under the **old** extraction:

```
$ git status --porcelain | awk '{print $2}' | sort -u
added.py
mod.py
old.py
untracked.py          <- renamed.py is MISSING
```

### 1.4 A second, sharper blind spot (recorded, not fixed here)

`git show --name-only --format= <rename-commit>` prints only the **new**
path. The patched extraction therefore emits the **old** path of a
rename, but the *committed* file list does not contain it. A slice that
`git mv`s a file it owns leaves the old name in the dirty set, and the old
name is not in `CFILES` — so the overlap still misses.

The only way to see the old name in `CFILES` is `git show --name-only
--format= --no-renames`. The `r6-check-accuracy` patch does **not** change
that, so this blind spot **remains open after the patch**. It is a
separate, smaller defect; it is listed in the report's OPEN section.

---

## 2. The counting defect (R6-7)

The old expression counted matching diff **lines**:

```bash
NTEST=$((NTEST + $(git -C "$REPO" show "$h" 2>/dev/null | grep -c '^\+.*def test_' || true)))
```

Three ways it over-counts or mis-counts:

1. **One method, several added lines.** A method whose body mentions
   `def test_` in a string literal is counted again.
2. **One method, two commits.** A method re-added by a later commit of the
   same slice is counted twice.
3. **Prose.** A `def test_` mention inside a **markdown** document is
   counted as a test method. This is the `orphan-adoption` case (§4).

The patched expression counts **distinct method names**, unioned across
the slice's commits:

```bash
NTEST_NAMES="$NTEST_NAMES
$(git -C "$REPO" show "$h" 2>/dev/null \
  | grep -oE '^[+][[:space:]]*(async[[:space:]]+)?def[[:space:]]+test_[A-Za-z0-9_]*' \
  | sed -E 's/^[+][[:space:]]*(async[[:space:]]+)?def[[:space:]]+//' || true)"
...
NTEST=$(printf '%s\n' "$NTEST_NAMES" | grep -v '^[[:space:]]*$' | sort -u | grep -c . || true)
```

Note the pattern also drops the old `\+` GNU-only BRE escape in favour of
a `[+]` bracket expression, so GNU grep and ugrep agree on it.

### 2.1 The threshold stays at 1

The patched code still says `[ "$NTEST" -ge 1 ]`. The taskbook promises
"≥ 9 new test methods" while the referee checks ≥ 1; raising the threshold
to 9 is the **coordinator's separate decision** (§8), and it must not
happen in this round.

---

## 3. The integration: three patches, one copy, one batch run

### 3.1 The exact `patch` output

```
$ mkdir -p /tmp/b173-r6-worktree-rename
$ cp -p /home/muse-newapi/b173-accept.sh /tmp/b173-r6-worktree-rename/accept.sh
$ cd /tmp/b173-r6-worktree-rename

$ patch -p0 accept.sh < /home/muse-newapi/b173-r6-manifest-integrity-fix.patch
patching file accept.sh

$ patch -p0 accept.sh < /home/muse-newapi/b173-r6-check-accuracy-fix.patch
patching file accept.sh
Hunk #1 succeeded at 151 (offset 71 lines).

$ patch -p0 accept.sh < /home/muse-newapi/b173-r6-12-session-resolution-fix.patch
patching file accept.sh
Hunk #1 succeeded at 262 (offset 99 lines).
Hunk #2 succeeded at 288 (offset 99 lines).

$ bash -n accept.sh
$ echo $?
0
```

All three apply cleanly, in that order, with **no** `FAILED` and **no**
`Reversed` hunk. No patch was edited to make it fit.

### 3.2 The batch

Every slice with a `b173-<slug>.files` manifest was run through **both**
referees — the live one and the integrated copy — once. The raw outputs
are kept per slice under `/tmp/b173-r6-worktree-rename/raw/<slug>.{old,new}`.

**Manifest population on 2026-11-15: 83 slices** (`ls /home/muse-newapi/
b173-*.files | wc -l` → 83; every one of them contains at least one `/`,
so every one of them is a real path manifest).

The taskbook's background says "72 on 2026-11-15". The **PASS** count
matches the background exactly (52 → 53 on the taskbook's population). The
**FAIL** count does not, because the population is larger than the
background's, not because the referee behaves differently:

| population | OLD PASS | OLD FAIL | NEW PASS | NEW FAIL |
|---|---|---|---|---|
| all 83 manifests (measured here) | **52** | **31** | **54** | **29** |
| the 74 slices that have BOTH a taskbook and a report | **52** | **22** | **54** | **20** |

The 9-slug difference between the two populations is slices with a
manifest but no taskbook and/or no report — `slice1`–`slice6`,
`runtime-registration`, and the two not-yet-committed slices
`r6-test-count` and `r6-worktree-rename`. The PASS count is identical in
both populations because those 9 are all FAIL either way.

**Net change: +2 PASS / −2 FAIL** over all 83; the four changed slices are
attributed one by one in §5. The background's "net +1 PASS" was measured
over a smaller population on a different day; the direction is the same
(**more slices pass, and no slice regresses for a technical reason**) but
the arithmetic differs because the population differs.

### 3.3 The full two-column verdict table

`OLD` = live `b173-accept.sh`, `NEW` = integrated copy.

| `acceptance-conformance` | FAIL | FAIL |
| `actionable-digest` | PASS | PASS |
| `agent-handoff` | PASS | PASS |
| `ageofagents` | PASS | PASS |
| `anthropic-effort-scaling` | PASS | PASS |
| `artifact-completion` | FAIL | PASS |
| `asinhhc` | PASS | PASS |
| `audit-head` | FAIL | FAIL |
| `autogen-speaker-selector` | PASS | PASS |
| `baseline-attribution` | PASS | PASS |
| `c52` | FAIL | FAIL |
| `c54` | FAIL | FAIL |
| `c58` | FAIL | FAIL |
| `capability-ceiling-probe` | PASS | FAIL |
| `cost-per-delivery` | PASS | PASS |
| `cwl-episode-eviction` | PASS | PASS |
| `deterministic-gate-score` | FAIL | FAIL |
| `diviner` | FAIL | FAIL |
| `dynamiq` | PASS | PASS |
| `e2b` | FAIL | FAIL |
| `effect-directive` | PASS | PASS |
| `event-condenser` | PASS | PASS |
| `evidence-independence` | PASS | PASS |
| `fable` | FAIL | FAIL |
| `false-green-detector` | PASS | PASS |
| `fieldnotes` | PASS | PASS |
| `horizon` | PASS | PASS |
| `horizon-gate` | PASS | PASS |
| `intent-bound-retry` | PASS | PASS |
| `jido-statebudget` | PASS | PASS |
| `judge-hygiene` | PASS | PASS |
| `langgraph` | PASS | PASS |
| `langgraph-durability` | PASS | PASS |
| `langgraph-retry-clears-writes` | PASS | PASS |
| `leased-task-claim` | PASS | PASS |
| `lightningzero` | PASS | PASS |
| `merged-tree-review` | FAIL | FAIL |
| `msaf-lineage` | FAIL | FAIL |
| `mutant-evidence-closure` | FAIL | FAIL |
| `neo-konsi-s2bw` | PASS | PASS |
| `openhands-stuck-detector` | PASS | PASS |
| `orphan-adoption` | FAIL | FAIL |
| `outsideloop` | PASS | PASS |
| `r6-12-session-resolution` | FAIL | PASS |
| `r6-baseline-unify` | FAIL | FAIL |
| `r6-check-accuracy` | PASS | PASS |
| `r6-manifest-integrity` | PASS | PASS |
| `r6-manifest-subject` | PASS | PASS |
| `r6-test-count` | FAIL | FAIL |
| `r6-worktree-rename` | FAIL | FAIL |
| `refusal-hold` | PASS | PASS |
| `refusal-hold-wiring` | FAIL | FAIL |
| `refusal-row` | PASS | PASS |
| `resume-validation` | PASS | PASS |
| `reversible-compaction` | PASS | PASS |
| `revision-checked-tool-results` | PASS | PASS |
| `runtime-registration` | FAIL | FAIL |
| `runtime-registration-closure` | FAIL | FAIL |
| `scope-verbatim-compaction` | PASS | PASS |
| `scorer-disagreement` | PASS | PASS |
| `seal-slice6` | FAIL | FAIL |
| `session-memory` | PASS | PASS |
| `silent-failure-detector` | PASS | PASS |
| `slice1` | FAIL | FAIL |
| `slice2` | FAIL | FAIL |
| `slice3` | FAIL | FAIL |
| `slice4` | FAIL | FAIL |
| `slice5` | FAIL | FAIL |
| `slice6` | FAIL | FAIL |
| `stale-checkpoint-gate` | PASS | PASS |
| `step-reliability-budget` | PASS | PASS |
| `strands` | PASS | PASS |
| `swe-failure-modes` | PASS | PASS |
| `tombstone` | FAIL | PASS |
| `tombstone-mutant-blindspots` | PASS | PASS |
| `tool-output-filter` | PASS | PASS |
| `toolfail` | PASS | PASS |
| `turn-truncation` | PASS | PASS |
| `unwind` | FAIL | FAIL |
| `verifiability-tier` | PASS | PASS |
| `vina` | PASS | PASS |
| `vina-mutant-blindspots` | PASS | PASS |
| `vina-receipt-signing` | FAIL | FAIL |


---

## 4. `orphan-adoption`: the slice that adds no test code at all

This is the case that proves the new counter is right.

The slice's commit is `1c947e7b`:

```
$ git show --name-only --format= 1c947e7b
docs/design/annotation-pin.md
docs/design/orphan-adoption.md
```

**Two markdown documents. No code. No tests.**

The old counter found exactly one line in the whole diff matching
`^\+.*def test_`, and it is **prose inside a markdown table**:

```
$ git show 1c947e7b | grep -c '^\+.*def test_'
1

$ git show 1c947e7b | grep -n '^\+.*def test_'
122:+| 1 | `tests/test_revision_checked_tool_results.py` | 6 new test methods (`test_result_as_dict_carries_the_schema_pin`, `test_with_result_revision_returns_a_copy_and_leaves_the_original`, `test_with_result_revision_validates_its_argument`, `test_evidence_entries_lists_retained_results_in_order`, `test_outcome_record_names_both_revisions_and_the_verdict`, `test_ledger_records_every_outcome_in_order`) | **keep** | Each method asserts behaviour that HEAD does not have: `git show HEAD:...\|grep -c 'def test_'` returns 0 for all six names. They cover the schema pin on `as_dict`, ...
```

Note that the six names it mentions belong to **another** slice
(`revision-checked-tool-results`), and that the prose itself quotes
`grep -c 'def test_'` — which is why the old `grep` matched it.

| | old | new |
|---|---|---|
| `NEW_TESTS` | `PASS NEW_TESTS 1 new test methods across 1 commit(s)` | `FAIL NEW_TESTS 0` |
| slice verdict | `ACCEPT: FAIL (8/11, 1 skipped)` | `ACCEPT: FAIL (7/11, 1 skipped)` |

The slice's overall verdict does **not** change (it was already FAIL for
unrelated reasons: its canary does not match its report, and its report
has no full-suite statement and no `161/169`), but the **check** is now
honest: this slice wrote zero test methods, and the referee says so.

This case is locked in by a regression test in
`components/northstar-agent-runtime/tests/test_r6_worktree_rename.py`
(`test_g_a_prose_mention_in_markdown_is_not_a_test_method`).

---

## 5. Per-change attribution

Every slice whose **verdict** or **check line** changed, with the exact
check and the exact cause. The four changed verdicts:

| slice | check | old | new | cause |
|---|---|---|---|---|
| `artifact-completion` | `REPORT_NUMBERS` | `FAIL REPORT_NUMBERS see detail above` | `PASS REPORT_NUMBERS jsonl=3c2b6040-….jsonl` | **R6-12** — the old `grep -rl <canary> … \| head -n1` picked the wrong session; the deterministic resolver picks the right one, so the numbers now cross-check |
| `r6-12-session-resolution` | `REPORT_NUMBERS` | `FAIL REPORT_NUMBERS see detail above` | `SKIP REPORT_NUMBERS no session resolved for canary iOgF8SrRoZvaqxTG7HFg` | **R6-12** — the resolver finds **no** session for this canary; `SKIP` is the honest answer ("no session / ambiguous"), never a guess |
| `tombstone` | `REPORT_NUMBERS` | `FAIL REPORT_NUMBERS see detail above` | `SKIP REPORT_NUMBERS no session resolved for canary 9lULp0MNufmuQZ6OGlNL` | **R6-12** — same: no session resolved, `SKIP` |
| `capability-ceiling-probe` | `COMMIT` | `PASS COMMIT 9ea57f23 (1 commit(s))` | `FAIL COMMIT none` | **R6-1b/R6-4** — the slice owns **no** commit whose subject is `B173 capability-ceiling-probe:`. The old referee borrowed `9ea57f23` (`B173 scorer-disagreement: …`) because that commit happened to touch a path in the manifest. The patched `COMMIT` refuses to borrow another slice's commit |

`capability-ceiling-probe` is the one slice that gets **worse**. It was
"crediting" another slice's commit; the patch exposes that. This is
correct, and it is the only verdict regression in the batch.

The check lines that changed **without** changing the verdict:

| slice | check | old | new | cause |
|---|---|---|---|---|
| `orphan-adoption` | `NEW_TESTS` | `PASS … 1 new test methods` | `FAIL NEW_TESTS 0` | **R6-7** — the one match was prose in a markdown table (§4) |
| `anthropic-effort-scaling` | `REPORT_NUMBERS` | `PASS … jsonl=1584ff04-….jsonl` | `SKIP … ambiguous session for canary WpEwcNwoMwHA9VLDmkcM -- not guessed` | **R6-12** — two candidate sessions, so the resolver refuses to pick |
| `judge-hygiene` | `NEW_TESTS` | `PASS … 20 new test methods` | `PASS … 17 distinct new test methods` | **R6-7** — three added lines *quote* a `def test_` inside a generated mutant |
| `r6-check-accuracy` | `NEW_TESTS` | `PASS … 58 new test methods` | `PASS … 20 distinct new test methods` | **R6-7** |
| `r6-manifest-integrity` | `NEW_TESTS` | `PASS … 20 new test methods` | `PASS … 14 distinct new test methods` | **R6-7** |
| `artifact-completion` | `NEW_TESTS` | `PASS … 14 new test methods` | `PASS … 12 distinct new test methods` | **R6-7** |
| every slice | `NEW_TESTS` detail | `N new test methods` | `N distinct new test methods` | **R6-7** — the wording changes even when the number does not |

`WORKTREE_CLEAN` is the one check whose **status** changed nowhere in the
batch: the repository had **no dirty renames** during the run, so the
defect was latent. It is proven by the throwaway-repo reproduction (§1)
and locked in by tests (a)–(d) in
`components/northstar-agent-runtime/tests/test_r6_worktree_rename.py`.

### 5.1 The full lines-vs-distinct-names table

Every slice whose **number** changed, measured with the patched rule over
the referee's own commit discovery:

| `artifact-completion` | 14 | **12** | −2 |
| `c52` | 42 | **41** | −1 |
| `c54` | 42 | **41** | −1 |
| `e2b` | 65 | **63** | −2 |
| `fable` | 50 | **48** | −2 |
| `judge-hygiene` | 20 | **17** | −3 |
| `orphan-adoption` | 1 | **0** | −1 |
| `r6-baseline-unify` | 40 | **38** | −2 |
| `r6-check-accuracy` | 58 | **20** | −38 |
| `r6-manifest-integrity` | 20 | **14** | −6 |
| `r6-manifest-subject` | 14 | **12** | −2 |
| `step-reliability-budget` | 31 | **26** | −5 |
| `strands` | 32 | **31** | −1 |

The full per-slice numbers (all 83 slices, including the unchanged ones)
are in `/tmp/b173-r6-worktree-rename/newtests.tsv`.

The background listed 10 slices; **13** changed. The three the background
missed are `r6-baseline-unify` (40 → 38), `r6-manifest-subject` (14 → 12)
and — the background listed `c52` / `c54` as one row — they are two rows
here.

---

## 6. Determinism

The integrated referee was run **3 times** on 8 slices — the 4 whose
verdict changed, plus the 4 whose check lines changed. The `ACCEPT:` line
is **identical** in all three runs, every time:

```
### artifact-completion
  run1: ACCEPT: PASS (11/11, 1 skipped) artifact-completion
  run2: ACCEPT: PASS (11/11, 1 skipped) artifact-completion
  run3: ACCEPT: PASS (11/11, 1 skipped) artifact-completion
### capability-ceiling-probe
  run1: ACCEPT: FAIL (11/12, 0 skipped) capability-ceiling-probe
  run2: ACCEPT: FAIL (11/12, 0 skipped) capability-ceiling-probe
  run3: ACCEPT: FAIL (11/12, 0 skipped) capability-ceiling-probe
### r6-12-session-resolution
  run1: ACCEPT: PASS (10/10, 2 skipped) r6-12-session-resolution
  run2: ACCEPT: PASS (10/10, 2 skipped) r6-12-session-resolution
  run3: ACCEPT: PASS (10/10, 2 skipped) r6-12-session-resolution
### tombstone
  run1: ACCEPT: PASS (10/10, 2 skipped) tombstone
  run2: ACCEPT: PASS (10/10, 2 skipped) tombstone
  run3: ACCEPT: PASS (10/10, 2 skipped) tombstone
### orphan-adoption
  run1: ACCEPT: FAIL (7/11, 1 skipped) orphan-adoption
  run2: ACCEPT: FAIL (7/11, 1 skipped) orphan-adoption
  run3: ACCEPT: FAIL (7/11, 1 skipped) orphan-adoption
### anthropic-effort-scaling
  run1: ACCEPT: PASS (11/11, 1 skipped) anthropic-effort-scaling
  run2: ACCEPT: PASS (11/11, 1 skipped) anthropic-effort-scaling
  run3: ACCEPT: PASS (11/11, 1 skipped) anthropic-effort-scaling
### judge-hygiene
  run1: ACCEPT: PASS (11/11, 1 skipped) judge-hygiene
  run2: ACCEPT: PASS (11/11, 1 skipped) judge-hygiene
  run3: ACCEPT: PASS (11/11, 1 skipped) judge-hygiene
### r6-check-accuracy
  run1: ACCEPT: PASS (11/11, 1 skipped) r6-check-accuracy
  run2: ACCEPT: PASS (11/11, 1 skipped) r6-check-accuracy
  run3: ACCEPT: PASS (11/11, 1 skipped) r6-check-accuracy
```

The `PASS`/`FAIL`/`SKIP` denominators are identical across the runs too
(`11/11, 1 skipped`, `10/10, 2 skipped`, …) — the counts are stable, not
just the words.

---

## 7. The denominator, the format, the exit codes — and how to apply the patches

### 7.1 The referee keeps its 12 checks

```
$ grep -oE 'check [A-Z_]+ ' accept.sh | sort -u | wc -l
12
$ grep -oE 'check [A-Z_]+ ' accept.sh | sort -u | tr '\n' ' '
check BENCH  check BENCH_DIFF  check CANARY  check COMMIT  check FABLE_VERIF  check FULL_SUITE  check MUTANT  check NEW_TESTS  check REPORT  check REPORT_NUMBERS  check TESTS_RAN  check WORKTREE_CLEAN
```

The live script has the same 12 distinct names:

```
$ grep -oE 'check [A-Z_]+ ' /home/muse-newapi/b173-accept.sh | sort -u | wc -l
12
```

(The raw number of `check ` **call sites** rises from 14 to 17, because the
patched script adds `else` branches for the new conditions. The number of
distinct **checks** — the denominator — is unchanged at 12.)

### 7.2 The denominator formula, the line format and the exit codes

Unchanged, verbatim, in the integrated copy:

```
$ grep -n 'TOTAL=' accept.sh
314:TOTAL=$((PASS+FAIL))

$ grep -n 'ACCEPT: ' accept.sh
315:if [ "$FAIL" -eq 0 ]; then echo "ACCEPT: PASS ($PASS/$TOTAL, $SKIP skipped) $SLUG"; exit 0;
316:else echo "ACCEPT: FAIL ($PASS/$TOTAL, $SKIP skipped) $SLUG"; exit 1; fi
```

The `check()` helper is unchanged:

```
PASS) PASS=$((PASS+1)); echo "PASS $name $detail";;
FAIL) FAIL=$((FAIL+1)); echo "FAIL $name $detail";;
*)    SKIP=$((SKIP+1)); echo "SKIP $name $detail";;
```

Exit codes: **0** = ACCEPT PASS, **1** = ACCEPT FAIL. Verified for real:
the integrated copy returned `1` for `capability-ceiling-probe` and
`r6-test-count`, and `0` for `artifact-completion` — and the recorded
`old_rc=` / `new_rc=` lines in the raw outputs agree.

### 7.3 The precise application order (for the coordinator)

The live script is **not** modified by this slice. To apply the same
integration to the live referee:

```bash
cp -p /home/muse-newapi/b173-accept.sh /home/muse-newapi/b173-accept.sh.r6patched
cd /home/muse-newapi
patch -p0 b173-accept.sh.r6patched < /home/muse-newapi/b173-r6-manifest-integrity-fix.patch
patch -p0 b173-accept.sh.r6patched < /home/muse-newapi/b173-r6-check-accuracy-fix.patch
patch -p0 b173-accept.sh.r6patched < /home/muse-newapi/b173-r6-12-session-resolution-fix.patch
bash -n b173-accept.sh.r6patched
```

That order works because each patch's context sits at a **different** part
of the file:

| patch | hunk lands at (in the patched file) | why the order matters |
|---|---|---|
| `manifest-integrity` | the `COMMIT` block (lines ~52–120) | rewrites commit discovery and `COMMIT`; **must be first**, because it shifts every later line |
| `check-accuracy` | the `NEW_TESTS` / `WORKTREE_CLEAN` block | it is offset by the manifest patch's insertions (+71 lines) |
| `r6-12-session-resolution` | the `REPORT_NUMBERS` block | offset by both earlier patches (+99 lines) |

`patch` reports the offsets, which is how the offsets above were
determined:

```
patching file accept.sh
Hunk #1 succeeded at 151 (offset 71 lines).
...
Hunk #1 succeeded at 262 (offset 99 lines).
Hunk #2 succeeded at 288 (offset 99 lines).
```

> **WARNING — `b173-r6-12-watch-session-resolution-fix.patch` targets
> `b173-watch.sh`, NOT `b173-accept.sh`.** Do **not** apply it to
> `b173-accept.sh`: its context is `b173-watch.sh`'s and the hunk was
> measured to conflict there. The `b173-watch.sh` counterpart is a
> **separate** patch for a **separate** script.

---

## 8. The threshold question — a decision input, not a change

**The threshold was NOT raised in this slice.** The patched referee still
says `[ "$NTEST" -ge 1 ]`.

Why it must not be raised here: the taskbooks promise "≥ 9 new test
methods" while the referee checks ≥ 1. Raising it to 9 **in this round**
would add a brand-new failure axis on top of the batch's existing
failures and rewrite the batch's pass/fail history on a technicality,
with no slice having written a line of bad code.

### 8.1 The measurement (2026-11-15, patched rule, all 83 manifests)

| population | slices |
|---|---|
| distinct new test methods **≥ 9** | **74** |
| distinct new test methods **< 9** | **9** |
| — of which **0** methods | 6 (`mutant-evidence-closure`, `orphan-adoption`, `r6-test-count`, `r6-worktree-rename`, `runtime-registration-closure`, `slice4`) |
| — of which 2, 3 and 7 methods | 3 (`slice2` = 2, `slice3` = 3, `slice1` = 7) |

### 8.2 How many currently-PASS slices would flip to FAIL

**Zero.**

Every one of the 9 slices with fewer than 9 distinct method names is
already `ACCEPT: FAIL` under the patched referee:

| slice | distinct methods | patched verdict | would flip at 9? |
|---|---|---|---|
| `orphan-adoption` | 0 | `ACCEPT: FAIL (7/11, 1 skipped)` | already FAIL |
| `slice1` | 7 | `ACCEPT: FAIL` | already FAIL |
| `slice2` | 2 | `ACCEPT: FAIL` | already FAIL |
| `slice3` | 3 | `ACCEPT: FAIL` | already FAIL |
| `slice4` | 0 | `ACCEPT: FAIL (8/10, 2 skipped)` | already FAIL |
| `mutant-evidence-closure` | 0 | `ACCEPT: FAIL (8/11, 1 skipped)` | already FAIL |
| `runtime-registration-closure` | 0 | `ACCEPT: FAIL (7/11, 1 skipped)` | already FAIL |
| `r6-test-count` | 0 | `ACCEPT: FAIL (0/9, 3 skipped)` | already FAIL |
| `r6-worktree-rename` | 0 | `ACCEPT: FAIL (0/9, 3 skipped)` | already FAIL |

**Net: raising the threshold from 1 to 9 would flip 0 currently-PASS
slices.** The number of slices the coordinator should weigh is therefore
**0**, not "every already-accepted slice".

### 8.3 Three caveats

1. **The count is a floor, not a ceiling.** `slice4`'s two real commits
   (`B173 slice4 (part 1)`, `B173 slice4 (part 2)`) contain **10**
   distinct test methods; the referee sees only the `B173 slice4:`
   consolidation commit, which adds none. A threshold of 9 would fail a
   slice that in fact delivered 10 methods, purely because of a
   subject-prefix mismatch.
2. **The distinct count is stricter than the old line count**, so raising
   the threshold on the *new* count is stricter than raising it on the
   old one. `judge-hygiene` reports 20 today and 17 under the new count —
   still above 9, but the margin is thinner.
3. **The measurement is population-sensitive.** It was taken over the 83
   manifests that exist on 2026-11-15. Two of them (`r6-test-count`,
   `r6-worktree-rename`) belong to slices that had not committed when the
   run was made; if they land with real test methods the "< 9" count
   drops.

**Recommendation:** keep the threshold at 1 in this round. If it is raised
later, raise it in a round whose only job is to re-run the whole batch and
re-baseline the ledger, and fix the subject-prefix discovery first
(caveat 1) so that the number means what it is supposed to mean.
