# R6-2 — the referee must verify the commit *subject*, so a slice cannot claim another slice's work

**Slice:** `r6-manifest-subject`
**Date:** 2026-11-15
**Status:** integrated and verified on a *copy* of the referee; the live
`b173-accept.sh` was **not** modified by this slice.

---

## 1. The defect

`b173-accept.sh` used to find "this slice's commit" like this
(`b173-accept.sh:52-55`, verbatim from the live script):

```bash
# All slice commits (subject prefix), newest first. Fallback: manifest files.
SLICE_HASHES=$(git -C "$REPO" log --format=%H --grep="^B173 ${SLUG}:" -i 2>/dev/null | head -20 || true)
if [ -z "$SLICE_HASHES" ] && [ -f "$MANIFEST" ]; then
  SLICE_HASHES=$(git -C "$REPO" log --format=%H -1 -- $(cat "$MANIFEST" | tr '\n' ' ') 2>/dev/null || true)
fi
```

The fallback takes **the newest commit that touched any path named in the
slice's manifest** and never checks that commit's subject. The manifest of
a slice that only *edited existing files* names paths other slices also
own, so the "newest commit touching those paths" is usually **someone
else's** commit — and the referee then judges this slice on that commit.

The fallback exists for a good reason (round-5 D-23): a slice's fix may
have been committed under another slice's slug. So the fallback must not be
deleted. But it must not be used as *attribution*.

### Reproduction

```bash
# which commit does the referee credit to this slice?
$ git log --format=%H --grep="^B173 acceptance-conformance:" -i | wc -l
0
$ git log --format=%s -1 50bda24f
B173 deterministic-gate-score: kill or@155/or@159/or@197 in deterministic-gate-score

$ git log --format=%H --grep="^B173 capability-ceiling-probe:" -i | wc -l
0
$ git log --format=%s -1 9ea57f23
B173 scorer-disagreement: disagreement detector over multi-scorer verdicts
```

Both slices own **no commit of their own**, and the old referee credited
them with a foreign commit:

| slice | own commits | old referee credited | that commit really belongs to |
|---|---|---|---|
| `acceptance-conformance` | **0** | `50bda24f` | `deterministic-gate-score` |
| `capability-ceiling-probe` | **0** | `9ea57f23` | `scorer-disagreement` |

`acceptance-conformance` had been passing 12/12 while being judged on
`deterministic-gate-score`'s commit.

---

## 2. The fix: attribution separated from evidence

The integrated referee keeps **both** hash sets and uses them for different
questions:

```bash
SUBJ_HASHES=$(git -C "$REPO" log --format=%H --grep="^B173 ${SLUG}:" -i | head -20)

# Legacy path-based fallback: the newest commit touching any manifest path.
# It is kept for the CONTENT checks (NEW_TESTS / WORKTREE_CLEAN / TESTS_RAN /
# MUTANT) so that their verdicts do not move; ATTRIBUTION is decided by
# COMMIT below, which only accepts a commit whose subject is this slice's.
SLICE_HASHES="$SUBJ_HASHES"
if [ -z "$SLICE_HASHES" ] && [ -f "$MANIFEST" ]; then
  SLICE_HASHES=$(git -C "$REPO" log --format=%H -1 -- $(cat "$MANIFEST" | tr '\n' ' ') 2>/dev/null || true)
fi

OWN_HASHES="$SUBJ_HASHES"
if [ -z "$OWN_HASHES" ] && [ -f "$MANIFEST" ]; then
  OWN_HASHES=""
  MPATHS=$(manifest_paths "$MANIFEST" | tr '\n' ' ')
  if [ -n "$MPATHS" ]; then
    for cand in $(git -C "$REPO" log --format=%H -20 -- $MPATHS 2>/dev/null || true); do
      csubj=$(git -C "$REPO" log --format=%s -1 "$cand" | tr '[:upper:]' '[:lower:]' || true)
      slug_lc=$(printf '%s' "$SLUG" | tr '[:upper:]' '[:lower:]')
      case "$csubj" in
        "b173 ${slug_lc}:"*) OWN_HASHES="$cand"; break;;
      esac
    done
  fi
fi
```

`COMMIT` is decided **only** by `OWN_HASHES`, and its detail names the
reason, not just a hash:

```
PASS COMMIT 1c947e7b (1 commit(s))
FAIL COMMIT none
FAIL COMMIT none; manifest: docs/design/acceptance-conformance.md: missing
```

**Why the content checks keep the fallback.** `NEW_TESTS` / `MUTANT` /
`TESTS_RAN` / `WORKTREE_CLEAN` read *code*, and that code may live under
another slice's slug. If those checks were tightened too, a dozen slices
would flip to FAIL for a technicality and the batch would drown in noise.
Keeping them on the fallback means:

* **attribution wrong → `COMMIT` FAIL**;
* **evidence missing → that check FAILs on its own**.

Two questions, two verdicts. The referee stays explainable.

---

## 3. The three patches, and their application order

The fix is **not** an edit to the live script. It is three patch files that
the coordinator applies to `b173-accept.sh`:

| # | patch file | targets | what it changes |
|---|---|---|---|
| 1 | `b173-r6-manifest-integrity-fix.patch` | `b173-accept.sh` | `B173_HOME_DIR` override; `manifest_paths` / `manifest_violations` helpers; `SUBJ_HASHES` vs `OWN_HASHES` split; `COMMIT` becomes the subject-verified attribution + manifest-truth gate |
| 2 | `b173-r6-check-accuracy-fix.patch` | `b173-accept.sh` | `NEW_TESTS` counts **distinct** new test method names (plain ERE, works under GNU grep *and* ugrep); `WORKTREE_CLEAN` reads **both** paths of a git rename line |
| 3 | `b173-r6-12-session-resolution-fix.patch` | `b173-accept.sh` | `REPORT_NUMBERS` resolves the session through `b173-resolve-session.py` (deterministic) instead of `grep -rl … | head -n1`; ambiguous → SKIP, never a guessed PASS |

### ⚠️ `b173-r6-12-watch-session-resolution-fix.patch` targets a DIFFERENT file

There is a fourth patch in the same family:

```
/home/muse-newapi/b173-r6-12-watch-session-resolution-fix.patch
```

It targets **`b173-watch.sh`**, not `b173-accept.sh`. Applying it to the
accept script conflicts (it has no matching hunk there and would corrupt
the file). Do not install it on `b173-accept.sh`.

### Exact application order (for the coordinator)

```bash
cd /home/muse-newapi
cp -p b173-accept.sh b173-accept.sh.bak          # keep a backup
patch -p1 b173-accept.sh < /home/muse-newapi/b173-r6-manifest-integrity-fix.patch
patch -p1 b173-accept.sh < /home/muse-newapi/b173-r6-check-accuracy-fix.patch
patch -p1 b173-accept.sh < /home/muse-newapi/b173-r6-12-session-resolution-fix.patch
bash -n b173-accept.sh                            # must print nothing
```

### Measured `patch` output on a copy (verbatim)

```
$ mkdir -p /tmp/b173-r6-manifest-subject
$ cp -p /home/muse-newapi/b173-accept.sh /tmp/b173-r6-manifest-subject/accept.sh
$ cd /tmp/b173-r6-manifest-subject

$ patch -p0 accept.sh < /home/muse-newapi/b173-r6-manifest-integrity-fix.patch
patching file accept.sh
rc=0

$ patch -p0 accept.sh < /home/muse-newapi/b173-r6-check-accuracy-fix.patch
patching file accept.sh
Hunk #1 succeeded at 151 (offset 71 lines).
rc=0

$ patch -p0 accept.sh < /home/muse-newapi/b173-r6-12-session-resolution-fix.patch
patching file accept.sh
Hunk #1 succeeded at 262 (offset 99 lines).
Hunk #2 succeeded at 288 (offset 99 lines).
rc=0

$ bash -n accept.sh
syntax OK
```

No patch needed editing; none reported `FAILED` or `Reversed`.
(The offsets are relative to the live script as of 2026-11-15; the
coordinator's `patch` output will carry its own offsets, which is normal.)

---
## 4. The whole batch through both referees

Every slice that has a `b173-<slug>.files` manifest was run through
**both** referees on the same repository state. The manifest-bearing
slice population is **83** on 2026-11-15 (the task book says 72,
measured before the round-6 slices and the parallel slices of
2026-11-15 added their own manifests; the extra rows are marked
`new` below). The old referee is the live
`/home/muse-newapi/b173-accept.sh`; the new one is the patched copy
in `/tmp/b173-r6-manifest-subject/accept.sh`.

```
OLD: PASS=52 FAIL=31
NEW: PASS=53 FAIL=30
net: +1 PASS, -1 FAIL
```

| slice | OLD | NEW | changed |
|---|---|---|---|
| `acceptance-conformance` | ACCEPT: FAIL (8/11, 1 skipped) | ACCEPT: FAIL (6/11, 1 skipped) | yes |
| `actionable-digest` | ACCEPT: PASS (12/12, 0 skipped) | ACCEPT: PASS (12/12, 0 skipped) |  |
| `agent-handoff` | ACCEPT: PASS (12/12, 0 skipped) | ACCEPT: PASS (12/12, 0 skipped) |  |
| `ageofagents` | ACCEPT: PASS (12/12, 0 skipped) | ACCEPT: PASS (12/12, 0 skipped) |  |
| `anthropic-effort-scaling` | ACCEPT: PASS (12/12, 0 skipped) | ACCEPT: PASS (11/11, 1 skipped) | yes |
| `artifact-completion` | ACCEPT: FAIL (10/11, 1 skipped) | ACCEPT: PASS (11/11, 1 skipped) | yes |
| `asinhhc` | ACCEPT: PASS (12/12, 0 skipped) | ACCEPT: PASS (12/12, 0 skipped) |  |
| `audit-head` | ACCEPT: FAIL (9/11, 1 skipped) | ACCEPT: FAIL (9/11, 1 skipped) |  |
| `autogen-speaker-selector` | ACCEPT: PASS (12/12, 0 skipped) | ACCEPT: PASS (12/12, 0 skipped) |  |
| `baseline-attribution` | ACCEPT: PASS (11/11, 1 skipped) | ACCEPT: PASS (11/11, 1 skipped) |  |
| `c52` | ACCEPT: FAIL (10/11, 1 skipped) | ACCEPT: FAIL (10/11, 1 skipped) |  |
| `c54` | ACCEPT: FAIL (10/11, 1 skipped) | ACCEPT: FAIL (10/11, 1 skipped) |  |
| `c58` | ACCEPT: FAIL (10/11, 1 skipped) | ACCEPT: FAIL (10/11, 1 skipped) |  |
| `capability-ceiling-probe` | ACCEPT: PASS (12/12, 0 skipped) | ACCEPT: FAIL (11/12, 0 skipped) | yes |
| `cost-per-delivery` | ACCEPT: PASS (12/12, 0 skipped) | ACCEPT: PASS (12/12, 0 skipped) |  |
| `cwl-episode-eviction` | ACCEPT: PASS (12/12, 0 skipped) | ACCEPT: PASS (12/12, 0 skipped) |  |
| `deterministic-gate-score` | ACCEPT: FAIL (11/12, 0 skipped) | ACCEPT: FAIL (11/12, 0 skipped) |  |
| `diviner` | ACCEPT: FAIL (9/11, 1 skipped) | ACCEPT: FAIL (9/11, 1 skipped) |  |
| `dynamiq` | ACCEPT: PASS (11/11, 1 skipped) | ACCEPT: PASS (11/11, 1 skipped) |  |
| `e2b` | ACCEPT: FAIL (9/11, 1 skipped) | ACCEPT: FAIL (9/11, 1 skipped) |  |
| `effect-directive` | ACCEPT: PASS (12/12, 0 skipped) | ACCEPT: PASS (12/12, 0 skipped) |  |
| `event-condenser` | ACCEPT: PASS (12/12, 0 skipped) | ACCEPT: PASS (12/12, 0 skipped) |  |
| `evidence-independence` | ACCEPT: PASS (12/12, 0 skipped) | ACCEPT: PASS (12/12, 0 skipped) |  |
| `fable` | ACCEPT: FAIL (11/12, 0 skipped) | ACCEPT: FAIL (11/12, 0 skipped) |  |
| `false-green-detector` | ACCEPT: PASS (12/12, 0 skipped) | ACCEPT: PASS (12/12, 0 skipped) |  |
| `fieldnotes` | ACCEPT: PASS (11/11, 1 skipped) | ACCEPT: PASS (11/11, 1 skipped) |  |
| `horizon` | ACCEPT: PASS (12/12, 0 skipped) | ACCEPT: PASS (12/12, 0 skipped) |  |
| `horizon-gate` | ACCEPT: PASS (12/12, 0 skipped) | ACCEPT: PASS (12/12, 0 skipped) |  |
| `intent-bound-retry` | ACCEPT: PASS (12/12, 0 skipped) | ACCEPT: PASS (12/12, 0 skipped) |  |
| `jido-statebudget` | ACCEPT: PASS (12/12, 0 skipped) | ACCEPT: PASS (12/12, 0 skipped) |  |
| `judge-hygiene` | ACCEPT: PASS (11/11, 1 skipped) | ACCEPT: PASS (11/11, 1 skipped) |  |
| `langgraph` | ACCEPT: PASS (12/12, 0 skipped) | ACCEPT: PASS (12/12, 0 skipped) |  |
| `langgraph-durability` | ACCEPT: PASS (12/12, 0 skipped) | ACCEPT: PASS (12/12, 0 skipped) |  |
| `langgraph-retry-clears-writes` | ACCEPT: PASS (12/12, 0 skipped) | ACCEPT: PASS (12/12, 0 skipped) |  |
| `leased-task-claim` | ACCEPT: PASS (12/12, 0 skipped) | ACCEPT: PASS (12/12, 0 skipped) |  |
| `lightningzero` | ACCEPT: PASS (11/11, 1 skipped) | ACCEPT: PASS (11/11, 1 skipped) |  |
| `merged-tree-review` | ACCEPT: FAIL (8/11, 1 skipped) | ACCEPT: FAIL (8/11, 1 skipped) |  |
| `msaf-lineage` | ACCEPT: FAIL (10/11, 1 skipped) | ACCEPT: FAIL (10/11, 1 skipped) |  |
| `mutant-evidence-closure` | ACCEPT: FAIL (8/11, 1 skipped) | ACCEPT: FAIL (8/11, 1 skipped) |  |
| `neo-konsi-s2bw` | ACCEPT: PASS (12/12, 0 skipped) | ACCEPT: PASS (12/12, 0 skipped) |  |
| `openhands-stuck-detector` | ACCEPT: PASS (12/12, 0 skipped) | ACCEPT: PASS (12/12, 0 skipped) |  |
| `orphan-adoption` | ACCEPT: FAIL (8/11, 1 skipped) | ACCEPT: FAIL (7/11, 1 skipped) | yes |
| `outsideloop` | ACCEPT: PASS (12/12, 0 skipped) | ACCEPT: PASS (12/12, 0 skipped) |  |
| `r6-12-session-resolution` | ACCEPT: PASS (11/11, 1 skipped) | ACCEPT: PASS (10/10, 2 skipped) | yes |
| `r6-baseline-unify` | ACCEPT: FAIL (10/11, 1 skipped) | ACCEPT: FAIL (9/10, 2 skipped) | yes |
| `r6-check-accuracy` | ACCEPT: PASS (11/11, 1 skipped) | ACCEPT: PASS (11/11, 1 skipped) |  |
| `r6-manifest-integrity` | ACCEPT: PASS (11/11, 1 skipped) | ACCEPT: PASS (11/11, 1 skipped) |  |
| `r6-manifest-subject` | ACCEPT: FAIL (0/9, 3 skipped) | ACCEPT: FAIL (0/9, 3 skipped) |  |
| `r6-test-count` | ACCEPT: FAIL (0/9, 3 skipped) | ACCEPT: FAIL (0/9, 3 skipped) |  |
| `r6-worktree-rename` | ACCEPT: FAIL (0/9, 3 skipped) | ACCEPT: FAIL (0/9, 3 skipped) |  |
| `refusal-hold` | ACCEPT: PASS (12/12, 0 skipped) | ACCEPT: PASS (12/12, 0 skipped) |  |
| `refusal-hold-wiring` | ACCEPT: FAIL (11/12, 0 skipped) | ACCEPT: FAIL (11/12, 0 skipped) |  |
| `refusal-row` | ACCEPT: PASS (12/12, 0 skipped) | ACCEPT: PASS (12/12, 0 skipped) |  |
| `resume-validation` | ACCEPT: PASS (12/12, 0 skipped) | ACCEPT: PASS (12/12, 0 skipped) |  |
| `reversible-compaction` | ACCEPT: PASS (12/12, 0 skipped) | ACCEPT: PASS (12/12, 0 skipped) |  |
| `revision-checked-tool-results` | ACCEPT: PASS (12/12, 0 skipped) | ACCEPT: PASS (12/12, 0 skipped) |  |
| `runtime-registration` | ACCEPT: FAIL (9/11, 1 skipped) | ACCEPT: FAIL (9/11, 1 skipped) |  |
| `runtime-registration-closure` | ACCEPT: FAIL (7/11, 1 skipped) | ACCEPT: FAIL (7/11, 1 skipped) |  |
| `scope-verbatim-compaction` | ACCEPT: PASS (12/12, 0 skipped) | ACCEPT: PASS (12/12, 0 skipped) |  |
| `scorer-disagreement` | ACCEPT: PASS (12/12, 0 skipped) | ACCEPT: PASS (12/12, 0 skipped) |  |
| `seal-slice6` | ACCEPT: FAIL (8/10, 2 skipped) | ACCEPT: FAIL (8/10, 2 skipped) |  |
| `session-memory` | ACCEPT: PASS (12/12, 0 skipped) | ACCEPT: PASS (12/12, 0 skipped) |  |
| `silent-failure-detector` | ACCEPT: PASS (12/12, 0 skipped) | ACCEPT: PASS (12/12, 0 skipped) |  |
| `slice1` | ACCEPT: FAIL (10/11, 1 skipped) | ACCEPT: FAIL (10/11, 1 skipped) |  |
| `slice2` | ACCEPT: FAIL (9/11, 1 skipped) | ACCEPT: FAIL (9/11, 1 skipped) |  |
| `slice3` | ACCEPT: FAIL (10/11, 1 skipped) | ACCEPT: FAIL (10/11, 1 skipped) |  |
| `slice4` | ACCEPT: FAIL (8/10, 2 skipped) | ACCEPT: FAIL (8/10, 2 skipped) |  |
| `slice5` | ACCEPT: FAIL (10/11, 1 skipped) | ACCEPT: FAIL (10/11, 1 skipped) |  |
| `slice6` | ACCEPT: FAIL (9/11, 1 skipped) | ACCEPT: FAIL (9/11, 1 skipped) |  |
| `stale-checkpoint-gate` | ACCEPT: PASS (12/12, 0 skipped) | ACCEPT: PASS (12/12, 0 skipped) |  |
| `step-reliability-budget` | ACCEPT: PASS (12/12, 0 skipped) | ACCEPT: PASS (12/12, 0 skipped) |  |
| `strands` | ACCEPT: PASS (12/12, 0 skipped) | ACCEPT: PASS (12/12, 0 skipped) |  |
| `swe-failure-modes` | ACCEPT: PASS (12/12, 0 skipped) | ACCEPT: PASS (12/12, 0 skipped) |  |
| `tombstone` | ACCEPT: FAIL (10/11, 1 skipped) | ACCEPT: PASS (10/10, 2 skipped) | yes |
| `tombstone-mutant-blindspots` | ACCEPT: PASS (12/12, 0 skipped) | ACCEPT: PASS (12/12, 0 skipped) |  |
| `tool-output-filter` | ACCEPT: PASS (12/12, 0 skipped) | ACCEPT: PASS (12/12, 0 skipped) |  |
| `toolfail` | ACCEPT: PASS (11/11, 1 skipped) | ACCEPT: PASS (11/11, 1 skipped) |  |
| `turn-truncation` | ACCEPT: PASS (12/12, 0 skipped) | ACCEPT: PASS (12/12, 0 skipped) |  |
| `unwind` | ACCEPT: FAIL (10/11, 1 skipped) | ACCEPT: FAIL (10/11, 1 skipped) |  |
| `verifiability-tier` | ACCEPT: PASS (12/12, 0 skipped) | ACCEPT: PASS (12/12, 0 skipped) |  |
| `vina` | ACCEPT: PASS (11/11, 1 skipped) | ACCEPT: PASS (11/11, 1 skipped) |  |
| `vina-mutant-blindspots` | ACCEPT: PASS (12/12, 0 skipped) | ACCEPT: PASS (12/12, 0 skipped) |  |
| `vina-receipt-signing` | ACCEPT: FAIL (11/12, 0 skipped) | ACCEPT: FAIL (11/12, 0 skipped) |  |

Rows marked `yes` are the **8** slices whose verdict or check line
moved; the other 75 are byte-identical. The three slices
`r6-manifest-subject`, `r6-test-count` and `r6-worktree-rename` are
this batch's in-flight slices (their reports did not exist yet at
run time) and are identical in both columns.

## 5. Per-change attribution

Every moved check line, with the exact cause. The **check** column names the
`b173-accept.sh` check; the **cause** column is the mechanism, verified by
git evidence, not an inference.

| slice | check | OLD | NEW | cause |
|---|---|---|---|---|
| `acceptance-conformance` | `COMMIT` | `PASS COMMIT 50bda24f (1 commit(s))` | `FAIL COMMIT none; manifest: docs/design/acceptance-conformance.md: missing` | The slice owns **0** commits (`git log --grep="^B173 acceptance-conformance:" -i` is empty). The old path fallback credited it `50bda24f`, whose subject is `B173 deterministic-gate-score: kill or@155/or@159/or@197 in deterministic-gate-score`. The new subject check rejects it; the `manifest:` half of the detail comes from `b173-r6-manifest-integrity-fix.patch`: the manifest names `docs/design/acceptance-conformance.md`, which is not in the tree. |
| `acceptance-conformance` | `REPORT_NUMBERS` | `PASS REPORT_NUMBERS jsonl=2d469aa9-…jsonl` | `FAIL REPORT_NUMBERS see detail above` | `b173-r6-12-session-resolution-fix.patch` resolves the session deterministically instead of `grep -rl … \| head -n1`. The resolved session is `ddcf50b8-8bde-43b9-9c34-7efba64add54.jsonl`, whose real peak is 88565; the report claims 97754 (the number the *wrong* session carried). The old referee passed it against the poisoned session `2d469aa9-…`. Detail: `PEAK FAIL: report claims 97754 but JSONL max is 88565`. |
| `capability-ceiling-probe` | `COMMIT` | `PASS COMMIT 9ea57f23 (1 commit(s))` | `FAIL COMMIT none` | The slice owns **0** commits. The old fallback credited it `9ea57f23`, whose subject is `B173 scorer-disagreement: disagreement detector over multi-scorer verdicts`. The new subject check rejects it. |
| `capability-ceiling-probe` | `REPORT_NUMBERS` | `PASS REPORT_NUMBERS jsonl=2d469aa9-…jsonl` | `PASS REPORT_NUMBERS jsonl=e7e675c4-…jsonl` | Same patch, same slice: the deterministic resolver now picks the slice's own session `e7e675c4-cefa-4762-ab17-0746d5e9f1c5.jsonl` instead of the shared poison session. The verdict stays PASS but the **numbers cross-checked** are now the slice's own. |
| `orphan-adoption` | `NEW_TESTS` | `PASS NEW_TESTS 1 new test methods across 1 commit(s)` | `FAIL NEW_TESTS 0` | Its single commit `1c947e7b` adds **only two markdown documents** (`git show --name-only --format= 1c947e7b` → `docs/design/annotation-pin.md`, `docs/design/orphan-adoption.md`). The old check counted a **prose mention** inside a markdown table as a test method — the offending diff line is `+\| 1 \| \`tests/test_revision_checked_tool_results.py\` \| 6 new test methods (\`test_result_as_dict_carries_the_schema_pin\`, …) \| **keep** \| …`. `b173-r6-check-accuracy-fix.patch` counts only lines that actually define a method (`^[+][[:space:]]*(async[[:space:]]+)?def[[:space:]]+test_…`), so the prose yields 0. |
| `orphan-adoption` | `REPORT_NUMBERS` | `PASS REPORT_NUMBERS jsonl=0976bbc5-…jsonl` | `PASS REPORT_NUMBERS jsonl=a7f805f9-…jsonl` | The deterministic resolver picks the slice's own session instead of the shared one. |
| `artifact-completion` | `REPORT_NUMBERS` | `FAIL REPORT_NUMBERS see detail above` | `PASS REPORT_NUMBERS jsonl=3c2b6040-…jsonl` | The old referee resolved the **wrong** session and the cross-check failed; the deterministic resolver finds the slice's own session `3c2b6040-5c84-43e8-8bcf-4dea627d7135.jsonl`, whose numbers match the report. This is the slice that becomes **PASS (11/11)**. |
| `artifact-completion` | `NEW_TESTS` | `PASS NEW_TESTS 14 new test methods across 3 commit(s)` | `PASS NEW_TESTS 12 distinct new test methods across 3 commit(s)` | The count-accuracy patch counts **distinct method names** across the slice's 3 commits (14 added lines, 12 distinct methods — 2 methods were re-added by a later commit). The verdict does not move; the number becomes honest. |
| `tombstone` | `REPORT_NUMBERS` | `FAIL REPORT_NUMBERS see detail above` | `SKIP REPORT_NUMBERS no session resolved for canary 9lULp0MNufmuQZ6OGlNL` | The deterministic resolver finds **no** candidate session for this slice (the watch anchor excludes it, see `b173-resolve-session.py`'s own docstring for the tombstone case). The new referee **SKIPs** (honest: "no session resolved") instead of failing against a poisoned session. This is the slice that becomes **PASS (10/10)**. |
| `anthropic-effort-scaling` | `REPORT_NUMBERS` | `PASS REPORT_NUMBERS jsonl=2d469aa9-…jsonl` | `SKIP REPORT_NUMBERS ambiguous session for canary WpEwcNwoMwHA9VLDmkcM -- not guessed` | Two legitimate attempts of the same slice survive the resolution rule (the resolver documents this exact case). The new referee reports **AMBIGUOUS** and SKIPs rather than guessing a session and PASSing on a coin flip. |
| `r6-12-session-resolution` | `REPORT_NUMBERS` | `PASS REPORT_NUMBERS jsonl=2d469aa9-…jsonl` | `SKIP REPORT_NUMBERS no session resolved for canary iOgF8SrRoZvaqxTG7HFg` | Same as `tombstone`: no candidate session → SKIP instead of a false PASS. |
| `r6-baseline-unify` | `REPORT_NUMBERS` | `PASS REPORT_NUMBERS jsonl=16c8d171-…jsonl` | `SKIP REPORT_NUMBERS no session resolved for canary iTQaVDBjY6YkvNAkfB8Y` | Same as above. |
| `r6-baseline-unify` | `NEW_TESTS` | `PASS NEW_TESTS 40 new test methods across 4 commit(s)` | `PASS NEW_TESTS 38 distinct new test methods across 4 commit(s)` | Distinct-name counting across 4 commits. Verdict unchanged. |
| all 83 slices | `NEW_TESTS` (detail text) | `N new test methods across M commit(s)` | `N distinct new test methods across M commit(s)` | The count-accuracy patch changes the *wording* of the detail line on every slice whose count was ≥1 (the threshold stays 1; raising it to 9 is a separate coordinator decision). No verdict moves because of this alone. |

**Slices whose check lines moved but whose verdict did not:**
`capability-ceiling-probe` (REPORT_NUMBERS only — it stays FAIL, for COMMIT),
`orphan-adoption` (stays FAIL, on NEW_TESTS),
`acceptance-conformance` (stays FAIL, on COMMIT and REPORT_NUMBERS),
`anthropic-effort-scaling`, `r6-12-session-resolution`, `r6-baseline-unify`
(all stay PASS; a false PASS became an honest SKIP).

### The three that had to be verified

1. **`capability-ceiling-probe` — `COMMIT` PASS → FAIL.** Verified: the
   slice's own-commit search is empty
   (`git log --format=%H --grep="^B173 capability-ceiling-probe:" -i | wc -l`
   → `0`), and the old fallback's candidate `9ea57f23` carries the subject
   `B173 scorer-disagreement: …`.
2. **`acceptance-conformance` — `COMMIT` PASS → FAIL.** Verified: own-commit
   search empty (`0`), old candidate `50bda24f` carries the subject
   `B173 deterministic-gate-score: …`. This slice **never committed
   anything at all**.
3. **`orphan-adoption` — `NEW_TESTS` PASS → FAIL.** Verified: the single
   commit `1c947e7b` adds two `.md` files only, and the sole `def test_`
   match is a prose mention in a markdown table (quoted above).

### Side-by-side COMMIT lines

```
$ /bin/grep -E '^(PASS|FAIL) COMMIT' per-slice/acceptance-conformance.old.txt
PASS COMMIT 50bda24f (1 commit(s))
$ /bin/grep -E '^(PASS|FAIL) COMMIT' per-slice/acceptance-conformance.new.txt
FAIL COMMIT none; manifest: docs/design/acceptance-conformance.md: missing

$ /bin/grep -E '^(PASS|FAIL) COMMIT' per-slice/capability-ceiling-probe.old.txt
PASS COMMIT 9ea57f23 (1 commit(s))
$ /bin/grep -E '^(PASS|FAIL) COMMIT' per-slice/capability-ceiling-probe.new.txt
FAIL COMMIT none
```

The new detail names the **reason** (`none`, `none; manifest: … missing`),
not just a hash.

## 6. R6-2 verified on a throwaway repository

A throwaway git repo in `/tmp` with two commits — one whose subject is
`B173 demo-slice: own work` and one whose subject is
`B173 other-slice: foreign work` — both touching manifest paths, with the
**foreign** commit the newest (so the path fallback picks it):

```
$ git log --format='%h %s'
a9cb0e0 B173 other-slug: foreign work
a632fa7 B173 demo-slice: own work

--- simulate the integrated logic for slug=demo-slice ---
a632fa7f2b5f782a1296bce316084f93cf07e67e          <- subject search finds the own commit
--- fallback candidates (newest touching manifest paths):
a9cb0e0658dcc6b4f55dfc8c0916567e4f4e2f79 B173 other-slug: foreign work
a632fa7f2b5f782a1296bce316084f93cf07e67e B173 demo-slice: own work
--- subject-verified attribution:
REJECT a9cb0e0658dcc6b4f55dfc8c0916567e4f4e2f79 b173 other-slug: foreign work
ACCEPT a632fa7f2b5f782a1296bce316084f93cf07e67e b173 demo-slice: own work
--- and for slug=other-slice:
REJECT a9cb0e0658dcc6b4f55dfc8c0916567e4f4e2f79 b173 other-slug: foreign work
REJECT a632fa7f2b5f782a1296bce316084f93cf07e67e b173 demo-slice: own work
```

(The second run uses slug `other-slice` to match the commits; the point of
the first run is that the *foreign* commit is rejected even though the
path fallback selects it first.)

The same behaviour is asserted by
`components/northstar-agent-runtime/tests/test_r6_manifest_subject.py`:
`test_a_foreign_subject_is_not_credited_as_this_slice`,
`test_b_own_subject_is_credited`,
`test_c_slice_without_own_commit_fails_commit`,
`test_c2_unrelated_commit_is_also_rejected`.

---

## 7. Determinism

The integrated referee was run **3 times** on 6 of the changed slices. The
`ACCEPT:` line is identical every time:

```
IDENTICAL  acceptance-conformance :: ACCEPT: FAIL (6/11, 1 skipped) acceptance-conformance
IDENTICAL  anthropic-effort-scaling :: ACCEPT: PASS (11/11, 1 skipped) anthropic-effort-scaling
IDENTICAL  artifact-completion :: ACCEPT: PASS (11/11, 1 skipped) artifact-completion
IDENTICAL  capability-ceiling-probe :: ACCEPT: FAIL (11/12, 0 skipped) capability-ceiling-probe
IDENTICAL  orphan-adoption :: ACCEPT: FAIL (7/11, 1 skipped) orphan-adoption
IDENTICAL  tombstone :: ACCEPT: PASS (10/10, 2 skipped) tombstone
```

A referee that returns different answers on the same repository is worse
than a broken one, so this is a hard requirement, not a nice-to-have. The
conformance test `test_h_two_consecutive_runs_agree` asserts it on a
sandbox repository (both the summary line *and* every individual check
line).

---

## 8. The denominator, the line format and the exit codes are intact

Evidence, not assertion:

```
$ /bin/grep -n 'TOTAL=' accept.sh
314:TOTAL=$((PASS+FAIL))
```

Distinct check names in the integrated copy — **12**, and the same set as
the live script:

```
BENCH  BENCH_DIFF  CANARY  COMMIT  FABLE_VERIF  FULL_SUITE
MUTANT  NEW_TESTS  REPORT  REPORT_NUMBERS  TESTS_RAN  WORKTREE_CLEAN
```

```
$ diff checks-old.txt checks-new.txt
IDENTICAL CHECK SETS
```

Exit codes:

```
$ bash accept.sh capability-ceiling-probe >/dev/null 2>&1 ; echo $?
1        # ACCEPT: FAIL
$ bash accept.sh tombstone >/dev/null 2>&1 ; echo $?
0        # ACCEPT: PASS
$ bash /home/muse-newapi/b173-accept.sh tombstone >/dev/null 2>&1 ; echo $?
1        # the old referee failed this slice
```

Output line format — the referee prints one line per check:

```
PASS <name> <detail>
FAIL <name> <detail>
SKIP <name> <detail>
```

and one summary line:

```
ACCEPT: PASS (11/11, 1 skipped) <slug>     -> exit 0
ACCEPT: FAIL (6/11, 1 skipped) <slug>      -> exit 1
```

The number of checks is **12**; `TOTAL=$((PASS+FAIL))` is unchanged; a
SKIP does not count towards the denominator, exactly as before.

---

## 9. Attribution is separated from evidence

The content checks still run on the **path-based fallback**, so their
verdicts do not move when attribution tightens. Measured directly:

| slice | check | before | after | moved? |
|---|---|---|---|---|
| `acceptance-conformance` | `NEW_TESTS` | `PASS … 12 new test methods` | `PASS … 12 distinct new test methods` | no (wording only) |
| `orphan-adoption` | `NEW_TESTS` | `PASS 1 new test methods` | `FAIL 0` | **yes** — but by the *count-accuracy* patch, not by attribution |
| `capability-ceiling-probe` | `NEW_TESTS` | `PASS 59 …` | `PASS 59 distinct …` | no |
| all slices | `WORKTREE_CLEAN` | unchanged | unchanged | no |
| all slices | `TESTS_RAN` | unchanged | unchanged | no |
| all slices | `MUTANT` | unchanged | unchanged | no |

The one content-check verdict that moved (`orphan-adoption` `NEW_TESTS`) is
caused by the **separate** count-accuracy patch, which counts real method
definitions instead of prose mentions. That patch was measured and landed
on its own slice (`r6-check-accuracy`); the R6-2 attribution change
contributes **no** content-check movement at all. This is the intended
separation: **attribution wrong → `COMMIT` FAIL; evidence missing → that
check FAILs on its own.**

---

## 10. Net effect — and who gets worse

```
OLD: PASS=52 FAIL=31
NEW: PASS=53 FAIL=30
```

Net **+1 PASS**. The improvement is **not** "everything got better".

### Slices that get BETTER

| slice | OLD | NEW | why |
|---|---|---|---|
| `artifact-completion` | FAIL (10/11) | **PASS (11/11)** | `REPORT_NUMBERS` now resolves the right session |
| `tombstone` | FAIL (10/11) | **PASS (10/10)** | `REPORT_NUMBERS` becomes an honest SKIP instead of a FAIL against a poisoned session |

### Slices that get WORSE

| slice | OLD | NEW | why this is correct |
|---|---|---|---|
| `capability-ceiling-probe` | **PASS (12/12)** | **FAIL (11/12)** | It owns **no commit of its own**. The old 12/12 was earned on `scorer-disagreement`'s commit. This is the first time the slice's real state is visible. |
| `acceptance-conformance` | FAIL (8/11) | FAIL (6/11) | Same cause, one check more: `COMMIT` FAIL (it never committed anything) **and** `REPORT_NUMBERS` now FAILs against the slice's own session instead of passing against a wrong one. It was already FAIL; it is now FAIL for the right reasons. |

### Slices that stay PASS but lose a check

`anthropic-effort-scaling`, `r6-12-session-resolution`, `r6-baseline-unify`
keep `ACCEPT: PASS`, but one of their 12 checks becomes an honest SKIP
(no session resolved / ambiguous session) instead of a PASS that was
cross-checked against the **wrong** session. Their totals change from
12/12 or 11/11 to 11/11 or 10/10.

**The honest summary:** the net is +1 PASS, and it is bought with two
slices being exposed. That is the point — the referee is being made to
tell the truth about attribution, and two slices were not telling it.

---

## 11. How to reproduce everything in this document

```bash
# 1. build the integrated referee on a copy
mkdir -p /tmp/b173-r6-manifest-subject
cp -p /home/muse-newapi/b173-accept.sh /tmp/b173-r6-manifest-subject/accept.sh
cd /tmp/b173-r6-manifest-subject
patch -p0 accept.sh < /home/muse-newapi/b173-r6-manifest-integrity-fix.patch
patch -p0 accept.sh < /home/muse-newapi/b173-r6-check-accuracy-fix.patch
patch -p0 accept.sh < /home/muse-newapi/b173-r6-12-session-resolution-fix.patch
bash -n accept.sh

# 2. run both referees over every slice with a manifest
for s in $(cd /home/muse-newapi && for f in b173-*.files; do
             slug=${f#b173-}; slug=${slug%.files}
             [ -s "$f" ] && [ "$(grep -c '/' "$f")" -gt 0 ] && echo "$slug"
           done); do
  echo "$s | $(bash /home/muse-newapi/b173-accept.sh "$s" | grep '^ACCEPT:') | $(bash accept.sh "$s" | grep '^ACCEPT:')"
done

# 3. the conformance test
cd /home/muse-newapi/northstar-agent-os/components/northstar-agent-runtime
PYTHONPATH=.:tests python3 -m unittest test_r6_manifest_subject
```

The conformance test file is
`components/northstar-agent-runtime/tests/test_r6_manifest_subject.py`.
It adds **no** runtime module, so there is nothing to register in
`runtime_registration.py` / `pyproject.toml`.

### The acceptance script's `MUTANT` check and this slice

The `MUTANT` check takes the **first** non-test module and the **first**
test file from the slice's manifest and pairs them. This slice ships **no
runtime module** — only a test file and a design document — so the mutant
probe has no module to mutate and will report
`MUTANT SKIP: manifest lacks module/test` for this slice. There is
therefore **no module-level mutation evidence** for this slice; the
verification evidence is the 12 behavioural test methods plus the
whole-batch measurement above.

---

## 12. Open items

* The live `b173-accept.sh` is **unchanged**. The coordinator still has to
  apply the three patches (section 3) — with the exact order, and **not**
  the watch patch.
* After the coordinator applies the patches, the batch verdicts will match
  the `NEW` column of section 4. Two slices will be **exposed**:
  `capability-ceiling-probe` (PASS → FAIL) and `acceptance-conformance`
  (still FAIL, for the right reasons now). Both are *correct* outcomes,
  not regressions.
* The three in-flight round-6 slices (`r6-manifest-subject`,
  `r6-test-count`, `r6-worktree-rename`) are in the table with
  `ACCEPT: FAIL (0/9, 3 skipped)` because their reports did not exist when
  the batch was measured. They must be re-measured after they land.
* `NEW_TESTS`'s threshold is still **1**, not the task book's 9. Raising it
  is a separate coordinator decision — the count-accuracy patch explicitly
  leaves it alone because it would flip many already-accepted slices.
