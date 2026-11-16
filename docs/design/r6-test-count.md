# r6-test-count — `NEW_TESTS` counted diff LINES, not distinct method names

> Slice: `r6-test-count` — an **integration-and-verification** slice.
> Date: 2026-11-15. Branch: `batch-173-moltbook-absorb`.
> Source: `local:/home/muse-newapi/b173-flow-optimization-round6-candidates-2026-11-14.md#R6-7`
> (rank 3 in the source). The source couples R6-7 to the same two lines as
> R6-3; the fix for both is already inside
> `/home/muse-newapi/b173-r6-check-accuracy-fix.patch`.
>
> **The live `/home/muse-newapi/b173-accept.sh` was NOT edited by this
> slice.** The patches are applied to a **copy** under `/tmp`; the
> coordinator applies them to the live file. The exact commands are in §9.

---

## 0. What this slice is, and what it is not

This slice **does not write the patch**. It **integrates three existing
patches** onto a copy of the live referee, runs the whole batch through
both the old and the new referee, attributes every difference to a
specific cause, proves the count is deterministic, proves the referee's
denominator / output format / exit codes are intact, and hands the
coordinator the **threshold decision input** (how many slices would flip
if `NEW_TESTS` were raised from 1 to 9).

| patch | round-6 item | what it changes |
|---|---|---|
| `b173-r6-manifest-integrity-fix.patch` | R6-1b / R6-4 + R6-2 | `COMMIT` becomes an attribution gate; `HOME_DIR` becomes overridable |
| `b173-r6-check-accuracy-fix.patch` | **R6-3 + R6-7** | `WORKTREE_CLEAN` sees both paths of a rename; **`NEW_TESTS` counts distinct method names** |
| `b173-r6-12-session-resolution-fix.patch` | R6-12 | `REPORT_NUMBERS` resolves the session deterministically, `SKIP`s when ambiguous |

> **DO NOT apply `b173-r6-12-watch-session-resolution-fix.patch` to
> `b173-accept.sh`.** It targets `b173-watch.sh`, not `b173-accept.sh`;
> installing it on the referee was measured to conflict. See §9.

---

## 1. The counting defect (R6-7)

### 1.1 The offending lines

`/home/muse-newapi/b173-accept.sh` lines 83–87, verbatim:

```bash
NTEST=0
for h in $SLICE_HASHES; do
  NTEST=$((NTEST + $(git -C "$REPO" show "$h" 2>/dev/null | grep -c '^\+.*def test_' || true)))
done
[ "$NTEST" -ge 1 ] && check NEW_TESTS PASS "$NTEST new test methods across $NCOMMITS commit(s)" || check NEW_TESTS FAIL "$NTEST"
```

`grep -c` counts **matching lines**. Each matching line is then treated
as if it were a distinct method.

### 1.2 The three ways one method is counted twice

| # | mechanism | what happens |
|---|---|---|
| 1 | **one method, several added lines** | a body line that mentions `def test_` (a quoted source, a generated mutant, a doc string) matches `^\+.*def test_` and is counted again |
| 2 | **one method, two commits** | the counter sums **per commit**, so a name re-added by a later commit of the same slice is counted twice |
| 3 | **prose** | a `def test_` mention inside a **markdown** document matches `^\+.*` (the `+` only has to be the first character of the line) and is counted as a test method |

Mechanism 3 is the `orphan-adoption` case (§5): it is the only one that
**flips a verdict**.

### 1.3 The patched expression

```bash
NTEST_NAMES=""
for h in $SLICE_HASHES; do
  NTEST_NAMES="$NTEST_NAMES
$(git -C "$REPO" show "$h" 2>/dev/null \
  | grep -oE '^[+][[:space:]]*(async[[:space:]]+)?def[[:space:]]+test_[A-Za-z0-9_]*' \
  | sed -E 's/^[+][[:space:]]*(async[[:space:]]+)?def[[:space:]]+//' || true)"
done
NTEST=$(printf '%s\n' "$NTEST_NAMES" | grep -v '^[[:space:]]*$' | sort -u | grep -c . || true)
```

Three properties follow:

* the names of **all** commits are unioned **before** the count, so a name
  added in two commits counts **once**;
* the literal `+` is spelled as the bracket expression `[+]` (not the
  GNU-only BRE escape `\+`), so GNU grep and ugrep agree on the pattern
  (§6);
* a name is only accepted **at the start of a line**, so a prose mention
  inside a markdown table is no longer a test method.

### 1.4 The threshold stays at 1

The patched code still says `[ "$NTEST" -ge 1 ]`. The taskbook promises
"≥ 9 个新测试方法" while the referee checks ≥ 1. **Raising the threshold
to 9 is the coordinator's separate, next-round decision** (§8) and must
be able to be rolled back **independently of the patches** — which is
why it is a one-line change in a different file position from the
pattern change.

---

## 2. The three patches, applied to a copy

```
$ mkdir -p /tmp/b173-r6-test-count
$ cp -p /home/muse-newapi/b173-accept.sh /tmp/b173-r6-test-count/accept.sh
$ cd /tmp/b173-r6-test-count

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

**No `FAILED`, no `Reversed`.** No patch was edited to make it fit; the
offsets are the expected consequence of applying the manifest-integrity
patch (which adds ~70 lines) before the check-accuracy patch.

The live file is unchanged by this slice:

```
$ ls -l --time-style=full-iso /home/muse-newapi/b173-accept.sh
-rwxrwx--- 1 muse-newapi muse-newapi 10032 2026-11-15 10:59:03.675753641 +0000 /home/muse-newapi/b173-accept.sh
$ md5sum /home/muse-newapi/b173-accept.sh /tmp/b173-r6-test-count/accept.sh
23fee57fad090e6fd0600b2948bc5b56  /home/muse-newapi/b173-accept.sh
e19dac16fac8cb9c53a99470513dde7e  accept.sh
```

(the live file's mtime predates this slice's first command; the two
checksums differ because the copy carries the three patches).

---

## 3. The counting properties, proven on real slices

The two `ACCEPT:` runs were executed over **every** slice with a
`b173-<slug>.files` manifest. The old and the new `NEW_TESTS` detail
lines were copied out of the two runs — they are not recomputed.

### 3.1 Every slice whose count changed

**14 slices** changed count. The background of the task book lists 10;
the complete list, measured here, is 14 (the four extra are the round-6
slices committed after the background was written: `r6-baseline-unify`,
`r6-manifest-subject`, `r6-worktree-rename`, and the `orphan-adoption`
flip itself).

| slice | old (lines) | new (distinct names) | Δ | old verdict | new verdict |
|---|---|---|---|---|---|
| `r6-check-accuracy` | 58 | **20** | −38 | PASS | PASS |
| `r6-worktree-rename` | 37 | **17** | −20 | FAIL | FAIL |
| `r6-manifest-integrity` | 20 | **14** | −6 | PASS | PASS |
| `step-reliability-budget` | 31 | **26** | −5 | PASS | PASS |
| `judge-hygiene` | 20 | **17** | −3 | PASS | PASS |
| `artifact-completion` | 14 | **12** | −2 | FAIL | **PASS** |
| `e2b` | 65 | **63** | −2 | FAIL | FAIL |
| `fable` | 50 | **48** | −2 | FAIL | FAIL |
| `r6-baseline-unify` | 40 | **38** | −2 | FAIL | FAIL |
| `r6-manifest-subject` | 14 | **12** | −2 | PASS | PASS |
| `c52` | 42 | **41** | −1 | FAIL | FAIL |
| `c54` | 42 | **41** | −1 | FAIL | FAIL |
| `strands` | 32 | **31** | −1 | PASS | PASS |
| `orphan-adoption` | **1** | **0** | −1 | FAIL | FAIL |

The exact `NEW_TESTS` lines, copied from the two runs:

```
r6-check-accuracy        OLD PASS NEW_TESTS 58 new test methods across 2 commit(s)
                         NEW PASS NEW_TESTS 20 distinct new test methods across 2 commit(s)
judge-hygiene            OLD PASS NEW_TESTS 20 new test methods across 3 commit(s)
                         NEW PASS NEW_TESTS 17 distinct new test methods across 3 commit(s)
step-reliability-budget  OLD PASS NEW_TESTS 31 new test methods across 1 commit(s)
                         NEW PASS NEW_TESTS 26 distinct new test methods across 1 commit(s)
r6-manifest-integrity    OLD PASS NEW_TESTS 20 new test methods across 2 commit(s)
                         NEW PASS NEW_TESTS 14 distinct new test methods across 2 commit(s)
r6-baseline-unify        OLD PASS NEW_TESTS 40 new test methods across 4 commit(s)
                         NEW PASS NEW_TESTS 38 distinct new test methods across 4 commit(s)
r6-manifest-subject      OLD PASS NEW_TESTS 14 new test methods across 2 commit(s)
                         NEW PASS NEW_TESTS 12 distinct new test methods across 2 commit(s)
r6-worktree-rename       OLD PASS NEW_TESTS 37 new test methods across 2 commit(s)
                         NEW PASS NEW_TESTS 17 distinct new test methods across 2 commit(s)
artifact-completion      OLD PASS NEW_TESTS 14 new test methods across 3 commit(s)
                         NEW PASS NEW_TESTS 12 distinct new test methods across 3 commit(s)
e2b                      OLD PASS NEW_TESTS 65 new test methods across 1 commit(s)
                         NEW PASS NEW_TESTS 63 distinct new test methods across 1 commit(s)
fable                    OLD PASS NEW_TESTS 50 new test methods across 2 commit(s)
                         NEW PASS NEW_TESTS 48 distinct new test methods across 2 commit(s)
c52                      OLD PASS NEW_TESTS 42 new test methods across 1 commit(s)
                         NEW PASS NEW_TESTS 41 distinct new test methods across 1 commit(s)
c54                      OLD PASS NEW_TESTS 42 new test methods across 1 commit(s)
                         NEW PASS NEW_TESTS 41 distinct new test methods across 1 commit(s)
strands                  OLD PASS NEW_TESTS 32 new test methods across 2 commit(s)
                         NEW PASS NEW_TESTS 31 distinct new test methods across 2 commit(s)
orphan-adoption          OLD PASS NEW_TESTS 1 new test methods across 1 commit(s)
                         NEW FAIL NEW_TESTS 0
```

The **verdict** only moves for `orphan-adoption` (the `NEW_TESTS` check
itself flips from PASS to FAIL). Every other slice keeps the same
`NEW_TESTS` verdict; `artifact-completion` moves from FAIL to PASS, but
because of `REPORT_NUMBERS` (R6-12), not because of the count.

### 3.2 The biggest discrepancy: `r6-check-accuracy`, 58 → 20

Its two commits are `f572f004` (the conformance test) and `0b1e48e7`
(the design doc). The OLD counter:

```
$ git show f572f004 | grep -c '^\+.*def test_'
38
$ git show 0b1e48e7 | grep -c '^\+.*def test_'
20
$ # 38 + 20 = 58
```

The NEW counter:

```
$ for h in f572f004 0b1e48e7; do git show $h \
    | grep -oE '^[+][[:space:]]*(async[[:space:]]+)?def[[:space:]]+test_[A-Za-z0-9_]*' \
    | sed -E 's/^[+][[:space:]]*(async[[:space:]]+)?def[[:space:]]+//'; done | sort -u | wc -l
20
```

The 38 lines of the first commit that the OLD pattern matched and the
NEW one does not — grouped by mechanism:

**Mechanism 1 — a method body (or a doc) that quotes `def test_`:**

```
+  (``grep -c '^\\+.*def test_'``), not distinct **method names**.  One
+DEFECTIVE_BRE_PATTERN = r"^\+.*def test_"
+            "+def test_alpha():\n"
+            "+    # def test_alpha():  <- a second added line matching the pattern\n"
+            "+def test_alpha():\n"
+            "+def test_beta():\n"
+        self.sb.write("tests/test_x.py", "def test_alpha():\n    assert True\n")
+            "def test_alpha():\n    assert True\n\n\ndef test_alpha():\n    assert True\n",
+            "def test_alpha():\n    assert True\n\n\ndef test_beta():\n    assert True\n",
+            "def test_alpha():\n    assert True\n\n\n"
+            "def test_beta():\n    assert True\n\n\n"
+            "def test_alpha():\n    assert True\n",
+        "+def test_alpha\n"
+        "+    def test_beta(self):\n"
+        "+    async def test_gamma(self):\n"
+        "+    # def test_delta(self):\n"
+        self.assertNotIn("grep -c '^\\+.*def test_'", code)
+        self.assertIn("grep -c '^\\+.*def test_'", text)
```

**Mechanism 3 — prose inside the design doc (the second commit, 20 lines):**

```
+  NTEST=$((NTEST + $(git -C "$REPO" show "$h" 2>/dev/null | grep -c '^\+.*def test_' || true)))
+  #     grep -c '^\+.*def test_'
+  (``grep -c '^\\+.*def test_'``), not distinct **method names**.  One
+  ``grep -c '^\\+.*def test_'`` is a **BRE** pattern using `\+`, which is a GNU
+  echo "commit $h -> $(git show $h | grep -c '^\+.*def test_')"
+  repository currently has none (`git log -p | grep -c '^\+.*async def test_'`
+$ ARGV0=ugrep <claude> -G -c '^\+.*def test_' file
+$ echo x | grep -c '^\+.*def test_'
+(?m)^+.*def test_
+1. a method split across several added lines that each match `^\+.*def test_`
+DEFECTIVE_BRE_PATTERN = r"^\+.*def test_"
+Every other slice's number is unchanged: its added `def test_` lines are all
+The old pattern `^\+.*def test_` matched that prose line because it ends in
+`` `git show HEAD:...|grep -c 'def test_'` returns 0 ``. The patched pattern
+`def test_...` lines can ever be attributed to a real slice.
+`def test_` inside a generated mutant:
+`grep -c '^\+.*def test_'` is a **BRE** pattern using `\+`, which is a GNU
+requires the line to **be** a `def test_<name>` definition, so the prose line
+| `judge-hygiene` | 20 | **17** | three added lines *quote* a `def test_` inside a generated mutant |
```

Of the 57 **unique** lines the OLD pattern matched across both commits,
**20** are real `def test_<name>` signatures and **37** are prose,
quoted source, or a generated mutant — the exact three mechanisms of
§1.2.

The **20 distinct names** the NEW counter reports:

```
test_a_defect_1_the_old_extraction_missed_the_rename
test_a_rename_line_yields_the_new_path
test_b_modified_line_yields_its_path
test_c_untracked_line_yields_its_path
test_d_added_line_yields_its_path
test_e_a_method_is_counted_once_even_when_two_lines_match
test_e_two_different_methods_count_as_two
test_f_defect_2_the_old_count_overstated_the_true_number
test_f_the_same_method_in_two_commits_counts_once
test_g_the_old_pattern_is_rejected_by_ugrep
test_g_the_old_pattern_still_works_under_gnu_grep
test_g_the_patched_pattern_is_accepted_by_both_engines
test_h_the_check_output_format_is_unchanged
test_h_the_exit_codes_are_unchanged
test_h_the_new_tests_threshold_stays_at_one
test_h_the_patched_referee_installs_the_two_fixed_expressions
test_h_the_referee_still_has_twelve_checks_with_the_same_names
test_h_the_total_denominator_is_still_pass_plus_fail
test_i_the_design_doc_exists_and_records_the_before_after_table
test_i_the_design_doc_states_the_threshold_stays_at_one
```

**Note on mechanism 2** (the same name in two commits): for
`r6-check-accuracy` it does not apply — the two commits share **no**
name (`uniq -d` over the two name sets is empty). The first commit
contributes all 20 names; the second (a design-doc commit) contributes
**zero** names but **20** prose lines. Mechanism 2 is exercised by
`r6-worktree-rename` (37 → 17) and by the dedicated conformance test
`test_c_same_method_name_in_two_commits_counts_once`.

---

## 4. The full old-vs-new verdict table

Every slice with a `b173-<slug>.files` manifest was run through **both**
referees, once. `OLD` = the live `/home/muse-newapi/b173-accept.sh`;
`NEW` = the integrated copy.

**Population: 83 slices** (`ls /home/muse-newapi/b173-*.files | wc -l` →
83). The task book says "72 on 2026-11-15"; the population grew because
more slices landed since the background was written. The counts are
therefore reported for the **83-slice population measured here**, and the
task book's numbers are not reproduced.

| | OLD | NEW |
|---|---|---|
| **PASS** | **52** | **54** |
| **FAIL** | **31** | **29** |

**Net change: +2 PASS / −2 FAIL.** Four slices changed verdict; every
change is attributed in §5.

The two-column table (also saved verbatim as
`/home/muse-newapi/b173-r6-test-count-verdicts.tsv`):

| slice | OLD | NEW |
|---|---|---|
| `acceptance-conformance` | FAIL | FAIL |
| `actionable-digest` | PASS | PASS |
| `agent-handoff` | PASS | PASS |
| `ageofagents` | PASS | PASS |
| `anthropic-effort-scaling` | PASS | PASS |
| `artifact-completion` | FAIL | **PASS** |
| `asinhhc` | PASS | PASS |
| `audit-head` | FAIL | FAIL |
| `autogen-speaker-selector` | PASS | PASS |
| `baseline-attribution` | PASS | PASS |
| `c52` | FAIL | FAIL |
| `c54` | FAIL | FAIL |
| `c58` | FAIL | FAIL |
| `capability-ceiling-probe` | PASS | **FAIL** |
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
| `r6-12-session-resolution` | FAIL | **PASS** |
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
| `tombstone` | FAIL | **PASS** |
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

## 5. Per-change attribution

Every slice whose **verdict or check line** changed, with the exact check
and the exact cause. The full diff of check verdicts (not only the
overall verdict) covers **8** slices; the other 75 slices are
byte-identical in every check line.

| slice | check | old | new | cause |
|---|---|---|---|---|
| `artifact-completion` | `REPORT_NUMBERS` | `FAIL REPORT_NUMBERS see detail above` | `PASS REPORT_NUMBERS jsonl=3c2b6040-….jsonl` | **R6-12** — the old `grep -rl <canary> … \| head -n1` picked the wrong session; the deterministic resolver picks the right one, so the numbers now cross-check |
| `r6-12-session-resolution` | `REPORT_NUMBERS` | `FAIL REPORT_NUMBERS see detail above` | `SKIP REPORT_NUMBERS no session resolved for canary iOgF8SrRoZvaqxTG7HFg` | **R6-12** — the resolver finds **no** session for this canary; `SKIP` is the honest answer ("no session / ambiguous"), never a guess |
| `tombstone` | `REPORT_NUMBERS` | `FAIL REPORT_NUMBERS see detail above` | `SKIP REPORT_NUMBERS no session resolved for canary 9lULp0MNufmuQZ6OGlNL` | **R6-12** — same: no session resolved, `SKIP` |
| `anthropic-effort-scaling` | `REPORT_NUMBERS` | `PASS REPORT_NUMBERS jsonl=1584ff04-….jsonl` | `SKIP REPORT_NUMBERS ambiguous session for canary WpEwcNwoMwHA9VLDmkcM -- not guessed` | **R6-12** — the old pick was a coin flip; the resolver reports **AMBIGUOUS** and refuses to guess. The slice's overall verdict is unchanged (PASS) |
| `r6-baseline-unify` | `REPORT_NUMBERS` | `PASS REPORT_NUMBERS jsonl=1584ff04-….jsonl` | `SKIP REPORT_NUMBERS no session resolved for canary iTQaVDBjY6YkvNAkfB8Y` | **R6-12** — the old pick was a coin flip onto a foreign session; the resolver finds none. Verdict unchanged (FAIL) |
| `acceptance-conformance` | `COMMIT` | `PASS COMMIT c08a86ad (1 commit(s))` | `FAIL COMMIT none; manifest: docs/design/acceptance-conformance.md: missing` | **R6-1b/R6-4** — the manifest names `docs/design/acceptance-conformance.md`, which is **not in the tree**; the attribution gate now refuses the borrowed commit |
| `acceptance-conformance` | `REPORT_NUMBERS` | `PASS REPORT_NUMBERS jsonl=2d469aa9-….jsonl` | `FAIL REPORT_NUMBERS see detail above` | **R6-12** — the deterministic resolver now picks a session whose numbers do **not** match the report, so the cross-check correctly fails. Verdict unchanged (FAIL) |
| `capability-ceiling-probe` | `COMMIT` | `PASS COMMIT 4e5a9657 (1 commit(s))` | `FAIL COMMIT none` | **R6-1b/R6-4** — the slice owns **no** commit whose subject is `B173 capability-ceiling-probe:`. The old referee borrowed `4e5a9657` (`B173 scorer-disagreement: …`) because that commit happened to touch a path in the manifest. The patched `COMMIT` refuses to borrow another slice's commit |
| `orphan-adoption` | `NEW_TESTS` | `PASS NEW_TESTS 1 new test methods across 1 commit(s)` | `FAIL NEW_TESTS 0` | **R6-7** — the slice wrote **zero** lines of test code; the old counter counted one **prose** line. See §6 |

`capability-ceiling-probe` is the one slice whose **verdict** gets
**worse**. It was crediting another slice's commit; the patch exposes
that. This is correct.

The `NEW_TESTS` **count** changes for 14 slices (§3.1) but the
`NEW_TESTS` **verdict** changes for exactly **one** — `orphan-adoption`.

---

## 6. `orphan-adoption`: the slice that wrote no test code at all

This is the case that proves the new counter is right, and the only
verdict flip caused by R6-7.

### 6.1 The commit adds two markdown documents and nothing else

```
$ git show --name-only --format= 53640d0e
docs/design/annotation-pin.md
docs/design/orphan-adoption.md
```

No `.py` file, no test file. The slice wrote **zero** lines of test code.

### 6.2 The offending line is prose inside a markdown table

```
$ git show 53640d0e | grep -c '^\+.*def test_'
1

$ git show 53640d0e | grep -n '^\+.*def test_'
122:+| 1 | `tests/test_revision_checked_tool_results.py` | 6 new test methods (`test_result_as_dict_carries_the_schema_pin`, `test_with_result_revision_returns_a_copy_and_leaves_the_original`, `test_with_result_revision_validates_its_argument`, `test_evidence_entries_lists_retained_results_in_order`, `test_outcome_record_names_both_revisions_and_the_verdict`, `test_ledger_records_every_outcome_in_order`) | **keep** | Each method asserts behaviour that HEAD does not have: `git show HEAD:...|grep -c 'def test_'` returns 0 for all six names. They cover the schema pin on `as_dict`, ...
```

The six names it mentions belong to **another** slice
(`revision-checked-tool-results`), and the prose itself quotes
`grep -c 'def test_'` — which is why the old `grep` matched it. The old
pattern only requires that the line **starts** with `+`; a markdown
table row starts with `+|` and matches `^\+.*def test_` just as well.

### 6.3 The two verdicts

| | old | new |
|---|---|---|
| `NEW_TESTS` | `PASS NEW_TESTS 1 new test methods across 1 commit(s)` | `FAIL NEW_TESTS 0` |
| slice verdict | `ACCEPT: FAIL (8/11, 1 skipped)` | `ACCEPT: FAIL (7/11, 1 skipped)` |

The slice's overall verdict does **not** change — it was already FAIL for
unrelated reasons (its canary does not match its report, and its report
has no full-suite statement and no `161/169`) — but the **check** is now
honest: **this slice really wrote zero lines of test code**, and the
referee says so.

The new pattern finds nothing in that diff:

```
$ git show 53640d0e | grep -oE '^[+][[:space:]]*(async[[:space:]]+)?def[[:space:]]+test_[A-Za-z0-9_]*' | wc -l
0
```

This case is locked in by the regression test
`test_d_prose_mention_in_markdown_is_not_a_test_method` in
`components/northstar-agent-runtime/tests/test_r6_test_count.py`.

---

## 7. Grep-engine portability

### 7.1 The two engines, identified explicitly

```
$ bash -c 'grep --version' | head -1
grep (GNU grep) 3.12
$ bash -c 'command -v grep'
/usr/bin/grep
```

```
$ grep --version | head -1
ugrep 7.8.4 aarch64-unknown-linux-gnu +neon/AArch64; -P:pcre2jit; ...
$ type grep
grep is a function
```

The **script** context (`bash -c`, and therefore every `#!/bin/bash`
script and every `bash script.sh`) gets **GNU grep 3.12** from
`/usr/bin/grep`. The **interactive** shell's `grep` is a **function**
installed by the Claude Code shell snapshot
(`~/.claude/shell-snapshots/snapshot-bash-*.sh`) that shadows
`/usr/bin/grep` with the **embedded ugrep 7.8.4**:

```bash
function grep {
  ...
  (exec -a ugrep "$_cc_bin" -G --ignore-files --hidden -I --exclude-dir=.git ... ${1+"$@"})
}
```

### 7.2 The OLD pattern fails under ugrep

```
$ grep -c '^\+.*def test_' /tmp/b173-r6-test-count/old.txt
ugrep: error: error at position 5
(?m)^+.*def test_
     \___invalid syntax

rc=2
```

`rc=2` — the pattern is **rejected outright**, not merely unmatched. The
same pattern under GNU grep:

```
$ bash -c "grep -c '^\+.*def test_' /tmp/b173-r6-test-count/old.txt"
2
rc=0
```

GNU grep accepts `\+` as the GNU-specific BRE "one or more" escape;
ugrep compiles the pattern with its Rust regex engine, which reads `\+`
as a **literal** `+` and then rejects the character class `^+` as an
invalid "nested set". That is why the bug survived: the referee is a
script, so it always ran under GNU grep.

### 7.3 The NEW pattern works under both

```
$ grep -oE '^[+][[:space:]]*(async[[:space:]]+)?def[[:space:]]+test_[A-Za-z0-9_]*' /tmp/b173-r6-test-count/old.txt
+    def test_alpha
+    async def test_beta
rc=0

$ bash -c "grep -oE '^[+][[:space:]]*(async[[:space:]]+)?def[[:space:]]+test_[A-Za-z0-9_]*' /tmp/b173-r6-test-count/old.txt"
+    def test_alpha
+    async def test_beta
rc=0
```

Both engines produce **identical output** and `rc=0`. The literal `+`
is spelled as the bracket expression `[+]`, which both engines parse
the same way.

The conformance test `test_f_pattern_is_accepted_by_gnu_grep_and_ugrep`
asserts this on every run: the NEW pattern parses under GNU grep **and**
under the embedded ugrep, the OLD pattern is **rejected** by ugrep with
`invalid syntax`, and the OLD pattern still **works** under GNU grep
(that is why the bug survived).

---

## 8. Determinism, denominator, format and exit codes

### 8.1 Determinism

The integrated referee was run **3 times** on **8** slices whose verdict
or check line changed. The `ACCEPT:` line was **identical** all three
times in every case:

```
IDENTICAL  r6-check-accuracy              ACCEPT: PASS (11/11, 1 skipped) r6-check-accuracy
IDENTICAL  judge-hygiene                  ACCEPT: PASS (11/11, 1 skipped) judge-hygiene
IDENTICAL  r6-manifest-integrity          ACCEPT: PASS (11/11, 1 skipped) r6-manifest-integrity
IDENTICAL  step-reliability-budget       ACCEPT: PASS (12/12, 0 skipped) step-reliability-budget
IDENTICAL  orphan-adoption                ACCEPT: FAIL (7/11, 1 skipped) orphan-adoption
IDENTICAL  artifact-completion            ACCEPT: PASS (11/11, 1 skipped) artifact-completion
IDENTICAL  r6-worktree-rename             ACCEPT: FAIL (10/11, 1 skipped) r6-worktree-rename
IDENTICAL  r6-baseline-unify              ACCEPT: FAIL (9/10, 2 skipped) r6-baseline-unify
```

### 8.2 The denominator is intact

```
$ grep -oE 'check [A-Z_]+ (PASS|FAIL|SKIP)' /home/muse-newapi/b173-accept.sh | awk '{print $2}' | sort -u | wc -l
12
$ grep -oE 'check [A-Z_]+ (PASS|FAIL|SKIP)' accept.sh | awk '{print $2}' | sort -u | wc -l
12
```

The **same 12 names**, live and integrated:

```
BENCH BENCH_DIFF CANARY COMMIT FABLE_VERIF FULL_SUITE MUTANT NEW_TESTS REPORT REPORT_NUMBERS TESTS_RAN WORKTREE_CLEAN
```

### 8.3 The output format is unchanged

The `check()` function is **byte-identical** between the live file and
the integrated copy:

```
$ diff <(sed -n '/^check() {/,/^}/p' /home/muse-newapi/b173-accept.sh) \
       <(sed -n '/^check() {/,/^}/p' accept.sh) && echo "IDENTICAL check() body"
IDENTICAL check() body
```

and the three line shapes are unchanged:

```
PASS <name> <detail>
FAIL <name> <detail>
SKIP <name> <detail>
```

(the `check()` body dispatches on the verdict word and echoes
`"$name $detail"` in all three branches).

### 8.4 The exit codes are unchanged

```
$ grep -n 'exit 0;\|exit 1;' /home/muse-newapi/b173-accept.sh
197:TOTAL=$((PASS+FAIL))
198:if [ "$FAIL" -eq 0 ]; then echo "ACCEPT: PASS ($PASS/$TOTAL, $SKIP skipped) $SLUG"; exit 0;
199:else echo "ACCEPT: FAIL ($PASS/$TOTAL, $SKIP skipped) $SLUG"; exit 1; fi

$ grep -n 'exit 0;\|exit 1;' accept.sh
314:TOTAL=$((PASS+FAIL))
315:if [ "$FAIL" -eq 0 ]; then echo "ACCEPT: PASS ($PASS/$TOTAL, $SKIP skipped) $SLUG"; exit 0;
316:else echo "ACCEPT: FAIL ($PASS/$TOTAL, $SKIP skipped) $SLUG"; exit 1; fi
```

Measured:

```
$ bash accept.sh r6-check-accuracy >/dev/null 2>&1; echo $?
0
$ bash accept.sh orphan-adoption  >/dev/null 2>&1; echo $?
1
$ bash /home/muse-newapi/b173-accept.sh r6-check-accuracy >/dev/null 2>&1; echo $?
0
$ bash /home/muse-newapi/b173-accept.sh orphan-adoption  >/dev/null 2>&1; echo $?
1
```

`0 = ACCEPT PASS`, `1 = ACCEPT FAIL`, identical live and integrated.

### 8.5 The threshold was NOT raised

```
$ grep -n 'NTEST.*-ge' accept.sh
175:  [ "$NTEST" -ge 1 ] && check NEW_TESTS PASS "$NTEST distinct new test methods across $NCOMMITS commit(s)" || check NEW_TESTS FAIL "$NTEST"
```

**1**, in the integrated copy and in the live file. This slice did not
change it and must not.

---

## 9. Threshold decision input for the coordinator

This is the slice's namesake deliverable. Measured with the integrated
referee and the **new** distinct-name rule over the **83-slice**
population.

### 9.1 The counts

| | slices |
|---|---|
| **≥ 9** distinct new test methods | **75** |
| **< 9** distinct new test methods | **8** |

(The eighth `<9` slice is `r6-test-count` — this slice — which had no
commit of its own when the batch was run, so the referee emitted **no**
`NEW_TESTS` verdict for it at all; it is counted as `<9` because it
cannot be shown to have ≥ 9.  Its own count is 12, see §9.3.  The other
seven `<9` slices are listed below.)

### 9.2 Every slice with < 9, with its count and its current verdict

| slice | distinct count | current `ACCEPT:` verdict |
|---|---|---|
| `mutant-evidence-closure` | 0 | `ACCEPT: FAIL (8/11, 1 skipped)` |
| `orphan-adoption` | 0 | `ACCEPT: FAIL (7/11, 1 skipped)` |
| `runtime-registration-closure` | 0 | `ACCEPT: FAIL (7/11, 1 skipped)` |
| `slice1` | 7 | `ACCEPT: FAIL (10/11, 1 skipped)` |
| `slice2` | 2 | `ACCEPT: FAIL (9/11, 1 skipped)` |
| `slice3` | 3 | `ACCEPT: FAIL (10/11, 1 skipped)` |
| `slice4` | 0 | `ACCEPT: FAIL (8/10, 2 skipped)` |
| `r6-test-count` (this slice) | 12 | — (see §9.3) |

### 9.3 How many currently-PASS slices would flip to FAIL

**ZERO.**

Every slice with fewer than 9 distinct new test methods is **already
FAIL** on the integrated referee. Raising the threshold from 1 to 9
would therefore:

* change **no** verdict of any currently-PASS slice;
* change the `NEW_TESTS` check line of the three zero-count slices
  (`mutant-evidence-closure`, `orphan-adoption`,
  `runtime-registration-closure`) — from `FAIL NEW_TESTS 0` to
  `FAIL NEW_TESTS 0` (no change: they already fail the check);
* change the `NEW_TESTS` check line of `slice1` (7), `slice2` (2) and
  `slice3` (3) from `PASS NEW_TESTS 7/2/3` to `FAIL NEW_TESTS 7/2/3`
  — these three slices would lose one check each, but their overall
  verdict is **already FAIL**, so no verdict changes.

**This slice's own count is 12** (twelve test methods in
`tests/test_r6_test_count.py`), so it would also be unaffected by a
threshold of 9.

### 9.4 Comparison with the task book's background numbers

The background measured this on 2026-11-15 over a **72-slice**
population and reported "69 have ≥ 9, 3 have < 9". This slice measured
**83 slices** and found **75 ≥ 9, 8 < 9**. The difference is
**population size**, not behaviour: the extra slices are
`slice1`–`slice4` (2, 3, 0 and 7 methods — all FAIL) plus this slice
and the other round-6 slices that landed after the background was
written.

The background's **key claim is reproduced exactly**: the three slices
it names — `mutant-evidence-closure` (0), `orphan-adoption` (0),
`runtime-registration-closure` (0) — are the three zero-count slices
here as well, and **all three are already FAIL**. So **0**
currently-PASS slices would flip, and raising the threshold to 9 is
**free** in the sense that it changes no verdict that is currently PASS.

The background's "net +1 PASS" and this slice's "+2 PASS" likewise
differ by population, not by behaviour (§4).

### 9.5 Why the threshold must be a separate, independently
rollback-able change

* The patches change **how** the number is computed. The threshold
  changes **how many** are required. They are different lines, in
  different places, with different blast radii.
* The threshold change would rewrite the **verdicts already written
  into the acceptance ledger**; that is a ledger re-run, not a code
  change, and it must be able to be rolled back on its own.
* Raising the threshold to 9 in the same commit as the pattern change
  would make it impossible to tell "the counter was wrong" from "the
  bar was raised".

**Recommendation**: land the three patches first (this round), then
decide the threshold in the next round, as its own change with its own
ledger re-run. The number the decision needs is in §9.1–§9.3.

---

## 10. The exact application order for the coordinator

```
cp -p /home/muse-newapi/b173-accept.sh /home/muse-newapi/b173-accept.sh.pre-r6
cd /home/muse-newapi

patch -p0 b173-accept.sh < b173-r6-manifest-integrity-fix.patch
patch -p0 b173-accept.sh < b173-r6-check-accuracy-fix.patch
patch -p0 b173-accept.sh < b173-r6-12-session-resolution-fix.patch

bash -n b173-accept.sh
```

**This exact order is required.** The manifest-integrity patch adds ~70
lines above the check-accuracy hunk, and the check-accuracy patch adds
~28 lines above the session-resolution hunks; applying them in any other
order produces hunks that do not apply cleanly.

Expected output (measured on the copy in §2):

```
patching file b173-accept.sh
patching file b173-accept.sh
Hunk #1 succeeded at 151 (offset 71 lines).
patching file b173-accept.sh
Hunk #1 succeeded at 262 (offset 99 lines).
Hunk #2 succeeded at 288 (offset 99 lines).
```

> **⚠️ `b173-r6-12-watch-session-resolution-fix.patch` targets
> `b173-watch.sh`, NOT `b173-accept.sh`.** Installing it on the referee
> was measured to conflict. The session-resolution patch that belongs on
> the referee is `b173-r6-12-session-resolution-fix.patch` (the one used
> above).

If the coordinator wants the threshold change, it is **one line** in the
same file, and it must be a **separate** change:

```bash
# in the NEW_TESTS check, after the patches are applied:
-  [ "$NTEST" -ge 1 ] && check NEW_TESTS PASS ...
+  [ "$NTEST" -ge 9 ] && check NEW_TESTS PASS ...
```

---

## 11. What this slice did NOT do

* It did **not** edit the live `/home/muse-newapi/b173-accept.sh`.
* It did **not** raise the threshold.
* It did **not** add any runtime `.py` module — only a test file and
  this document — so no packaging registration is needed
  (`tests/test_*.py` is excluded from `modules_on_disk()` by the
  `not path.name.startswith("test_")` filter, and the registry,
  `pyproject.toml`'s `py-modules` and the disk all agree at 1612 /
  1612 / 1613 — the one extra file on disk is
  `merged_tree_review.py`, which belongs to the `merged-tree-review`
  slice and is documented in the report's OPEN section).
* It did **not** touch `tool_use.py`, `tool_failure.py`, `sessions.py`,
  `checkpoints.py`, `compaction.py`, `durable_resume.py`,
  `long_horizon.py`, `blind_rerunner.py`, `audit_head_holder.py`,
  `context_budget.py`, `ledger.py`, `forward_seal_ledger.py`,
  `sealed_audit_sink.py`, `grant_pin_ledger.py`, `permissions.py`, or
  anything under `components/northstar-agent-interop/`.
* It did **not** push, merge, tag, publish or change a version.


