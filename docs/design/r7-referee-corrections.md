# b173 round 7 — referee corrections: the NEW_TESTS threshold and the TESTS_RAN module list

**Date**: 2026-11-16
**Branch**: `batch-173-moltbook-absorb`
**Scope**: the referee scripts under `/home/muse-newapi/` (`b173-accept.sh`) and the
conformance tests that pin their behaviour. No runtime module is added by this
round; the round adds two test files and changes the referee.

---

## 0. Why this round exists

Round 6 landed six patches on the referee and the batch verdict went from
`PASS=53 FAIL=23` to `PASS=69 FAIL=7`. Two defects survived that round, both
of them **false FAILs** — the referee convicting a slice for something that
was not the slice's doing.

This round closes them. It also closes a hole that round 6 opened: a slice
that promised ≥9 new test methods in its taskbook but delivered 0 was
PASSing, because the judge only demanded ≥1.

---

## 1. Defect 1 — `TESTS_RAN` ran the wrong tests (repo-root-level test files)

### 1.1 The measurement

```
$ bash b173-accept.sh seal-slice6
FAIL TESTS_RAN  [tests unittest: Ran 138 tests in 14.113s FAILED (failures=4) ]
```

`seal-slice6`'s own test file is `tests/test_delivery_seal.py` — a
**repo-root-level** test file, not one under `components/<c>/tests/`. Run
directly it passes:

```
$ cd northstar-agent-os && PYTHONPATH=.:tests python3 -m unittest test_delivery_seal
Ran 37 tests in 2.473s
OK
```

So the four failures belong to four **unrelated** test files:

```
FAIL: test_northstar_delivered_patch_passes_clean_fixture_evaluation (test_code_task_pack...)
FAIL: test_committed_api_pages_match_docstring_generation (test_docbuild...)
FAIL: test_every_public_module_is_documented_or_deliberately_excluded (test_docbuild...)
FAIL: test_panel_renders_the_full_record_vocabulary (test_observability_examples...)
```

### 1.2 Root cause — two bugs compounding

`b173-accept.sh`, TESTS_RAN block:

```bash
for compdir in $(echo "$ADDED_TESTS" | xargs -n1 dirname | sed 's|/tests$||' | sort -u); do
  MODS=$(echo "$ADDED_TESTS" | grep "^$compdir/tests/" | ... )
```

1. `sed 's|/tests$||'` strips a trailing `/tests`. A repo-root-level test
   directory is the bare string `tests` — there is no leading slash for the
   pattern `/tests$` to match — so `compdir` stays `tests`.
2. The per-file lookup then greps `"^$compdir/tests/"`, i.e. `"^tests/tests/"`,
   which matches **nothing** for a repo-root-level file.

With `MODS` empty, `python3 -m unittest` is invoked with **no module
arguments**, and unittest then falls back to **discovery**: it runs every test
in `tests/` (138 at the time of measurement) and reports their failures as the
slice's.

> The slice was convicted by 138 tests it never wrote. 101 of those passed and
> 4 failed, and the 4 belonged to other files entirely.

### 1.3 The fix

Group each test file by the directory that **contains it**, and take the
module names from the files in that group:

```bash
for compdir in $(echo "$ADDED_TESTS" | xargs -n1 dirname | sort -u); do
  MODS=$(echo "$ADDED_TESTS" | awk -v d="$compdir/" 'index($0, d) == 1 {n = $0; sub(/.*\//, "", n); sub(/\.py$/, "", n); print n}' | tr '\n' ' ')
  TFILES=$(echo "$ADDED_TESTS" | awk -v d="$compdir/" 'index($0, d) == 1 {print substr($0, length(d) + 1)}' | tr '\n' ' ')
  if [ -z "$(echo "$MODS" | tr -d '[:space:]')" ]; then
    RAN_DETAIL="$RAN_DETAIL [$compdir unittest: SKIPPED empty module list]"
    continue
  fi
  ...
```

Both shapes (`tests/` and `components/<c>/tests/`) now work, and a group with
an empty module list is **skipped and reported**, never silently handed to
unittest — so discovery can never be reached by accident again.

### 1.4 The test

`components/northstar-agent-runtime/tests/test_r7_tests_ran_compdir.py`
(4 methods). It is **behavioural, not textual**: it extracts the referee's
*own* `compdir`/`MODS`/`TFILES` computation out of the live
`b173-accept.sh` and *runs* it against three inputs. A comment that merely
mentions the right words cannot satisfy it.

RED (against the pre-fix referee) — 4 failures:

```
FAIL: test_a_mixed_set_yields_every_module_and_none_other
FAIL: test_a_repo_root_level_test_file_yields_its_module_name
FAIL: test_the_module_list_is_never_empty_for_a_non_empty_test_set (path='tests/test_delivery_seal.py')
FAIL: test_the_module_list_is_never_empty_for_a_non_empty_test_set (path='tests/docbuild.py')
```

The failure reason is the right one: `module list is EMPTY for
tests/test_delivery_seal.py -- unittest would then discover the whole
directory`.

GREEN (after the fix) — `Ran 4 tests ... OK`.

**RED was verified against a reverted referee**, not assumed: the pre-fix
block was restored in place, the test was re-run (4 failures), and the fixed
referee was restored.

### 1.5 Effect

```
$ bash b173-accept.sh seal-slice6
PASS TESTS_RAN  [tests unittest: Ran 37 tests in 2.040s OK ]
ACCEPT: PASS (9/9, 3 skipped) seal-slice6
```

---

## 2. Defect 2 — the `NEW_TESTS` threshold was 1; the taskbook contract says 9

### 2.1 The contract

`b173-taskbook-template.md` line 104:

> 约束：工作目录仓库根，分支 batch-173-moltbook-absorb；**≥9 个新测试方法**。

Every slice's taskbook carries that line. The judge checked `>= 1`.

### 2.2 Why the round-6 slice deliberately left it at 1

`r6-check-accuracy` was scoped to fix the *counting rule* (distinct method
names, not diff lines), and its taskbook explicitly deferred the threshold:

> **THRESHOLD STAYS 1**: raising it to the taskbook's 9 is a separate
> coordinator decision (it would make every already-accepted slice fail on a
> technicality).

It also had to *assert* that, because "the threshold stays at 1" was part of
its own contract. So the deferral was recorded as a test.

### 2.3 The measurement that made the decision free

Measured with the corrected distinct-name counter across the whole batch:

```
distinct new test methods >= 9 :  69 slices
distinct new test methods <  9 :   7 slices
```

**All 7 of the sub-9 slices were already FAIL for another reason.** Raising
the threshold therefore flips **0 currently-PASS slices** — the cost that
concerned the round-6 slice does not exist.

### 2.4 The decision, and this round's test change

The threshold is raised to 9. `r6-check-accuracy`'s test
`test_h_the_new_tests_threshold_stays_at_one` asserted the opposite, so it
had to change — from asserting a *deferral* to asserting the *contract*:

```python
def test_h_the_new_tests_threshold_matches_the_taskbook_contract(self):
    text = self.patched.read_text(encoding="utf-8")
    self.assertIn('[ "$NTEST" -ge 9 ]', text)
    self.assertNotIn('[ "$NTEST" -ge 1 ]', text)
```

The counting **rule** is unchanged — that was round 6's work and it stands.

### 2.5 The test

`components/northstar-agent-runtime/tests/test_r7_new_tests_threshold.py`
(1 method). Written first, watched fail, then the referee was changed.

RED:

```
AssertionError: 9 != 1 : the NEW_TESTS threshold is 1, but the taskbook
contract (b173-taskbook-template.md line 104) requires at least 9 new test
methods
```

GREEN after the one-line change in `b173-accept.sh`.

### 2.6 The three slices that now correctly fail

| slice | distinct new test methods | what its taskbook promised |
|---|---|---|
| `mutant-evidence-closure` | 0 | "New test methods **≥18**" |
| `orphan-adoption` | 0 | "bring the total number of NEW test methods … to **≥ 9**" |
| `runtime-registration-closure` | 0 | "Write tests … (**≥9 new methods**)" |

These are **real gaps**, not legitimate zeros: all three taskbooks explicitly
promise test methods, and all three delivered a documentation-only commit.
The threshold now says so.

---

## 3. Full-suite verification

Run after the change, from the repo root, `make test`:

```
Ran 21212 tests in 239.194s
```

Failure set diffed **item by item** against the previous recorded run
(`/home/muse-newapi/b173-r7-suite.log`, 32 failures/errors):

```
new failures introduced by this round : 0
failures that disappeared              : 2
  FAIL: test_every_injected_block_is_booked_in_the_memory_tax (test_context_budget_skills_memory...)
  FAIL: test_the_total_skill_budget_drops_the_surplus_and_says_so (test_context_budget_skills_memory...)
```

The two that disappeared are the known `/tmp` residue failures documented in
the taskbooks (the full suite leaves ~86,000 `nsar-*` directories; a full
tmpfs makes those cases report `Errno 122 Disk quota exceeded`). They are
**not** caused by this round — they are flaky-on-disk-full, and the taskbook
prescribes clearing `/tmp` before the run.

Net: the failure set got **strictly smaller**, with **no new failures**.

---

## 4. Files

| file | change |
|---|---|
| `components/northstar-agent-runtime/tests/test_r7_new_tests_threshold.py` | new — pins the NEW_TESTS threshold at 9 |
| `components/northstar-agent-runtime/tests/test_r7_tests_ran_compdir.py` | new — pins the TESTS_RAN module-list behaviour |
| `components/northstar-agent-runtime/tests/test_r6_check_accuracy.py` | the deferred-threshold assertion replaced by the contract assertion |
| `docs/design/r7-referee-corrections.md` | this document |

Outside the repo (referee scripts, not committed):

| file | change |
|---|---|
| `/home/muse-newapi/b173-accept.sh` | TESTS_RAN module-list fix; NEW_TESTS threshold 1 → 9 |

---

## 5. Open items this round did NOT close

These remain FAIL and are **not** in scope for a referee correction — they are
missing work, and the round-7 measurement is the first time the judge has
been able to say so cleanly:

| slice | failing check | diagnosis |
|---|---|---|
| `acceptance-conformance` | COMMIT | its work (47 test methods) landed under `deterministic-gate-score`'s commit; `docs/design/acceptance-conformance.md` was never written |
| `capability-ceiling-probe` | COMMIT | 59 test methods + an 8.6 KB design doc, all committed under `scorer-disagreement`'s subject |
| `mutant-evidence-closure` | NEW_TESTS 0 | its three commits only *delete* test classes from other slices' files |
| `orphan-adoption` | NEW_TESTS 0 | its only commit adds two markdown docs |
| `runtime-registration-closure` | NEW_TESTS 0 | its only commit adds one design doc |

The last three are **legitimately 0 new tests** — the round-6 measurement
already called this out. The taskbooks, however, each promise ≥9 (and ≥18 for
`mutant-evidence-closure`), so the promise was broken. These three need real
test work, not a referee change.
