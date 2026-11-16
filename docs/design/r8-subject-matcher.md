# b173 round 8 — the subject matcher: a slice is held to the subject it actually wrote

**Date**: 2026-11-16
**Branch**: `batch-173-moltbook-absorb`
**Scope**: the referee scripts under `/home/muse-newapi/` and the conformance test that pins the
matcher. No runtime module is added by this round.

---

## 0. Why this round exists

Round 7 closed two false FAILs in the referee and took the batch from `PASS=75 FAIL=9` to
`PASS=80 FAIL=4`. The four remaining failures are real work. This round closes one more
**false FAIL**, found while diagnosing them:

> `slice4` was told it had written **zero** test methods, when it had written **ten**.

---

## 1. The defect

### 1.1 The measurement

```bash
$ bash b173-accept.sh slice4
FAIL NEW_TESTS 0 (threshold 1)
ACCEPT: FAIL (8/9, 3 skipped) slice4
```

But `slice4`'s work is in the branch:

```bash
$ git log --format='%h %s' -- components/northstar-agent-runtime/tests/test_alert_trigger_registry.py
4fe1ff28 B173 slice4 (part 2): check-input seal pinning + regression tests + idempotent scan

$ git show 4fe1ff28 | grep -cE '^\+.*def test_'
10
```

Ten new test methods, committed, under a subject that *names* the slice.

### 1.2 Root cause

Every place the referee looks for a slice's commits used one pattern:

```bash
git log --format=%H --grep="^B173 ${SLUG}:" -i
```

The `:` is **immediately** after the slug. The subject `B173 slice4 (part 1): ...` has a
**space** after the slug, so the pattern cannot match it.

Measured across the whole branch history (1054 commits, 82 slugs), exactly **three** commits
have a `B173 <slug>` subject this pattern cannot see:

| commit | subject | slice |
|---|---|---|
| `ffc5dfe2` | `B173 slice4 (part 1): alert trigger registry + audit-sink reader + transcript landing` | `slice4` |
| `4fe1ff28` | `B173 slice4 (part 2): check-input seal pinning + regression tests + idempotent scan` | `slice4` |
| `95038ecb` | `B173 r6-worktree-rename, r6-manifest-subject: keep the referee tests testing after the patches land` | two slices |

The first two are `slice4`'s **entire deliverable**. The third names two slices.

### 1.3 Why this is a general false-FAIL generator

This is the third time in this batch that the referee held a slice to a contract it was never
given. The pattern of all three is identical:

| defect | what the slice was promised | what the referee compared against |
|---|---|---|
| CANARY check (round 5) | a canary, if the taskbook had one | a canary, always |
| NEW_TESTS threshold (round 7) | ≥9 methods, if the taskbook said so | ≥9 methods, always |
| **subject matcher (this round)** | a commit whose subject names the slice | a commit whose subject is *exactly* `B173 <slug>:` |

> *"No comparison was possible" is not "the slice failed."*

### 1.4 A related trap: `--grep` searches the WHOLE MESSAGE

`git log --grep` matches the commit message, not just the subject. On this branch **175**
commits have a body line beginning with `B173 ` — mostly because the round-6 and round-7
commits quote earlier subjects in their bodies:

```
B173 r6-worktree-rename: name the nine-slice difference explicitly
```

Widening the pattern without checking this would let a commit be attributed to a slice on the
strength of a line in its *body*. §2.1 measures that this does not happen, but the measurement
had to be made rather than assumed.

---

## 2. The fix

### 2.1 The rule

The subject after `B173 ` names the slice. The boundary after the slug is **"a character that
is not a word character"**, not "a colon":

```
^B173 <slug>[^A-Za-z0-9_-]
```

The trailing character class excludes `-` as well as letters and digits, so `slice4` does not
match a hypothetical `B173 slice4x:`.

### 2.2 The comma-list shape

One commit may name several slices:

```
B173 r6-worktree-rename, r6-manifest-subject: keep the referee tests testing
```

so the slug may be preceded by other slugs in a comma-separated list. The BRE for that is:

```
^B173 \([^:,][^:,]*,\ \)*<slug>[^A-Za-z0-9_-]
```

`[^:,]` excludes both the comma and the colon, so the list cannot swallow the slug itself.

### 2.3 The scripts changed

| script | what changed |
|---|---|
| `b173-accept.sh` | the `--grep` pattern; **and** the `case` glob in the `OWN_HASHES` fallback, which had the same literal-colon defect |
| `b173-mutant.sh` | the `--grep` pattern |
| `b173-watch.sh` | the `--grep` pattern |
| `b173-ac-facts.py` | the `--grep` pattern |
| `b173-ac-commit-match.py` | the `--grep` pattern |
| `b173-watchdog.py` | the `--grep` pattern (3 sites) |

The `case` glob needed the comma-list shape too:

```bash
case "$csubj" in
  "b173 "*", ${slug_lc}"[^a-z0-9_-]*) OWN_HASHES="$cand"; break;;
  "b173 ${slug_lc}"[^a-z0-9_-]*) OWN_HASHES="$cand"; break;;
esac
```

### 2.4 The blast radius, measured

Every one of the 82 slugs was re-counted under the old pattern and the new one, over all 1054
commits:

```
total gains: 3 commits, in 2 slugs
  r6-worktree-rename   3 -> 4   + B173 r6-worktree-rename, r6-manifest-subject: ...
  slice4               1 -> 3   + B173 slice4 (part 1): ...
                                + B173 slice4 (part 2): ...
body-contaminated slugs (old pattern): 0
body-contaminated slugs (new pattern): 0
```

**3 gains, 0 losses, 0 contamination.** The other 80 slugs' commit sets are unchanged.

### 2.5 The batch ledger, re-run

The ledger is the instrument that catches a referee change which breaks many slices at once —
it caught two 30+-slice regressions in round 7, neither of which was visible in the diff.

```
before: PASS=75 FAIL=9   (84 slices)
after:  PASS=80 FAIL=4   (84 slices)

r6-check-accuracy             FAIL -> PASS
r7-referee-corrections        FAIL -> PASS
runtime-registration          FAIL -> PASS
runtime-registration-closure  FAIL -> PASS
slice4                        FAIL -> PASS
```

`runtime-registration` and `runtime-registration-closure` were already fixed by the
registration work (§4) and were still FAIL in the "before" column only because that ledger
predates it.

---

## 3. The test

`components/northstar-agent-runtime/tests/test_r7_subject_matcher.py` (6 methods).

It is **behavioural**: it builds a throwaway git repository with real commits and runs the
referee's own `--grep` pattern against it. A comment that merely mentions the right words
cannot satisfy it.

| test | what it pins |
|---|---|
| `test_the_referee_matches_the_slice_slug_not_a_literal_colon` | no script requires `${SLUG}:` |
| `test_a_subject_with_a_part_suffix_is_matched` | `B173 slice4 (part 1):` is found for `slice4` |
| `test_a_subject_naming_two_slugs_is_matched_by_both` | `B173 a, b:` is found for **both** |
| `test_a_slug_prefix_of_another_slug_does_not_match` | `slice4` does not match `B173 slice4x:` |
| `test_the_plain_colon_subject_is_still_matched` | the shape that already worked still works |
| `test_every_script_that_matches_slice_commits_shares_the_rule` | `accept.sh`, `mutant.sh` and `watch.sh` agree |

### 3.1 RED was verified against the pre-fix referee

The referee scripts were backed up to `*.preround8`, the fix applied, and the test run
against both:

| | before the fix | after the fix |
|---|---|---|
| `test_r7_subject_matcher.py` | **6 failures** | **OK** |

The first draft of the test asserted only the single-slug shape and passed 5 of 6 after the
first version of the fix. The sixth failure was real: the comma-list commit was still
invisible to `r6-manifest-subject`. That is what forced the comma-list shape in §2.2.

---

## 4. The registration closure (same round, separate commit)

`runtime-registration` and `runtime-registration-closure` were entangled: closing one closes
the other, because both failed on the same unregistered module.

`merged_tree_review.py` was delivered by the `merged-tree-review` slice and never registered:

```
RegistrationError: runtime module registration does not match the disk:
  module(s) on disk but not in the registry: merged_tree_review;
  module(s) on disk but not in py-modules: merged_tree_review
```

The fix is one line in each of the two views (`runtime_registration.py`'s `REGISTRY` and
`pyproject.toml`'s `py-modules`), and `tests/test_registration_closure.py` (14 methods) is the
recurrence guard.

Full suite, measured: **26** failures/errors, against **30** at the previous run — the four
that disappeared are exactly the registration failures, and no new failure appeared.

---

## 5. Files

| file | change |
|---|---|
| `components/northstar-agent-runtime/tests/test_r7_subject_matcher.py` | new — pins the subject matcher |
| `components/northstar-agent-runtime/tests/test_registration_closure.py` | new — pins the three-view registration agreement |
| `components/northstar-agent-runtime/runtime_registration.py` | one `REGISTRY` line |
| `components/northstar-agent-runtime/pyproject.toml` | one `py-modules` line |
| `docs/design/runtime-registration-closure.md` | the round-7 closure record |
| `docs/design/r8-subject-matcher.md` | this document |

Outside the repo (referee scripts, not committed):

| file | change |
|---|---|
| `b173-accept.sh` | the `--grep` pattern and the `case` glob |
| `b173-mutant.sh`, `b173-watch.sh` | the `--grep` pattern |
| `b173-ac-facts.py`, `b173-ac-commit-match.py`, `b173-watchdog.py` | the `--grep` pattern |
| `b173-accept.sh.preround8`, `b173-mutant.sh.preround8`, `b173-watch.sh.preround8` | the pre-fix backups |

---

## 6. Open items

These remain FAIL and need **real work**, not a referee change:

| slice | failing check | diagnosis |
|---|---|---|
| `acceptance-conformance` | COMMIT | its work (47 test methods) landed under `deterministic-gate-score`'s and `vina-receipt-signing`'s commits; `docs/design/acceptance-conformance.md` was never written |
| `capability-ceiling-probe` | COMMIT | 59 test methods + an 8.6 KB design doc, all committed under `scorer-disagreement`'s subject |
| `mutant-evidence-closure` | NEW_TESTS 0 | its three commits only *move* test classes between other slices' files; the taskbook promised ≥18 new methods |
| `orphan-adoption` | NEW_TESTS 0 | its only commit adds two markdown docs; the taskbook promised ≥9 new methods |
