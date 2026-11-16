# r6-manifest-integrity — make the referee check the manifest against reality

Slice: `r6-manifest-integrity` (B173, branch `batch-173-moltbook-absorb`).
Date of measurement: 2026-11-15.

## What this slice is, and what it is not

Every slice in this batch has a manifest: `/home/muse-newapi/b173-<slug>.files`
— a plain list of the paths the slice owns. Two tools read it:

- `b173-accept.sh` uses it as a **fallback** to find the slice's commit when
  the subject-prefix search finds nothing;
- `b173-mutant.sh` uses it to find **which module and which test** the
  planted-fault probe should attack.

Nothing ever checked that the manifest is *true*. Three defects follow.

**This slice does not edit `b173-accept.sh`.** The referee must not be edited
by the slice that would then be grading itself. The fix is delivered as a
unified-diff patch file
(`/home/muse-newapi/b173-r6-manifest-integrity-fix.patch`) plus this
document's precise change specification, and is verified by applying the
patch to a **copy** in `/tmp` and running the reproduction cases against
that copy. The live script is byte-identical before and after this slice.

The only in-repo additions are this document and
`components/northstar-agent-runtime/tests/test_r6_manifest_integrity.py`
(a read-only conformance test). **No runtime module is added**, so no
packaging registration (`runtime_registration.py` / `pyproject.toml`
`py-modules`) is needed.

---

## Defect 1 — the manifest names files that do not exist

### Reproduction

```bash
cd /home/muse-newapi
for m in b173-*.files; do
  out=""
  while IFS= read -r p; do
    [ -z "$p" ] && continue
    [ -e "northstar-agent-os/$p" ] || out="$out $p"
  done < "$m"
  [ -n "$out" ] && echo "${m%.files} MISSING:$out"
done
```

### Measurement on 2026-11-15 (79 manifests, 255 non-empty lines)

Only **one** manifest path is genuinely missing in the current tree:

| manifest | missing path |
|---|---|
| `b173-acceptance-conformance.files` | `docs/design/acceptance-conformance.md` |

Everything else the task book listed as missing has since been created and
committed by later slices of the same batch:

| task book's claim | current state (measured) |
|---|---|
| `components/northstar-agent-runtime/refusal_hold_wiring.py` missing | **exists and tracked** — added by `782412c0` (`B173 refusal-hold-wiring: a recorded refusal blocks the re-seal of the same grant pin, fail closed on an unusable gate`, 849 lines) |
| `components/northstar-agent-runtime/tests/test_refusal_hold_wiring.py` missing | **exists and tracked** — added by the same commit (680 lines) |
| `docs/design/refusal-hold-wiring.md` missing | **exists and tracked** |
| `docs/design/artifact-completion.md` missing | **exists and tracked** |
| `components/northstar-agent-runtime/tests/test_artifact_completion.py` missing | **exists and tracked** |
| `docs/design/baseline-attribution.md` missing | **exists and tracked** |
| `scripts/b173-baseline-check.sh` missing | **exists and tracked** |
| `components/northstar-agent-runtime/tests/test_baseline_attribution.py` missing | **exists and tracked** |
| `docs/design/mutant-evidence-closure.md` missing | **exists and tracked** |

So the defect is **real but almost fully repaired by the batch itself**; the
residue is `acceptance-conformance`'s design doc. The rule is still worth
adding, because nothing prevents the next slice from reintroducing it — and
because one stale manifest already silently costs a slice its acceptance.

### The `refusal-hold-wiring` module-name mismatch — what actually happens

The task book states the consequence is `SKIP MUTANT probe could not run`.
**Measured: that is not what the probe does.** In a sandbox with a manifest
naming a module that does not exist, `b173-mutant.sh` selects the missing
path and `b173-mutant.py` dies with an uncaught traceback:

```
mutant probe: slug=sandbox commit=a084b859 module=components/northstar-agent-runtime/mod_missing.py test=test_mod_x
Traceback (most recent call last):
  File "/home/muse-newapi/b173-mutant.py", line 111, in main
    with open(a.file, encoding="utf-8") as f:
FileNotFoundError: [Errno 2] No such file or directory: '.../mod_missing.py'
rc=1
```

The referee maps exit code 1 to `FAIL MUTANT all applied mutants survived
(tests do not verify behavior)` — a **false accusation** ("the tests do not
verify behaviour") about a slice whose module simply had a different name
than its manifest said. `SKIP` (exit 2) is produced only when the module
exists but has no mutable construct, or when no manifest/commit is found.

The historical `SKIP MUTANT` line quoted in the task book comes from the
acceptance ledger of 2026-11-14
(`b173-acceptance-ledger-2026-11-14.md`: `refusal-hold-wiring(SKIP)`), i.e.
from a run where the probe could not find a commit or a construct — not from
the module-name mismatch as such. Either way the outcome is the same in kind:
the mutation evidence for the slice was **not** produced.

The same mismatch was confirmed against the real history: at
`782412c0^` the tree has `refusal_hold.py` but no `refusal_hold_wiring.py`,
and the probe against that tree aborts exactly as above.

**What the check would do under the proposed rule.** `COMMIT` FAILS and names
the offending path and which of the two conditions failed
(`missing` / `untracked` / `not committed`). For `refusal-hold-wiring`
*at the time of the defect* that would have been the correct outcome: the
slice had declared a module it had not delivered, so its mutation evidence
was never produced.

---

## Defect 2 — a manifest file that exists but was never committed

### Reproduction

```bash
cd /home/muse-newapi/northstar-agent-os
git status --porcelain | grep merged-tree-review
#   ?? docs/design/merged-tree-review.md
git log --all --oneline -- docs/design/merged-tree-review.md
#   (nothing)
ls -la docs/design/merged-tree-review.md
#   -rw-rw-r-- 1 muse-newapi muse-newapi 35185 Nov 14 07:22
bash /home/muse-newapi/b173-accept.sh merged-tree-review | grep WORKTREE_CLEAN
#   PASS WORKTREE_CLEAN
```

### Why `WORKTREE_CLEAN` misses it

`WORKTREE_CLEAN` compares the set of files **the slice committed** against
the set of **dirty** paths:

```bash
CFILES=$(... git show --name-only ... )          # committed by the slice
DIRTY=$(git status --porcelain | awk '{print $2}') # dirty in the worktree
OVERLAP=$(comm -12 <(echo "$CFILES") <(echo "$DIRTY"))
```

`docs/design/merged-tree-review.md` was never `git add`ed, so it appears in
**neither** set: it is invisible to the comparison, and `WORKTREE_CLEAN`
reports PASS. The slice gets credit for a 35 KB design document that exists
only in one working directory and is lost on any fresh clone.

### The tracked/untracked distinction

`git ls-files --error-unmatch -- <path>` exits non-zero for a path that is
not in the index, and zero for one that is. The patch uses a three-way
distinction so that the failure detail says which condition failed:

| state | condition reported |
|---|---|
| not on disk at all | `missing` |
| on disk, in the index, but not in `HEAD` | `not committed` |
| on disk, not in the index | `untracked` |

---

## Defect 3 — the manifest fallback credits another slice's commit

### Reproduction

```bash
cd /home/muse-newapi/northstar-agent-os
git log --format='%h %s' --grep="^B173 acceptance-conformance:" -i   # empty
git log --format='%h %s' -1 -- $(cat /home/muse-newapi/b173-acceptance-conformance.files | tr '\n' ' ')
#   c08a86ad B173 deterministic-gate-score: kill or@155/or@159/or@197 in deterministic-gate-score
bash /home/muse-newapi/b173-accept.sh acceptance-conformance | grep '^PASS COMMIT'
#   PASS COMMIT c08a86ad (1 commit(s))
```

| slice | own commits (`--grep "^B173 <slug>:"`) | commit the fallback picks |
|---|---|---|
| `acceptance-conformance` | **none** | `c08a86ad` — `B173 deterministic-gate-score: …` |
| `capability-ceiling-probe` | **none** | `4e5a9657` — `B173 scorer-disagreement: disagreement detector over multi-scorer verdicts` |

Both slices are **credited with another slice's commit**. `acceptance-conformance`
is the important one: it has zero commits of its own, yet `COMMIT` prints
`PASS`, and `NEW_TESTS` then counts *another slice's* test methods
(`12 new test methods across 1 commit(s)` — the deterministic-gate-score
tests) as its own.

The reason the fallback misfires is structural: a slice that only touches
**existing** files has a manifest full of paths that other slices also own,
so "the newest commit touching these paths" is usually somebody else's.

### Correct outcome under the proposed rule

`FAIL COMMIT none` — the slice has no commit whose subject is
`B173 <slug>:`, and the path-based fallback may not borrow another slice's
commit. For `acceptance-conformance` the detail additionally names the
stale manifest path (`docs/design/acceptance-conformance.md: missing`).

---

## The junk-line finding

18 of the 79 manifests begin with a line that is the **slug itself**, not a
path:

```bash
cd /home/muse-newapi
for m in b173-*.files; do
  first=$(head -1 "$m")
  case "$first" in */*|*.py|*.md|*.sh|*.txt|*.json) ;; *) echo "${m%.files} FIRSTLINE=$first";; esac
done
```

| manifest | junk first line |
|---|---|
| `b173-audit-head.files` | `audit-head` |
| `b173-c52.files` | `c52` |
| `b173-c54.files` | `c54` |
| `b173-c58.files` | `c58` |
| `b173-diviner.files` | `diviner` |
| `b173-e2b.files` | `e2b` |
| `b173-fable.files` | `fable` |
| `b173-horizon.files` | `horizon` |
| `b173-langgraph.files` | `langgraph` |
| `b173-runtime-registration.files` | `runtime-registration` |
| `b173-seal-slice6.files` | `seal-slice6` |
| `b173-slice1.files` | `slice1` |
| `b173-slice2.files` | `slice2` |
| `b173-slice3.files` | `slice3` |
| `b173-slice4.files` | `slice4` |
| `b173-slice5.files` | `slice5` |
| `b173-slice6.files` | `slice6` |
| `b173-unwind.files` | `unwind` |

(That is the complete list — 18 of 79. The task book's list matches.)

### Decision: **ignore non-path lines**, and *also* clean the manifests

**Both are needed**, and the evidence says so:

* **Ignore.** The junk lines are harmless *today* — the path simply does not
  exist, so a naive "every manifest path must exist" rule turns 18 slices
  into failures for a reason that has nothing to do with their work. A check
  that produces 18 unrelated failures on the day it lands is a check that
  gets reverted. Measured over the whole corpus: **237 of 255** manifest
  lines contain a `/`; the remaining **18** are exactly the junk lines, and
  **no manifest contains any other kind of line** (no absolute paths, no
  lines with spaces). So "a line is a path iff it contains `/`" is a rule
  that discards exactly the junk and nothing else.
* **Clean.** The manifests live outside the repo, so the cleanup is a
  **coordinator-applied** change; this slice does not edit them. The table
  above is the cleanup list: delete line 1 of each of those 18 manifests.

The rule is implemented as "ignore lines without a `/`". That is a
*deliberate, documented* behaviour, not an accident, and the conformance
test `test_d_junk_non_path_line_is_ignored` pins it.

---

## Why the manifest truth is folded into `COMMIT` and not added as a 13th check

There are already 12 checks and the denominator is `TOTAL=$((PASS+FAIL))`
(line 197). Adding a 13th check would rewrite every existing acceptance
record from "12/12" to "13/13" and churn the whole batch's history for no
gain — and it would change the meaning of `TOTAL`, which the coordinator
reads as the headline number.

`COMMIT` already means "this slice really delivered". The manifest is the
slice's own declaration of what it delivered, so folding the manifest's
truth into `COMMIT` is the semantically correct place:

* a slice whose manifest names a path it never created has **not** delivered
  what it claimed — that is exactly a `COMMIT` failure;
* a slice with no commit of its own has **not** delivered — also `COMMIT`.

The check **count stays 12**, the check **names stay the same 12**, the
`check()` output format (`PASS`/`FAIL`/`SKIP` + name + detail) is unchanged,
and the exit codes (0 = `ACCEPT: PASS`, 1 = `ACCEPT: FAIL`) are unchanged.
The conformance tests pin all of these.

### Semantics of the edge cases

* **No manifest file at all** → the manifest truth is simply not evaluated
  and `COMMIT` is decided by attribution alone. A slice with no manifest
  must not start failing for a new reason; before this patch it passed
  `COMMIT` when it had a subject-matching commit, and it still does.
  (`test_h_missing_manifest_does_not_fail_commit`.)
* **Empty manifest** → same: no paths, no violations, `COMMIT` unchanged.
  (`test_h_empty_manifest_does_not_fail_commit`.)
* **A manifest whose files the slice creates later** → the paths exist and
  are tracked at acceptance time, so `COMMIT` passes. The check is evaluated
  against the *current tree*, never against a snapshot taken when the
  manifest was written, so a slice is never penalised for work it has not
  written **yet** — only for work it never delivers. For `r6-12-session-resolution`
  the two manifest paths
  (`components/northstar-agent-runtime/tests/test_r6_12_session_resolution.py`,
  `docs/design/r6-12-session-resolution.md`) exist and are tracked, so
  `COMMIT` stays PASS (before and after the patch).
* **The legacy path fallback is kept** for the *content* checks
  (`NEW_TESTS`, `WORKTREE_CLEAN`, `TESTS_RAN`, `MUTANT`), so their verdicts
  do not move. Only the *attribution* decision (which commit is the
  slice's own) is subject-verified. This is what keeps the other 11
  verdicts byte-identical before and after the patch.

---

## Before/after `COMMIT` verdicts for the six verification slices

Measured by running the **live** `b173-accept.sh` and the **patched copy**
(`/tmp/b173-r6-manifest-accept.sh`, produced by applying the patch to a
copy) **serially** on the same tree, then diffing the 12 verdict lines.
The mutation-probe worktree is shared per slug (`/tmp/b173-mutant-<slug>`),
so the two runs must not overlap — running them concurrently produces
spurious `MUTANT` differences that have nothing to do with the patch.

| slice | before | after | what moved |
|---|---|---|---|
| `acceptance-conformance` | `PASS COMMIT c08a86ad (1 commit(s))` | `FAIL COMMIT none; manifest: docs/design/acceptance-conformance.md: missing` | foreign-commit fallback **and** a missing manifest path |
| `capability-ceiling-probe` | `PASS COMMIT 4e5a9657 (1 commit(s))` | `FAIL COMMIT none` | foreign-commit fallback (`4e5a9657` is `scorer-disagreement`'s commit) |
| `refusal-hold-wiring` | `PASS COMMIT d08958d6 (2 commit(s))` | `PASS COMMIT d08958d6 (2 commit(s))` | nothing — the module the manifest names now exists and is tracked |
| `merged-tree-review` | `PASS COMMIT 4e43c32a (2 commit(s))` | `FAIL COMMIT 4e43c32a manifest: docs/design/merged-tree-review.md: untracked` | the 35 KB design doc is named in the manifest but was never committed |
| `judge-hygiene` | `PASS COMMIT 825ea66b (3 commit(s))` | `PASS COMMIT 825ea66b (3 commit(s))` | nothing — clean manifest |
| `r6-12-session-resolution` | `PASS COMMIT 4525ca31 (2 commit(s))` | `PASS COMMIT 4525ca31 (2 commit(s))` | nothing — the manifest's own files exist and are tracked |

For the three slices whose `COMMIT` verdict does not move, **all 12 verdict
lines are identical** before and after (the `TESTS_RAN` detail line carries
a wall-clock duration and is normalised away in the comparison; every other
line is byte-identical).

For the three slices whose `COMMIT` verdict moves, **only the `COMMIT` line
differs** — the other 11 lines are byte-identical. This is by construction:
the legacy path fallback is retained for the content checks, so
`NEW_TESTS` / `WORKTREE_CLEAN` / `TESTS_RAN` / `MUTANT` keep seeing exactly
what they saw before.

Note that `acceptance-conformance`'s `COMMIT` was **already** going to fail
the slice for other reasons (`FAIL CANARY`, `FAIL FULL_SUITE`, `FAIL BENCH`
— it has no full-suite statement and no `161/169`), so the patch does not
change that slice's overall verdict from FAIL to FAIL; what it changes is
that the failure is now **attributed correctly** ("this slice delivered
nothing") instead of being masked by another slice's commit.

---

## The precise change specification

File: `/home/muse-newapi/b173-accept.sh` (the live referee — **not** edited by
this slice). Patch: `/home/muse-newapi/b173-r6-manifest-integrity-fix.patch`
(unified diff, `a/b173-accept.sh` → `b/b173-accept.sh`).

### Change 1 — line 34: make the home directory overridable (so a copy can be tested)

Old (line 34):

```
HOME_DIR=/home/muse-newapi
```

New:

```
HOME_DIR="${B173_HOME_DIR:-/home/muse-newapi}"
```

*Why:* the patched copy must be runnable against a sandbox `$HOME_DIR`
instead of the real one, so the behavioural tests never touch the real
batch. The default is unchanged, so the live behaviour is identical.

### Change 2 — lines 51-55: subject-verified attribution + manifest helpers

Old (lines 51-55):

```
# All slice commits (subject prefix), newest first. Fallback: manifest files.
SLICE_HASHES=$(git -C "$REPO" log --format=%H --grep="^B173 ${SLUG}:" -i 2>/dev/null | head -20 || true)
if [ -z "$SLICE_HASHES" ] && [ -f "$MANIFEST" ]; then
  SLICE_HASHES=$(git -C "$REPO" log --format=%H -1 -- $(cat "$MANIFEST" | tr '\n' ' ') 2>/dev/null || true)
fi
```

New:

```
# --- manifest helpers (r6-manifest-integrity) ------------------------------
# A manifest line is a PATH line iff it contains a "/".  Lines without one
# are junk: 18 of the 79 manifests in this batch start with a bare slug
# ("c52", "slice3", ...).  The truth check and the subject-checked fallback
# ignore them; the coordinator's cleanup table removes them.
manifest_paths() {
  [ -f "$1" ] || return 0
  grep -E '/' "$1" | grep -v '^[[:space:]]*$' | sed 's/[[:space:]]*$//' || true
}
# One violation per line: "<path>: missing" (named by the manifest but not
# in the tree), "<path>: untracked" (on disk, never added to git) or
# "<path>: not committed" (added to the index but absent from HEAD).
manifest_violations() {
  local p
  while IFS= read -r p; do
    [ -z "$p" ] && continue
    case "$p" in "$REPO"/*) p="${p#"$REPO"/}";; esac
    if [ ! -e "$REPO/$p" ]; then
      echo "$p: missing"
    elif git -C "$REPO" cat-file -e "HEAD:$p" 2>/dev/null; then
      :
    elif git -C "$REPO" ls-files --error-unmatch -- "$p" >/dev/null 2>&1; then
      echo "$p: not committed"
    else
      echo "$p: untracked"
    fi
  done < <(manifest_paths "$1")
}
# All slice commits (subject prefix), newest first.
SUBJ_HASHES=$(git -C "$REPO" log --format=%H --grep="^B173 ${SLUG}:" -i 2>/dev/null | head -20 || true)
# Legacy path-based fallback: the newest commit touching any manifest path.
# It is kept for the CONTENT checks (NEW_TESTS / WORKTREE_CLEAN / TESTS_RAN /
# MUTANT) so that their verdicts do not move; ATTRIBUTION is decided by
# COMMIT below, which only accepts a commit whose subject is this slice's.
SLICE_HASHES="$SUBJ_HASHES"
if [ -z "$SLICE_HASHES" ] && [ -f "$MANIFEST" ]; then
  SLICE_HASHES=$(git -C "$REPO" log --format=%H -1 -- $(cat "$MANIFEST" | tr '\n' ' ') 2>/dev/null || true)
fi
# Attribution hash: subject-verified.  The path fallback may only contribute
# a commit whose subject is "B173 <slug>:", otherwise a slice with no commit
# of its own is accepted on another slice's work.
OWN_HASHES="$SUBJ_HASHES"
if [ -z "$OWN_HASHES" ] && [ -f "$MANIFEST" ]; then
  OWN_HASHES=""
  MPATHS=$(manifest_paths "$MANIFEST" | tr '\n' ' ')
  if [ -n "$MPATHS" ]; then
    for cand in $(git -C "$REPO" log --format=%H -20 -- $MPATHS 2>/dev/null || true); do
      csubj=$(git -C "$REPO" log --format=%s -1 "$cand" 2>/dev/null | tr '[:upper:]' '[:lower:]' || true)
      slug_lc=$(printf '%s' "$SLUG" | tr '[:upper:]' '[:lower:]')
      case "$csubj" in
        "b173 ${slug_lc}:"*) OWN_HASHES="$cand"; break;;
      esac
    done
  fi
fi
```

### Change 3 — line 58: fold the manifest truth into `COMMIT`

Old (line 58):

```
if [ -n "$HASH" ]; then check COMMIT PASS "${HASH:0:8} ($NCOMMITS commit(s))"; else check COMMIT FAIL "none"; fi
```

New:

```
# --- COMMIT: attribution + manifest truth (the check count stays 12) ------
# COMMIT is the slice's attribution gate: it now fails when the slice owns no
# commit of its own (the path fallback may not borrow another slice's) or
# when the manifest names a path that does not exist / was never committed.
OWN_HASH=$(echo "$OWN_HASHES" | head -n1)
OWN_N=$(echo "$OWN_HASHES" | grep -c . || true)
MANIFEST_VIOL=""
if [ -f "$MANIFEST" ]; then MANIFEST_VIOL=$(manifest_violations "$MANIFEST"); fi
VIOL_TXT=$(echo "$MANIFEST_VIOL" | grep -v '^[[:space:]]*$' | tr '\n' ';' | sed 's/;$//')
if [ -n "$OWN_HASH" ]; then
  if [ -n "$VIOL_TXT" ]; then
    check COMMIT FAIL "${OWN_HASH:0:8} manifest: $VIOL_TXT"
  else
    check COMMIT PASS "${OWN_HASH:0:8} ($OWN_N commit(s))"
  fi
else
  if [ -n "$VIOL_TXT" ]; then
    check COMMIT FAIL "none; manifest: $VIOL_TXT"
  else
    check COMMIT FAIL "none"
  fi
fi
```

### What is NOT changed

* `TOTAL=$((PASS+FAIL))` (line 197) — unchanged.
* The `check()` helper (lines 42-49) — unchanged; the output format is
  still `PASS <name> <detail>` / `FAIL <name> <detail>` / `SKIP <name> <detail>`.
* The 12 check names — unchanged.
* The exit codes — unchanged (`exit 0` on `ACCEPT: PASS`, `exit 1` on
  `ACCEPT: FAIL`).
* `b173-mutant.sh` and `b173-mutant.py` — untouched.
* The 79 manifest files — untouched (the cleanup is a coordinator task).
