# r8 — the referee's content-commit set: a union, not a fallback

**Date**: 2026-11-16
**Branch**: `batch-173-moltbook-absorb`
**Scope**: the referee (`/home/muse-newapi/b173-accept.sh`, outside the repo) and the
conformance tests that pin it (inside the repo).

---

## 1. Why this round exists

Round 8 started with a subject matcher: a commit whose subject did not name its slice
was invisible to the referee.  The matcher was widened and three slices that had real,
complete work became visible (`slice4`, `r6-worktree-rename`, and — through the
comma-list shape — `r6-manifest-subject`).

Widening the matcher exposed the next layer of the same problem.  Three slices were
still FAILing for reasons that had nothing to do with their work:

```
$ bash b173-accept.sh capability-ceiling-probe
FAIL COMMIT none
ACCEPT: FAIL (11/12, 0 skipped) capability-ceiling-probe

$ bash b173-accept.sh orphan-adoption
FAIL NEW_TESTS 0 (threshold 9)
ACCEPT: FAIL (10/11, 1 skipped) orphan-adoption

$ bash b173-accept.sh mutant-evidence-closure
FAIL NEW_TESTS 0 (threshold 9)
ACCEPT: FAIL (10/11, 1 skipped) mutant-evidence-closure
```

All three slices had their work in the branch.  All three were told they had none.

## 2. The defect, measured

### 2.1 `capability-ceiling-probe` — the commit was amended in place

The slice's entire deliverable — a 695-line module, a 458-line test file with 59
methods, an 8.6 KB design doc — was committed as:

```
4e5a9657  B173 scorer-disagreement: disagreement detector over multi-scorer verdicts
```

The correctly-subjected twin exists in the reflog:

```
f85282fb  B173 capability-ceiling-probe: fail-first admission + calibration error + ceiling routing
4e5a9657  B173 scorer-disagreement: disagreement detector over multi-scorer verdicts
```

Both have the **same parent** (`6c5fa00a`) and the **same author date**
(`2026-11-13 19:30:34 +0000`).  The reflog records `commit` → `commit (amend)`: the
commit was amended in place and its subject was overwritten.

The two trees differ by one file:

```
$ git diff --stat f85282fb 4e5a9657
 components/northstar-agent-runtime/scorer_disagreement.py | 6 +++---
```

and that difference is **three comment-header lines rotated** (`# helpers` ↔ `# records`
↔ `# pure computation`) with **no code change**.  `scorer_disagreement.py` was
introduced by a different commit (`0bd27ade`), so an amend elsewhere in the tree swept
it in.

The commit subject is the repo's convention and the referee's matcher.  A commit that
delivers a slice's work and does not say so is a mis-attribution the referee cannot see.

### 2.2 The registry mis-attributed the same module

`components/northstar-agent-runtime/runtime_registration.py:538`:

```python
_registration("capability_ceiling_probe", "scorer-disagreement", "2026-11-14", ...)
```

The `slice_slug` field is documented as *"the slice that introduced the module"*.
`capability_ceiling_probe` was introduced by the `capability-ceiling-probe` slice;
`scorer_disagreement.py` was introduced by `0bd27ade` (`scorer-disagreement`).  The
same mis-attribution as the commit subject, in the runtime registry itself.

### 2.3 The referee made correctness destructive

The referee's content-commit selection was **exclusive**:

```bash
SLICE_HASHES="$SUBJ_HASHES"
if [ -z "$SLICE_HASHES" ] && [ -f "$MANIFEST" ]; then
  SLICE_HASHES=$(git log --format=%H -1 -- $(cat "$MANIFEST" | tr '\n' ' ') || true)
fi
```

Its own comment says it was kept *"so that their verdicts do not move"*.  It moved
them, in the wrong direction.  The moment a slice's subject was corrected, the fallback
stopped firing — and the commit that actually carries the slice's work, which sits
under the old, wrong subject, became invisible to every content check:

```
before the subject was corrected:  NEW_TESTS 59   (threshold 9)  PASS
after  the subject was corrected:  NEW_TESTS  8   (threshold 9)  FAIL
```

A 51-method loss, caused by making the slice's history **more honest**.

### 2.4 Two slices' evidence lives under other slices' subjects

`orphan-adoption` and `mutant-evidence-closure` are slices whose whole subject was
**adopting** other slices' work:

| slice | manifest file | introduced by |
|---|---|---|
| `orphan-adoption` | `scope_verbatim_compaction.py` | `b53b71c6` — `B173 scope-verbatim-compaction:` |
| | `test_scope_verbatim_compaction.py` | `b53b71c6` |
| | `event_condenser.py` | `e7ca19d4` — `B173 event-condenser:` |
| | `test_revision_checked_tool_results.py` | `93082890` — `B173 revision-checked-tool-results:` |
| | `annotation-pin.md` | `b7a01e59` — `B173 outsideloop:` |
| | `orphan-adoption.md` | `53640d0e` — `B173 orphan-adoption:` |
| `mutant-evidence-closure` | `test_event_condenser.py` | `e7ca19d4` — `B173 event-condenser:` |
| | `test_endpoint_identity.py` | `ddf86494` — `B173 neo-konsi-s2bw:` |
| | `test_cancellation_tombstone.py` | `695a25b7` — `B173 tombstone:` |
| | `test_artifact_authority.py` | `6026b3e3` — `B173 vina:` |
| | `test_deterministic_gate_score.py` | `f4a1413e` — `B173 deterministic-gate-score:` |
| | `test_signed_receipt.py` | `ef748b93` — `B173 vina-receipt-signing:` |

Every one of those commits carries test methods.  The exclusive fallback counted them
for these two slices only because they had **no** subject commit of their own to shadow
them — an accident of the rule, not a property of the work.

## 3. The fix

### 3.1 The content-commit set is a union

```bash
PATH_HASHES=""
if [ -f "$MANIFEST" ]; then
  for mp in $(cat "$MANIFEST" | tr '\n' ' '); do
    ih=$(git log --diff-filter=A --format=%H -1 -- "$mp" || true)
    [ -n "$ih" ] && PATH_HASHES="$PATH_HASHES
$ih"
  done
fi
SLICE_HASHES=$(printf '%s\n%s\n' "$SUBJ_HASHES" "$PATH_HASHES" | awk '!seen[$0]++')
```

The subject-matched commits **and** the commits that introduced the manifest's files,
always both.

Two refinements were measured, not guessed:

* **introducing commit, not every touching commit.**  The manifest of `refusal-hold-wiring`
  names `pyproject.toml`, which every slice in the batch has touched.  "Every commit
  that touched" yields **18,764** distinct method names; "the commit that introduced
  it" yields **75**.  The introducing commit is also the honest one: it is the commit
  that brought the file into the tree.
* **the introducing commit is admitted even when its subject names a different slice.**
  That is the whole point: a slice's evidence may sit under the wrong subject (an
  in-place amend) or under the source slice's subject (an adoption).

### 3.2 The union must not convict a slice of another slice's failures

A union brings in commits that introduced **other** slices' files, and those commits
carry other slices' test files.  `TESTS_RAN` then ran them and convicted the slice of
failures it never wrote:

| slice | wrongly-pulled test files | wrongly-charged failures |
|---|---|---|
| `runtime-registration-closure` | `test_cli.py`, `test_module_layout.py`, `test_version.py` | 5 `test_cli` doctor/sandbox failures |
| `msaf-lineage` | `test_cli.py`, `test_sessions.py`, `test_permissions.py` + 11 more | 11 failures |

Every one of those failures is in the batch's **standing baseline failure set** and none
of them is the charged slice's.

The rule that fixes it:

> A test file is the slice's evidence when the commit that introduced it is one of the
> slice's **own subject commits** — or when it is the commit that introduced one of the
> manifest's files *and* that commit is also one of the slice's own subject commits.

In one sentence: **the commit that introduced a file is the slice's evidence only if
the slice's own commits are the ones that introduced it.**  A file the slice merely
*edited* — adopted from an older commit, or from another slice — contributes nothing.
Adopting a file is not the same as having written it.

### 3.3 The output says which is which

```
commit (subject):     <the slice's own commit>
commit (introducing): <a commit that carries evidence>
```

`ATTRIBUTION` is decided by the `COMMIT` check and is untouched by the union: it still
accepts only a commit whose subject names this slice.

### 3.4 The slice's own fixes

* `runtime_registration.py`: `slice_slug` for `capability_ceiling_probe` →
  `"capability-ceiling-probe"`.
* `capability_ceiling_probe.py`: `UnknownProbeError` was declared and never raised.
  Every operation takes the probe *object*, so no call can name an id the ledger has
  never seen.  The class is now **documented as reserved and deliberately not raised**,
  with the reason — it is kept because the name is the runtime's established one
  (`ai_probing`, `capability_eval`, `probing`, `reward_hacking` all raise it).
* `test_capability_ceiling_probe.py`: the slice's task book asked for *"every new
  public function has a test naming it"*.  Measured, the file named **none** of
  `submit`, `CalibrationBucket`, `RoutingVerdict`, `Submission`,
  `CapabilityCeilingProbeError` or `UnknownProbeError`.  They are named now, in
  `PublicSurfaceTests`; the slice's test count went **59 → 67**.

## 4. Blast radius, measured

Over all 84 slices of the batch, under the union rule:

* **0 slices lose** test methods.  No count falls.
* **17 slices' counts rise**; **6 cross the threshold**, and every one of them was
  failing for exactly this reason: `capability-ceiling-probe`,
  `mutant-evidence-closure`, `orphan-adoption`, `slice1`, `slice2`, `slice3`.
* The largest count becomes **18,764** under the naive "every touching commit" rule and
  **75** under the introducing-commit rule.  The introducing-commit rule is the one
  that is in force.

## 5. Files

| file | change |
|---|---|
| `/home/muse-newapi/b173-accept.sh` | the union, the introducing-commit rule, the `TESTS_RAN` ownership filter, the labelled commit list |
| `components/northstar-agent-runtime/tests/test_r8_content_commit_union.py` | new — behavioural conformance for the union |
| `components/northstar-agent-runtime/tests/test_r6_manifest_integrity.py` | the "e" case now pins the union's semantics instead of the exclusive fallback's |
| `components/northstar-agent-runtime/tests/test_r8_capability_ceiling_probe.py` | new — the slice's own promise |
| `components/northstar-agent-runtime/tests/test_capability_ceiling_probe.py` | the six unnamed public names |
| `components/northstar-agent-runtime/capability_ceiling_probe.py` | `UnknownProbeError` documented as reserved |
| `components/northstar-agent-runtime/runtime_registration.py` | the `slice_slug` |
| `docs/design/capability-ceiling-probe.md` | the attribution and the three findings |

## 6. Open items

1. `docs/api/northstar-agent-runtime.md` is stale: 53 runtime modules are on disk but
   in neither `tests/docbuild.py`'s manifest nor its exclusion list, and the
   `northstar-agent-interop` page is stale against `handoff.py`'s new `tombstones`
   parameter.  `tests/test_docbuild.py` fails on both — **and it fails at the baseline
   commit too** (verified in a detached worktree at `81836320`), so this is a batch
   regression that predates round 8, not a round-8 defect.  It needs its own slice.
2. `slice1` and `slice2` fail `TESTS_RAN` on `benchmarks/code-tasks/v1/fixtures/*` —
   the code-task fixtures, which fail on their own.  Same question: batch regression or
   slice defect?  Measured separately.
3. The `mutant-evidence-closure` and `orphan-adoption` design docs do not yet record
   *where* their promised test methods were landed and why they are not in the slices'
   own history.  The union makes the referee count them; the docs should say it too.
