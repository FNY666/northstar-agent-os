# delivery-bundle-hygiene — a delivery bundle is a delivery artefact, not source

Module: (none — this slice changes the repository's history, not a runtime module)
Tests: `tests/test_delivery_bundle_hygiene.py`
Status: implemented, measured, documented. No version bump, no tag, no merge.

## 1. What was wrong

The repo's rule (`CLAUDE.md`) is explicit:

> Delivery is a git bundle (`git bundle create <name>.bundle <branch>`), handed
> to the parent for review; the parent pushes.

A bundle is the **hand-off**.  It is produced *from* the repository.  Committing
one *into* the repository is a category error — and an expensive one, because a
bundle carries the repository's whole history.

### 1.1 The measurement

```
$ git ls-tree -r -l HEAD | grep '\.bundle$'
23 bundles, 475005084 bytes (453 MiB)

$ git rev-list --objects --all | grep '\.bundle' | wc -l
22
```

All 23 were added by a **single commit** whose subject is the literal string
`c1`.  A commit named `c1` names no slice, so:

* the referee could not attribute it;
* `docs/design/merged-tree-review.md` rode in on it, and was therefore the
  one manifest file the attribution test had to carry as a known exception;
* the commit's subject failed the batch's own naming rule.

### 1.2 What it cost

The cost is not disk (the machine has 154 GiB free).  It is:

* **every clone** of this branch clones 453 MiB of bundles it will never use;
* **the delivery bundle** the parent is handed was 48.5 MB, of which 26 MB
  was the same history the parent already had;
* **`.gitignore` had to be taught `*.bundle`** (commit `33fd8c90`) to stop the
  next `git add -A` from committing a fresh 70 MiB binary — a workaround for
  the same defect.

Measured on the machine, before the fix:

```
$ du -sh .git                      # 502 M
$ git count-objects -vH | grep size-pack
size-pack: 28.25 MiB
$ git count-objects -vH | grep ^size
size: 466.58 MiB        # <-- 453 MiB of it is loose bundle objects
```

The bundles were **loose objects**, not packed.  `git gc` alone would have
reclaimed most of it, but `git gc` does not remove them — they are reachable,
and they are *meant* to be there by the history that introduced them.

## 2. The fix

### 2.1 Two steps, in the tree and in the history

**Step 1 — the tree.**  Commit `043d3739` untracks the 23 bundles.  The
working tree stops carrying them; the history still does.

**Step 2 — the history.**  `git filter-branch` with an index-filter that
removes `*.bundle` from every commit's index:

```bash
git filter-branch --index-filter \
  'git ls-files -z "*.bundle" | xargs -0 -r git rm -q --cached --ignore-unmatch' \
  --prune-empty -- batch-173-moltbook-absorb
```

`--prune-empty` drops the commits that become empty.  16 commits were pruned:
14 pre-batch commits dated 2026-10-06/09 that had contributed **only** bundles
or nothing, and 2 confirmed-empty B173 commits (`fe7feb14`, `c42bae66`).

### 2.2 The rewrite was proved lossless before it was applied

A history rewrite is the one operation in this repo that can lose work
silently, so it was measured, not assumed.  The proof is a **snapshot
comparison**: for every commit in the old history, take its tree, strip the
bundle paths, and write it as a tree object.  Every distinct stripped snapshot
must still exist in the new history.

```python
# for each commit: read-tree into a temp index, `git rm --cached` the
# bundles, `git write-tree`
old_snapshots = {stripped_tree(repo, sha) for sha in old_history}
new_snapshots = {stripped_tree(repo, sha) for sha in new_history}
assert old_snapshots <= new_snapshots
```

Measured:

```
distinct stripped snapshots: OLD 1026   NEW 1026
OLD snapshots absent from NEW: 0
NEW snapshots not in OLD:     0
```

**All 1026 distinct content-snapshots survive, and the rewrite invented none.**
The HEAD tree is byte-identical before and after the tree step
(`78e137ecb4b2279947437681c474b0a4e41bd24f`).

The rewrite was first run on a **clone**, and its output compared, before it
was run on the branch.

### 2.3 The second pass: the malformed subjects

The first pass left two commits whose subjects were the literal strings `c1`
and `c2`.  A subject of one or two characters names nothing, and the referee
matches a slice by its subject.

* `c1` carried three files: the slice-5 report, the seal-slice6 report, and
  `docs/design/merged-tree-review.md`.  The design doc is named by the
  `merged-tree-review` manifest, so the subject must name that slice.
* `c2` carried `tests/test_x.py` — a stray file with **no test method**, named
  by **no** manifest and referenced by **no** code.  Removing it made the
  commit empty, so `--prune-empty` dropped it.

The second pass was one `filter-branch` with a `--msg-filter` and an
`--index-filter` together, so the sha mapping stayed consistent.

> **The msg-filter bug, and what it cost.**  The first attempt read the
> commit message with `cat` inside a `case` statement — which consumed the
> message and emitted **nothing** for every commit whose subject did not
> match.  40 commits lost their subjects entirely.  The damage was caught by
> counting: the rewrite produced 40 commits with empty subjects, where there
> should have been 0.
>
> The corrected filter reads the message in full (`msg=$(cat)`) and re-emits
> it for every non-target commit.  It was then **self-tested against all 1054
> commit messages** before it was applied:
>
> ```
> messages checked: 1054   differing: 0
> ```
>
> The branch was restored from the safety branch (`backup-pre-bundle-rewrite-verify`)
> and the rewrite re-run.  This is why the safety branch existed.

### 2.4 What the rewrite cost: the sha map

Rewriting history changes every commit's sha.  The batch cites commit shas
in **25 documents**, in test constants, and in the delivery evidence.

The old→new map was built by matching commits on
`(author, email, author-date, committer, committer-email, committer-date,
message body)`:

```
mapped: 1053 of 1070
unmapped: 17  (16 pruned by the bundle filter + 1 pruned as empty)
```

Every **cited** sha was then remapped, and the remapping preserved each
citation's **length** (the docs cite 7-, 8- and 40-character forms):

```
cited shas that resolved BEFORE and still resolve NOW: 150
cited shas that resolved BEFORE and are now STALE:        0
```

### 2.5 The delivery evidence had to be re-bound

`docs/delivery/slice6/` holds the slice-6 delivery seal: a JSON seal, a
manifest that binds it by digest, a divergence report, and a patch replay.
They record the **start commit** and the **delivery commit** by sha.

The seal's `start_tree_hash` is **unchanged** (`6bc4388d…`) — the tree is
content-addressed and the rewrite did not alter the tree.  Only the two
*commit* shas moved.

The manifest binds the seal by **digest**
(`delivery_seal_sha256 = sha256(slice6-seal.json)`), so changing the seal
changes its digest, so the manifest's digest field changes too.  Both were
updated by **byte-level** replacement: re-serialising the JSON with
`json.dumps(indent=2)` reflows the files, which changes their bytes and
breaks the digests the manifest itself carries.

```
docs/delivery/slice6/ | 5 insertions(+), 5 deletions(-)
```

### 2.6 The test constants

Two test files hardcode the slice-6 commits:

* `tests/test_delivery_seal.py` — `START_COMMIT`, `DELIVERY_COMMIT`
* `components/northstar-agent-runtime/tests/test_blind_rerunner.py` — the
  end commit of the sealed delivery

Both were remapped.  The objects themselves still existed after the rewrite
(git keeps unreachable objects until `gc`), so the tests kept passing
*silently* — which is exactly the failure mode worth catching: the test
would have skipped or resolved against an object that a fresh clone does not
have.  The remapping makes the evidence reachable in a fresh clone.

### 2.7 The effect, measured

| | before | after |
|---|---|---|
| delivery bundle | 48,463,695 bytes | 22,590,572 bytes (**−53%**) |
| `.git` | 502 M | 54 M after `git gc` (**−89%**) |
| bundles in the tree | 23 (453 MiB) | 0 |
| bundles reachable from HEAD | 22 | 0 |
| commits with a non-batch subject | 2 (`c1`, `c2`) | 0 |

## 3. The tests (9 methods)

`tests/test_delivery_bundle_hygiene.py` — they read the **live** repository,
so they fail if the defect returns.

| test | what it pins |
|---|---|
| `test_the_committed_tree_contains_no_bundle_files` | the tree carries no bundle |
| `test_the_tracked_file_list_contains_no_bundle_files` | git tracks no bundle |
| `test_no_git_object_in_the_history_is_a_bundle` | the **history** carries no bundle object — a deleted bundle is still in every clone's packfile |
| `test_the_delivery_bundle_carries_no_bundle_objects` | the same, stated for the delivered artefact |
| `test_the_gitignore_still_excludes_bundles` | the rule that stops the defect returning stays in place |
| `test_the_ignore_rule_matches_a_bundle_in_the_repo_root` | the rule must **match**, not merely be present as text |
| `test_every_commit_subject_starts_with_the_batch_prefix` | every commit the batch authored names its slice |
| `test_no_commit_subject_is_a_bare_single_character` | the specific shape of the defect: `c1`, `c2` |
| `test_the_batch_range_is_not_empty` | the scope helper is not vacuous |

### 3.1 Two scoping decisions the first version got wrong

**The subject test's scope.**  The first version ran `git log --all`.  The
branch inherits ~1050 commits from `main`, and `main` has its own subjects
(`fix: drop duplicated return in _canary_evidence`, `P1 seg1: bash_parser
skeleton`, …).  Those are **not the batch's to name**: the batch inherited
them, it did not write them.  The test now scopes to the batch's own
commits — the range from the **first** `B173 ` commit to `HEAD`:

```
the branch carries 1053 commits, of which 189 are the batch's own
(prefix "B173 "), 2 are not, and the other 862 are inherited from main.
```

**The history test's scope.**  The first version ran
`git rev-list --objects --all`.  `--all` includes the **safety branches**,
which exist precisely to keep the pre-rewrite objects alive; they are not
part of the branch the parent receives.  The test now uses `HEAD`.

## 4. Verification

See the slice report (`b173-delivery-bundle-hygiene-cc-final.txt`) for the
full numbers: RED/GREEN, the full runtime suite against the stored baseline,
the bench, and the referee's verdict.

## 5. Open items

1. **The safety branches hold the pre-rewrite objects.**  `backup-pre-bundle-rewrite`
   and `backup-pre-bundle-rewrite-verify` keep 22 bundle objects alive
   (453 MiB).  They are the reason the rewrite was safe to attempt, and they
   should be deleted **after** the parent has accepted the delivery — not
   before.  The repo's rule forbids deleting branches without a decision.

2. **The batch's history now diverges from `origin/batch-173-moltbook-absorb`.**
   The rewrite changed every sha, so the branch can no longer be pushed as a
   fast-forward.  The parent must **force-push** (or delete and re-push) the
   branch.  `main` is untouched — `main` never had the bundles
   (`git ls-tree -r --name-only origin/batch-173-moltbook-absorb | grep -c '\.bundle$'` → 0).

3. **155 cited shas do not resolve at all**, in either history.  They are
   pre-existing staleness, not caused by this rewrite: `docs/design/r6-12-session-resolution.md`
   (23), `docs/design/artifact-completion.md` (20), and so on.  A future slice
   could resolve them against the batch's ledger.

4. **`docs/api/northstar-agent-runtime.md` is 2.44 MB.**  Unrelated to this
   slice, but it is a generated artefact checked in whole on every
   regeneration.

5. **The 19 `b173-*.bundle` files the batch delivered remain on disk** at
   `/home/muse-newapi/`.  They are the batch's delivery artefacts and are
   outside the repository; this slice does not remove them.
