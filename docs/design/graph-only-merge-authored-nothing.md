# A graph-only merge authored nothing

**Date:** 2026-11-25
**From:** the submission window (session 728a716a)
**Status:** FIXED, with the before/after measured and the control proved
by planting the fault.

## 1. The one-line finding

`test_every_commit_subject_starts_with_the_batch_prefix` requires every
commit in the batch's range to have a subject starting with `B173 `. A
**merge commit** whose subject is git's default fails it. Three such
merges were on the branch — all inherited from the remote tip, all
already published, so their subjects could not be renamed without
rewriting history other windows hold.

The commits were not wrong. **The rule's scope was.**

## 2. What the three offenders actually did

| commit | subject | tree vs first parent |
|---|---|---|
| `481d2366` | `Merge branch 'submission-window/b173-refusal-gate-landing' of github.com:... into submission-window/b173-refusal-gate-landing` | **identical** |
| `0c8aae85` | `Merge the remote tip into the submission window` | **identical** |
| `23c8174d` | `Merge the pre-repair remote tip into the repaired branch` | **identical** |

`git diff --stat <m>^1 <m>` is EMPTY for each. Their trees are
byte-identical to their first parent's:

```
$ git rev-parse 481d2366^{tree}   # 6940edef5c8184f12c2dd89d4e1080e0e43289f9
$ git rev-parse 481d2366^1^{tree} # 6940edef5c8184f12c2dd89d4e1080e0e43289f9
```

So each one reconciled the **graph** and introduced no **content**. A
commit that authored nothing has no slice to name. Asking it to name one
was asking the wrong question of it.

## 3. The scope of the rule, measured

The branch's range (476 commits from the first `B173 ` commit to `HEAD`)
holds **11 merges**:

| shape | count | named with `B173 `? |
|---|---|---|
| graph-only (tree == first parent's tree) | 6 | 3 |
| content-changing | 5 | 5 (all) |

Two facts follow.

**First:** every **non-merge** commit in the range carries the prefix —
0 offenders. The defect was never about sloppy subjects; it was never
about a commit that failed to name its work.

**Second:** the repo's own convention is to name a merge. 8 of the 11
merges DO carry `B173 <slug>: ...`, and the two content-identical twins
of the offenders — `1b107058` and `8edb3d1d` — are exactly that: the
same merges, the same trees, with the prefix applied. The batch knew the
convention; three merges were made without it, on a day when the branch
was being reconciled with a remote that had moved.

## 4. The fix

Scope the test to commits that authored content:

```python
def _is_graph_only_merge(sha: str) -> bool:
    parents = _parents(sha)
    if len(parents) < 2:
        return False
    return _tree(sha) == _tree(parents[0])
```

A graph-only merge is skipped; everything else must carry the prefix.

## 5. Why that is not a weakening — the control

An exemption with nothing holding it is an amnesty. So the fix ships a
**non-vacuity control** in the opposite direction:

> `test_every_content_changing_merge_names_its_slice` — a merge that DID
> author content must still name its slice.

And the control itself asserts it is not vacuous: it requires at least one
content-changing merge to exist in the range (there are **5** on this
branch).

### 5.1 The control was proved by planting the fault

A test that cannot fail proves nothing, so the faults were planted in a
throwaway clone and the tests run against them:

| planted fault | caught? | by which |
|---|---|---|
| a stray non-merge commit, subject `a stray note` | **YES** | `test_every_commit_subject_starts_with_the_batch_prefix` |
| a content-changing merge, subject `Merge the side branch in` | **YES** | **both** tests |

The second row is the one that matters: a merge that authored content and
hid behind the exemption is caught by the control, not waved through.

### 5.2 The measurement

| | before | after |
|---|---|---|
| repo suite | `1 failed, 460 passed, 6238 subtests passed` | **`462 passed, 6238 subtests passed`** |
| `delivery-bundle-hygiene` acceptance | `ACCEPT: FAIL (9/10, 2 skipped)` | **`ACCEPT: PASS (10/10, 2 skipped)`** |

The repo suite had been red for the whole batch. It is now green for the
first time.

## 6. What this does NOT change

* The prefix rule itself is unchanged for every commit that authored
  content.
* No history was rewritten. The three merges keep their subjects, because
  they are published and other windows hold them.
* The `B173 ` prefix convention for merges that DO author content is
  unchanged, and is now pinned by a test rather than by habit.

## 7. The general lesson

**A commit can be in the graph without being the author of anything.**
Before convicting a commit of a defect, ask what it actually did. `git
log --format=%P` distinguishes a merge; the tree comparison distinguishes
a graph-only merge from one that authored content. The second comparison
is the one that decides whether a commit-level rule applies at all.

**And when the commit in question cannot be fixed** — because it is
published, or because other windows hold it — the fix belongs in the
**scope of the rule**, not in the commit. The rule was mis-scoped; the
history was fine.

## 8. Where the fix lives

`tests/test_delivery_bundle_hygiene.py`, commit `b3d44161` on
`submission-window/b173-refusal-gate-landing`.

## 9. Related

* `docs/design/delivery-bundle-hygiene.md` — the slice that introduced
  the test, and its own scoping decision (§3.1).
* `docs/design/session-resolver-date-blind-filter.md` — the other defect
  this window found and fixed in the same round: a comparison that read
  fewer fields than the rule it served.
