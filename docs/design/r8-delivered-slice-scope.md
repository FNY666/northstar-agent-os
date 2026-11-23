# b173 round 8 (amended 2026-11-23) -- a manifest is a DECLARATION: the rules must not convict a slice that has not started

**Date**: 2026-11-23
**Branch**: `submission-window/b173-refusal-gate-landing`
**Scope**: the two round-8 conformance tests that apply the subject-matcher's
rules.  No runtime module is changed by this amendment.

---

## 1. The defect
 A manifest is a DECLARATION: the rules must not convict a slice that has not started

`tests/test_r8_commit_attribution.py` and
`tests/test_r8_tests_ran_ownership.py` apply their rules to **every**
slice with a manifest.  A manifest is a **DECLARATION**, written when a
slice is LAUNCHED, before any of it exists.  Measured 2026-11-23, four
slices had manifests and no commit on the branch under test --
`agent-authorization-boundary`, `memory-provenance-axis`,
`northstar-expand-search` and `state-transfer-audit` -- and every one of
their manifest files was "never committed".  The rules were written for
slices that DELIVERED, and applying them to a slice that has not started
measures nothing: it reports a failure that is not the slice's fault
and that no amount of work by the slice would change.

`northstar-expand-search` is the sharp case: its commit (`919e970a`)
exists, on the `batch-173-northstar-expand-search` branch, and is NOT
an ancestor of the branch under test.  So "a slice has delivered when
the branch under test carries its commit" is the right rule -- it is
what the referee can actually find.

The narrowing is **pinned**, because a narrowing that is computed
wrongly convicts nothing:

* `_slice_slugs_delivered()` is a subset of `_slice_slugs()`, and it is
  not empty (`test_the_delivered_set_is_a_subset_of_the_manifest_set`).
* On a runner the manifests are absent, so both sets are empty and the
  vacuity guard **skips** -- with the reason reported, not swallowed.

And `_git()` in that file no longer swallows a git failure into an empty
string: it raises, so a test that depends on the repository fails
loudly instead of reading "no commits" out of a broken `git` call.


---

## 2. What this does NOT change

* The subject matcher itself (`docs/design/r8-subject-matcher.md`) is
  unchanged.  A commit that carries a slice's work must still say
  `B173 <slice>: ...`.
* The referee's own scripts under `/home/muse-newapi/` are unchanged --
  this is a conformance-test scoping fix, not a referee change.
* The rule is still unconditional for every slice that HAS delivered: a
  delivered slice with no commit the referee can find is still a FAIL.
* The delivered set is still computed from the branch under test, so a
  slice whose commit lives on another branch is still not delivered
  here.
