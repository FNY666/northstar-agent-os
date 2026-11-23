# The mutant census and re-measurement artifacts

These are the **measurements** the B173 mutant-evidence checks compare
against.  They live in the repository so that the checks that use them
run on a machine that does not have the coordinator's directory — a CI
runner, a fresh clone, a reviewer's laptop.

## Why they are here at all

Each artifact was produced by running the mutant probe against a tree.
The measurement is expensive (a worktree per slice, a probe per
construct), so the artifacts are **snapshots**: taken once, on a named
tree, and then compared against the table.

The checks that use them are:

| Artifact | Scope | Used by |
|---|---|---|
| `census-parallel-corrected.txt` | slice | `test_equivalence_table_coverage.py` |
| `census-parallel.txt` | slice | `test_equivalence_table_coverage.py`, `test_unittest_blind_slices.py` |
| `census-v3.txt` | module | `test_equivalence_table_coverage.py` |
| `k3-remeasure.txt` | slice, first three constructs | `test_census_table_freshness.py` |
| `k3-blind-rows.txt` | slice, whole file | `test_census_table_freshness.py`, `test_unittest_blind_slices.py` |
| `k3-bash-pins.txt` | slice, whole file, at pinned commits | `test_census_table_freshness.py`, `test_unittest_blind_slices.py` |

## The order the artifacts are read in

For each measurement, the **coordinator's copy wins** — it is the
freshest, and re-measuring is the coordinator's decision.  The copies
here are the **fallback** for a machine that does not have it.  The
order is pinned by tests that read the *selected* path, not by a
string comparison against the source.

## The rule these copies exist to satisfy

> **A check whose artifact is a measurement must RUN on a runner.**

A check that reads one of these files and *skips* on a runner has
stopped checking anything — a skip leaves the check unrun, and an
unrun check looks exactly like a passing one.  `tests/test_ci_runner_artifacts.py`
enforces this: it simulates a runner (the coordinator's directory
absent), runs the files that read these artifacts, and **fails** if any
of them skipped **while their artifact is one of the copies below** —
a copy that is present but unused is the failure this catches.  Checks
whose artifact is live state are expected to skip, and the guard
distinguishes the two kinds.

This is why the distinction matters between the two kinds of artifact
the coordinator holds:

| kind | example | copy? | on a runner |
|---|---|---|---|
| **a measurement** | these six files | **yes** | the check **runs** |
| **live state** | `b173-accept.sh`, `b173-mutant.sh`, the taskbooks, the slice manifests, the session JSONLs | no | the check **skips** |

Live state is the coordinator's *moving* state; a copy of it would be a
copy of a moving target, and a stale copy is worse than no copy
because it would make the check assert against a referee that no longer
exists.  A measurement is a snapshot of a named tree, and a snapshot is
still a true claim.

## Provenance

Each artifact is a byte-for-byte copy of the coordinator's file of the
same name.  The copies were taken on 2026-11-22 from
`/home/muse-newapi/`, and their checksums are:

```
071e97989c1293f94e6cfdb9c0b1d282  census-parallel-corrected.txt
0a83d878c0b635145e6773c5073b8dd4  census-parallel.txt
58580b760020bbb0b9ba43b36c0c21d9  census-v3.txt
a13fd3ee55361e887390797c9c586833  k3-remeasure.txt
76acdd50e64725142fc8303ba0d69789  k3-blind-rows.txt
fbeac56b2ea7adeed9edfa7429f0183c  k3-bash-pins.txt
```

**These are claims about a tree, not about the current tree.**  A
census is a snapshot of a mutant probe run against a named tree; if the
tree changes, the census does not follow it automatically.  That is why
the checks that read them are comparisons against a *named* artifact
rather than a re-derivation, and why a stale census is a thing a human
has to notice.

## What this does NOT do

It does not re-take a measurement.  Re-measuring is the coordinator's
decision; this directory only holds snapshots so that the checks can
run off the coordinator's machine.
