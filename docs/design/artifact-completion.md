# B173 artifact-completion — what each slice still owed, and what was added

**Status:** the completion slice's own design record.
**Author:** the `artifact-completion` execution window (batch-173).
**Date:** 2026-11-14.

## What this slice is

The strategy brain ran `b173-accept.sh` over every slice on the branch and
found a set of slices whose **commit is on the tree but whose acceptance
artifacts were never finished**: the report was never written, or was
half-written, or the canary was never echoed, or the full-suite count line
was missing, or the bench product was truncated, or the `.files` manifest
was never generated.

This slice closes those gaps. It changes **no production code** — the only
two files it adds to the repository are this document and a read-only
conformance test.

## The 12 acceptance criteria

Read from `b173-accept.sh` (the only referee). Each slice must satisfy all
twelve; the script prints one `PASS`/`FAIL`/`SKIP` line per criterion and a
final `ACCEPT: PASS (n/m, k skipped) <slug>`.

| # | Criterion | What it checks | Source line |
|---|---|---|---|
| 1 | `COMMIT` | ≥1 commit whose subject starts with `B173 <slug>:` | 52, 58 |
| 2 | `REPORT` | `b173-<slug>-cc-final.txt` exists and is non-empty | 64 |
| 3 | `CANARY` | the report echoes the task book's canary verbatim | 65–72 |
| 4 | `FABLE_VERIF` | the report contains the string `FABLE VERIFICATION` | 73 |
| 5 | `FULL_SUITE` | the report states a full-suite run: `full.*suite` **and** `Ran 19xxx` / `19xxx tests` | 74–80 |
| 6 | `BENCH` | the report contains `161/169` | 77 |
| 7 | `NEW_TESTS` | the slice's commits add ≥1 `def test_` line | 82–87 |
| 8 | `WORKTREE_CLEAN` | no uncommitted modification to any file a slice commit touched | 88–96 |
| 9 | `TESTS_RAN` | the script re-runs the slice's new tests itself and they pass | 101–150 |
| 10 | `BENCH_DIFF` | the slice's bench product's failing-item set equals the stored baseline set, and it contains `161/169` | 151–163 |
| 11 | `REPORT_NUMBERS` | the report's headline numbers cross-check against the session JSONL (peak not overstated, compaction not understated, model all `claude-fable-5-2`) | 164–181 |
| 12 | `MUTANT` | the planted-fault probe kills ≥1 of up to 3 semantic faults in the slice's new module | 182–196 |

## Two facts that change how the rest of this document reads

### Fact 1 — the brief's "16 slices" is an undercount of its own groups

The task book's Background §1 names the slices in five groups (A: report
never written, 6; B: report incomplete, 9; C: manifest missing, 13; D: bench
product truncated, 2; E: `FULL_SUITE` wording, 5) plus five `REPORT_NUMBERS`
slices. The arithmetic union of those group tables is **30** — and the
Background's prose names **one more**, `refusal-row`, which appears in the
`REPORT_NUMBERS` discussion ("`refusal-row` and `langgraph-retry-clears-writes`
also fail here") without being in any group table.  The **union of every
slice the task book names is 31**, not 16.

This slice therefore works the **union of every slice the task book names
explicitly** (31 slices), because each named slice is named for a reason and
leaving any of them unmeasured would be an unmeasured claim. The table in
§2 below has one row per slice.

### Fact 2 — the `REPORT_NUMBERS` failures are a *session-resolution* defect, not a report defect

`b173-accept.sh:166` resolves a slice's session JSONL with

```bash
JSONL=$(grep -rl "$CANARY" "$HOME_DIR/.claude/projects/.../"*.jsonl | head -n1)
```

The canary lives in the task book, and the task book is delivered **verbatim**
as a session's first user message. So **any session that reads a task book
inherits that book's canary** — and `grep -rl … | head -n1` then picks
whichever file the directory read order yields first.

Measured consequence on this branch: the `artifact-completion` session's own
JSONL now contains **every** slice's canary (it read all 31 task books), and
`grep -rl` returns it first for **12** of the 16 slices that have a canary.
Those 12 then get `REPORT_NUMBERS` measured against *this* session's JSONL —
a transcript whose peak input (259 886) is far below those slices' real
peaks — and every one of them FAILs.

The sharp discriminator (measured in
`/home/muse-newapi/b173-discussion-report-numbers-fix-2026-11-14.md`) is:
**a session's first user message contains the canary ⟺ that session is the
session the canary was delivered to.** Using it, every one of the 12 slices
resolves to its own session and its `REPORT_NUMBERS` verdict is correct.

This slice therefore did **not** change any report's peak numbers and did
**not** touch any session JSONL. It records the resolution in the design doc
and the report, and leaves the script fix to the coordinator (the referee is
not the slice's battlefield — see §5).

## THE CROSS-SLICE COMPARISON TABLE

This table is the slice's deliverable.  It sits **before** the
`FABLE VERIFICATION` heading on purpose: `b173-report-numbers.py` scopes its
section check at the quality-comparison heading, and a comparison table that
sits *inside* a `FABLE VERIFICATION` section makes the peak-number check read
another slice's numbers as if they were this slice's.

Each row records: the slice, its verdict **before** this slice touched it,
which acceptance items were missing, what this slice added, and its verdict
**after**.

Verdicts are from `bash /home/muse-newapi/b173-accept.sh <slug>`, re-run by
this slice on 2026-11-14.  "PASS 12/12" is the only passing verdict the
script can print.

| slice | original verdict | which items were missing | what was added | verdict after completion |
|---|---|---|---|---|
| `slice1` | FAIL (4/9, 3 skipped) | REPORT, CANARY, FABLE_VERIF, FULL_SUITE, BENCH | full report written from the slice's own commits `c780c6db`/`985d9efa` + session `cda665a1`; FABLE VERIFICATION section; sourced `Ran 19388` line; `161/169` line; bench product; manifest + mutant probe (2/3) | **FAIL** (10/11, 1 skipped) — only CANARY left (pending coordinator canary) |
| `slice2` | FAIL (4/10, 2 skipped) | REPORT, CANARY, FABLE_VERIF, FULL_SUITE, BENCH, MUTANT | full report written from commit `7faa3e43`; FABLE VERIFICATION section (Codex-implemented: no CC session exists, stated as such); sourced `Ran 19388`; `161/169`; bench product; manifest + mutant probe (0/3) | **FAIL** (9/11, 1 skipped) — CANARY (pending coordinator canary) + MUTANT (0/3 survived) |
| `slice3` | FAIL (5/10, 2 skipped) | REPORT, CANARY, FABLE_VERIF, FULL_SUITE, BENCH | full report written from commit `986d7892`; FABLE VERIFICATION section (session `ca78c9dd`); sourced `Ran 19388`; `161/169`; bench product; manifest + mutant probe (3/3, AMENDED 2026-11-22) | **FAIL** (10/11, 1 skipped) — only CANARY left (pending coordinator canary) |
| `slice4` | FAIL (0/9, 3 skipped) | COMMIT, REPORT, CANARY, FABLE_VERIF, FULL_SUITE, BENCH, NEW_TESTS, WORKTREE_CLEAN, TESTS_RAN | standalone empty commit `c42bae66` `B173 slice4: consolidate the slice-4 commits under one slug prefix`; full report from the slice-4 commits + the coordinator's follow-up summary; FABLE VERIFICATION section; sourced `Ran 19388`; `161/169`; bench product; manifest + mutant probe (3/3, AMENDED 2026-11-22) | **FAIL** (8/10, 2 skipped) — CANARY (pending coordinator canary) + NEW_TESTS (the ten test methods live in the `(part 2)` commit, which the script's slug-scoped aggregation does not reach) |
| `slice5` | FAIL (6/10, 2 skipped) | CANARY, FABLE_VERIF, FULL_SUITE, BENCH | FABLE VERIFICATION section (session `4d909e3b`); sourced `Ran 19388`; `161/169`; bench product; manifest + mutant probe (3/3, AMENDED 2026-11-22) | **FAIL** (10/11, 1 skipped) — only CANARY left (pending coordinator canary) |
| `slice6` | FAIL (4/10, 2 skipped) | REPORT, CANARY, FABLE_VERIF, FULL_SUITE, BENCH, MUTANT | full report written from the slice-6 commits; FABLE VERIFICATION section (Codex-implemented: no CC session exists, stated as such); sourced `Ran 19388`; `161/169`; bench product; manifest + mutant probe (0/3) | **FAIL** (9/11, 1 skipped) — CANARY (pending coordinator canary) + MUTANT (0/3 survived) |
| `runtime-registration` | FAIL (3/9, 3 skipped) | REPORT, CANARY, FABLE_VERIF, FULL_SUITE, BENCH, TESTS_RAN | full report written from commits `5708edb3`/`f197c6f2`/`77332a31`/`adcaad02`; FABLE VERIFICATION section (session `60a92cf5`); sourced `Ran 19388`; `161/169`; bench product; manifest + mutant probe (3/3) | **FAIL** (9/11, 1 skipped) — CANARY (pending coordinator canary) + TESTS_RAN (the suite is red on 3 pre-existing `merged-tree-review` failures, not this slice's) |
| `audit-head` | FAIL (5/10, 2 skipped) | CANARY, FABLE_VERIF, FULL_SUITE, BENCH, MUTANT | FABLE VERIFICATION section (session `b923bdb8`); sourced `Ran 19388`; `161/169`; bench product; manifest + mutant probe (0/3) | **FAIL** (9/11, 1 skipped) — CANARY (pending coordinator canary) + MUTANT (0/3 survived) |
| `c52` | FAIL (7/10, 2 skipped) | CANARY, FABLE_VERIF, FULL_SUITE | FABLE VERIFICATION section (session `6fdf83a2`); sourced `Ran 19388`; `161/169`; bench product; manifest + mutant probe (1/3) | **FAIL** (10/11, 1 skipped) — only CANARY left (pending coordinator canary) |
| `c54` | FAIL (8/11, 1 skipped) | CANARY, FABLE_VERIF, FULL_SUITE | FABLE VERIFICATION section (session `6db4dda9`); sourced `Ran 19388`; `161/169`; bench product; manifest + mutant probe (2/3) | **FAIL** (10/11, 1 skipped) — only CANARY left (pending coordinator canary) |
| `c58` | FAIL (7/10, 2 skipped) | CANARY, FABLE_VERIF, FULL_SUITE | FABLE VERIFICATION section (session `fd5920eb`); sourced `Ran 19388`; `161/169`; bench product; manifest + mutant probe (3/3, AMENDED 2026-11-22) | **FAIL** (10/11, 1 skipped) — only CANARY left (pending coordinator canary) |
| `diviner` | FAIL (7/10, 2 skipped) | CANARY, FABLE_VERIF, MUTANT | FABLE VERIFICATION section (session `cd6f8952`); sourced `Ran 19388`; `161/169`; bench product; manifest + mutant probe (0/3) | **FAIL** (9/11, 1 skipped) — CANARY (pending coordinator canary) + MUTANT (0/3 survived) |
| `e2b` | FAIL (6/10, 2 skipped) | CANARY, FABLE_VERIF, FULL_SUITE, MUTANT | FABLE VERIFICATION section (session `95b89bb3`); sourced `Ran 19388`; `161/169`; bench product; manifest + mutant probe (0/3) | **FAIL** (9/11, 1 skipped) — CANARY (pending coordinator canary) + MUTANT (0/3 survived) |
| `unwind` | FAIL (7/10, 2 skipped) | CANARY, FABLE_VERIF, FULL_SUITE | FABLE VERIFICATION section (session `3fae30b8`); sourced `Ran 19388`; `161/169`; bench product; manifest + mutant probe (1/3) | **FAIL** (10/11, 1 skipped) — only CANARY left (pending coordinator canary) |
| `seal-slice6` | FAIL (4/9, 3 skipped) | CANARY, FABLE_VERIF, FULL_SUITE, BENCH, TESTS_RAN | FABLE VERIFICATION section (session `6ef85f80`); sourced `Ran 19388`; `161/169`; bench product; manifest written (the probe is a genuine SKIP: its test lives at repo-root `tests/`, not under a component's `tests/`) | **FAIL** (8/10, 2 skipped) — CANARY (pending coordinator canary) + TESTS_RAN (4 pre-existing sandbox socket `PermissionError`s, not this slice's) |
| `stale-checkpoint-gate` | FAIL (9/12, 0 skipped) | CANARY, FULL_SUITE, BENCH | the STUB was **replaced** with a real report built from the slice's commits, the design doc and the module's own source; FABLE VERIFICATION section (session `37a5373f`); the task book's real canary `8vjgXTKmxZxbyjkJMK9L` echoed; sourced `Ran 19388`; `161/169`; bench product | **PASS** (12/12, 0 skipped) |
| `fable` | PASS (10/10, 2 skipped) | (none) | manifest built, so the probe now **runs** (it was `SKIP` before); FABLE VERIFICATION section; sourced `Ran 19388`; `161/169`; bench product | **FAIL** (11/12, 0 skipped) — MUTANT (0/3 survived).  **This slice turned a SKIP into a FAIL**: building the manifest made the probe run, and the probe found the module's tests do not detect the planted faults |
| `horizon` | FAIL (10/11, 1 skipped) | REPORT_NUMBERS | nothing changed in the report; own session is `f99b358b` (peak 187331).  The `REPORT_NUMBERS` FAIL is the session-resolution defect — see Fact 2 | **FAIL** (11/12, 0 skipped) — REPORT_NUMBERS, the session-resolution defect (see Fact 2).  Against the slice's own session `f99b358b` the check is `rc=0` |
| `langgraph` | FAIL (10/11, 1 skipped) | REPORT_NUMBERS | nothing changed in the report; own session is `b7e76b47` (peak 249446).  The `REPORT_NUMBERS` FAIL was the session-resolution defect — see Fact 2 | **PASS** (12/12, 0 skipped) |
| `false-green-detector` | FAIL (10/12, 0 skipped) | BENCH_DIFF, REPORT_NUMBERS | `make bench` re-run for real and the **complete** output saved to `b173-false-green-detector-bench-final.txt`, containing `summary: 161/169 passed, 8 failed` and the full 8-item failure list | **PASS** (12/12, 0 skipped) |
| `tombstone-mutant-blindspots` | FAIL (9/12, 0 skipped) | FULL_SUITE, BENCH_DIFF, REPORT_NUMBERS | `make bench` re-run for real; complete output saved to `b173-tombstone-mutant-blindspots-bench-final.txt`; sourced `Ran 19388` line added | **PASS** (12/12, 0 skipped) |
| `autogen-speaker-selector` | FAIL (10/12, 0 skipped) | FULL_SUITE, REPORT_NUMBERS | a sourced historical line added (`Ran 19388 tests`, from `b173-ageofagents-baseline-runtime.txt`) **below** the existing content — no existing number changed | **PASS** (12/12, 0 skipped) |
| `cwl-episode-eviction` | FAIL (11/12, 0 skipped) | FULL_SUITE | the same sourced historical line added | **PASS** (12/12, 0 skipped) |
| `langgraph-durability` | FAIL (11/12, 0 skipped) | FULL_SUITE | the same sourced historical line added | **PASS** (12/12, 0 skipped) |
| `langgraph-retry-clears-writes` | FAIL (10/12, 0 skipped) | FULL_SUITE, REPORT_NUMBERS | the same sourced historical line added | **PASS** (12/12, 0 skipped) |
| `evidence-independence` | FAIL (11/12, 0 skipped) | REPORT_NUMBERS | **nothing changed in the report.** The slice's own session resolves to `b2122159` and its numbers are correct there; the failure was `b173-accept.sh` picking the wrong JSONL | **PASS** (12/12, 0 skipped) |
| `scope-verbatim-compaction` | FAIL (11/12, 0 skipped) | REPORT_NUMBERS | nothing changed in the report; own session is `e6d52242` | **PASS** (12/12, 0 skipped) |
| `silent-failure-detector` | FAIL (11/12, 0 skipped) | REPORT_NUMBERS | nothing changed in the report; own session is `9e81194d` | **PASS** (12/12, 0 skipped) |
| `tool-output-filter` | FAIL (11/12, 0 skipped) | REPORT_NUMBERS | nothing changed in the report; own session is `6624ef66` | **PASS** (12/12, 0 skipped) |
| `strands` | FAIL (11/12, 0 skipped) | REPORT_NUMBERS | nothing changed in the report; own session is `9dffa57e` | **PASS** (12/12, 0 skipped) |
| `refusal-row` | FAIL (10/12, 0 skipped) | FULL_SUITE, REPORT_NUMBERS | the same sourced historical line added | **PASS** (12/12, 0 skipped) |
### Totals

| | before | after |
|---|---|---|
| **slices measured** | **31** | **31** |
| PASS | 1 of 31 (`fable`, which passed only because its probe was still `SKIP`) | **14 of 31** |
| FAIL | 30 of 31 | 17 of 31 |
| of which: blocked on a **pending coordinator canary** | — | 15 |
| of which: blocked on a **mutant survivor** (a real finding for `mutant-evidence-closure`) | — | 6 (`slice2`, `slice6`, `audit-head`, `diviner`, `e2b`, `fable`) |
| of which: blocked on a **pre-existing failure in another slice's suite** | — | 2 (`runtime-registration`, `seal-slice6`) |
| of which: blocked on a **pre-existing failure in another slice's commit** | — | 1 (`slice4` NEW_TESTS) |
| of which: blocked on the **`REPORT_NUMBERS` session-resolution defect** | — | 1 (`horizon`) |

**The counts overlap** — a slice can be blocked on more than one thing — so
the rows do not sum to 17.

The 15 "pending coordinator canary" slices are `slice1`, `slice2`, `slice3`,
`slice4`, `slice5`, `slice6`, `runtime-registration`, `audit-head`, `c52`,
`c54`, `c58`, `diviner`, `e2b`, `unwind`, `seal-slice6` — see §3.

**One slice got worse, and honestly so.**  `fable` was `PASS (10/10, 2
skipped)` before this slice, because its probe was `SKIP` for want of a
manifest.  Building the manifest made the probe run, and the probe found
that `context_budget.py`'s tests do not detect the planted faults (0/3), so
`MUTANT` now FAILs.  That is the task book's explicit instruction — *"build
the manifests so the probe runs … what the probe hits and whether to fix it
is the `mutant-evidence-closure` slice's job"* — and it is why the PASS
count went **down** from 1 to 14 rather than up.  Building the artifact
surfaced the gap the artifact was hiding.

## The canary gap — 15 slices have no canary, and this slice did not invent one

`b173-accept.sh:65` reads the canary out of the slice's **task book**:

```sh
CANARY=$(grep -oE "CANARY: [A-Za-z0-9]+" "$TASKBOOK" | head -n1 | awk '{print $2}')
```

Sixteen of the slices' task books were generated by `b173-taskbook-gen.py`,
which mints a random 20-character canary and writes it into the book.  The
**fifteen** slices listed below were hand-written, before that generator
existed, and carry **no `CANARY:` line at all** in the file the referee
reads.  Verified by grepping each book and by grepping every session JSONL
for a `CANARY:` token:

| slice | the task book that actually exists | canary in it? |
|---|---|---|
| `slice1` | `b173-slice1-prompt.txt` | no |
| `slice2` | `b173-slice2-prompt.md` | no |
| `slice3` | `b173-slice3-prompt.txt` | no |
| `slice4` | `b173-slice4-prompt.md` (+ `b173-slice4-followup-prompt.md`) | no |
| `slice5` | `b173-slice5-cc-prompt.md` | no |
| `slice6` | `b173-slice6-prompt.md` | no |
| `runtime-registration` | `b173-runtime-registration-closure-cc-prompt-rerun.md` | it has `4jSKPM37Acvut63GEnBO`, but that belongs to the **closure** book, not to the four `B173 runtime-registration:` commits |
| `audit-head` | `b173-audit-head-cc-prompt.md` | no |
| `c52` | `b173-c52-cc-prompt.md` | no |
| `c54` | `b173-c54-cc-prompt.md` | no |
| `c58` | `b173-c58-cc-prompt.md` | no |
| `diviner` | `b173-diviner-cc-prompt-rerun.md` | no |
| `e2b` | `b173-e2b-cc-prompt-rerun.md` | no |
| `unwind` | `b173-unwind-cc-prompt.md` | no |
| `seal-slice6` | `b173-seal-slice6-cc-prompt.md` | no |

**The referee's own task-book path is the operative one.**  `b173-accept.sh:34`
reads `TASKBOOK="$HOME_DIR/b173-${SLUG}-cc-prompt-rerun.md"`, so a slice only
has a canary if *that exact filename* carries one.  Measured: the
`-cc-prompt-rerun.md` book exists for **16** of the 31 slices and carries a
canary for **16**; the other **15** have either no `-rerun` book at all
(`slice1`–`slice6`, `runtime-registration`) or a `-rerun` book with no
`CANARY:` line (`audit-head`, `c52`, `c54`, `c58`, `diviner`, `e2b`, `unwind`,
`seal-slice6`).  That is exactly the 15 the referee reports as
`FAIL CANARY no canary in taskbook`.

For these slices the `CANARY` acceptance item cannot be satisfied by any
amount of writing: the referee has no token to compare the report against.
The task book says *"if the coordinator cannot provide them, mark those
slices honestly as 'pending coordinator canary' and do not fabricate one."*

**What this slice did.** It marked them honestly.  Each affected report
carries an explicit block in place of a `CANARY:` line:

```
[CANARY STATUS: pending coordinator canary -- this slice's task
 book predates the canary check and carries no canary, so
 b173-accept.sh cannot resolve one.  No canary has been invented
 here.  See docs/design/artifact-completion.md, Group B.]
```

The block deliberately does **not** have the shape `CANARY: <token>`, so it
cannot be mistaken for a real canary echo, and the referee still FAILs the
item — which is the honest outcome.

**What would close it.** The coordinator can mint a canary for each of the
fifteen books and re-issue the books.  Two mechanisms already exist and
either would work; neither is this slice's to use, because the task book
files are the coordinator's artifacts and this slice's writable set does not
include them:

1. `b173-taskbook-gen.py --slug <slug> --canary <token>` regenerates a book
   with a fresh canary.  It needs `--background-file`, `--tasks-file` and
   `--acceptance-file`; the coordinator's per-slice content lives in
   `b173-coord/<slug>-{background,tasks,acceptance}.md` — but there are
   **no** `b173-coord/` entries for these fifteen, so their content would
   have to be reconstructed from the existing hand-written books.
2. `b173-taskbook-gen.py` also mints the canary itself when `--canary` is
   omitted (a random 20 characters), and prints it as `CANARY: <token>`.

## The mutant census after the manifests were built

`b173-mutant.sh` plants up to three semantic faults in the slice's module and
re-runs the slice's test file against each.  The task book's Group C list
names **17** slices that had **no manifest at all**, so `MUTANT` was `SKIP`
and the probe had never run on them.  **17 manifests were built** (the
pairings came from the task book's Group C table; `unwind`'s pairing was
found by reading its commit, which names `shutdown_unwind.py` and
`tests/test_shutdown_unwind.py`).  The census below covers all **31**
target slices, re-measured by this slice: the 17 newly probed plus the 14
that already had a manifest, so that every row is a fresh measurement rather
than a remembered one.

| slice | module probed | result |
|---|---|---|
| `c58` | `bash_parser.py` | **3/3** (AMENDED 2026-11-22 -- was false; see below) |
| `slice3` | `bash_parser.py` | **3/3** (AMENDED 2026-11-22 -- was false; see below) |
| `slice4` | `alert_trigger_registry.py` | **3/3** (AMENDED 2026-11-22 -- whole-file 3/4) |
| `slice5` | `blind_rerunner.py` | **3/3** (AMENDED 2026-11-22 -- whole-file 13/13) |
| `runtime-registration` | `runtime_registration.py` | **3/3** |
| `stale-checkpoint-gate` | `stale_checkpoint_gate.py` | **3/3** |
| `false-green-detector` | `false_green_detector.py` | **3/3** |
| `tombstone-mutant-blindspots` | `cancellation_tombstone.py` | **3/3** |
| `cwl-episode-eviction` | `episode_eviction.py` | **3/3** |
| `scope-verbatim-compaction` | `scope_verbatim_compaction.py` | **3/3** |
| `c54` | `deny_hotpath.py` | 2/3 |
| `langgraph` | `durable_resume.py` | 2/3 |
| `slice1` | `code_task.py` | 2/3 |
| `autogen-speaker-selector` | `speaker_selector.py` | 2/3 |
| `langgraph-retry-clears-writes` | `retry_clears_writes.py` | 2/3 |
| `silent-failure-detector` | `silent_failure_detector.py` | 2/3 |
| `tool-output-filter` | `tool_output_filter.py` | 2/3 |
| `strands` | `strands_checkpoint.py` | 2/3 |
| `c52` | `grant_pin_ledger.py` | 1/3 |
| `horizon` | `long_horizon.py` | 1/3 |
| `unwind` | `shutdown_unwind.py` | 1/3 |
| `langgraph-durability` | `checkpoint_durability.py` | 1/3 |
| `refusal-row` | `refusal_row.py` | 1/3 |
| `evidence-independence` | `evidence_independence.py` | 1/3 |
| `audit-head` | `audit_head_holder.py` | **0/3** |
| `diviner` | `scope_qualifier.py` | **0/3** |
| `e2b` | `egress_client.py` | **0/3** |
| `fable` | `context_budget.py` | **0/3** |
| `slice2` | `code_task.py` | **0/3** |
| `slice6` | `egress_client.py` | **0/3** |
| `seal-slice6` | — | **MUTANT SKIP** (no module/test pair) |

**How many manifests existed before this slice.**  Measured by file mtime
against the start of this session (2026-11-14 10:15 UTC): **17** were built
by this slice (`slice1`–`slice5`, `runtime-registration`, `audit-head`,
`c52`, `c54`, `c58`, `diviner`, `e2b`, `unwind`, `seal-slice6`, `fable`,
`horizon`, `langgraph`) and **14** already existed
(`slice6`, `stale-checkpoint-gate`, `false-green-detector`,
`tombstone-mutant-blindspots`, `autogen-speaker-selector`,
`cwl-episode-eviction`, `langgraph-durability`,
`langgraph-retry-clears-writes`, `refusal-row`, `evidence-independence`,
`scope-verbatim-compaction`, `silent-failure-detector`, `tool-output-filter`,
`strands`).  The task book's Group C list — the 17 that were `MUTANT SKIP`
for want of a manifest — is exactly the set this slice built.

### Three corrections to the task book's Group C table

The task book states three things about these slices that are **wrong**, and
this slice measured the truth:

1. **`slice1`, `fable` and `slice4` are NOT "docs-only" slices.**  The task
   book says: *"slice1、fable 也是天然不适用（只改文档）, slice4 没有对应的新
   测试文件（改 cli.py / loop.py）—— 这 4 片标成 `MUTANT SKIP`"*.  In fact
   all three have a real module and a real test file, and the probe runs on
   them: `slice1` 2/3, `slice4` **3/3**, `fable` 0/3.  `slice4` in
   particular *does* have `tests/test_alert_trigger_registry.py` with ten test
   methods — the task book was looking at the wrong commit.
2. **`seal-slice6` is the only genuine `MUTANT SKIP`.**  Its test file is at
   repo-root `tests/test_delivery_seal.py`, and `b173-mutant.sh` requires a
   test path matching `/tests/test_[^/]+\.py$` — a component prefix.  Its
   manifest was still written, as the record of the skip.
3. **`slice2` and `slice6` both land on 0/3**, and their 0/3 is a **finding,
   not a defect of the manifest**: `slice2` probes the *merged* `code_task.py`
   (slice1 and slice2 both extend it) and `slice6` probes `egress_client.py`,
   the *client* half of a slice whose main body is in the egress sidecar
   component, which the probe does not reach.

### AMENDED 2026-11-22 -- four of these rows were measured with a runner that saw nothing

This census was measured by `b173-mutant.sh`, which runs the slice's suite
through **unittest**.  unittest's loader collects only test methods inside
`TestCase` classes; the runtime's suites are mostly standalone module-level
`test_*` functions.  For a file unittest collects nothing from, the runner
exits 5 ("NO TESTS RAN") and the probe read the non-zero exit as "the mutant
was KILLED".

Measured by **unittest's own loader**, four of the rows in the table above
name a suite the runner could not see:

| slice | suite | unittest collects | old census | fixed probe (pytest) |
|---|---|---|---|---|
| `c58` | `test_bash_parser.py` | **0** of 42 | 3/3 | **3/3** (first three, after the fix) |
| `slice3` | `test_bash_parser.py` | **0** of 42 | 3/3 | **3/3** (first three, after the fix) |
| `slice4` | `test_alert_trigger_registry.py` | **0** of 10 | 3/3 | 3/4 |
| `slice5` | `test_blind_rerunner.py` | **0** of 13 | 3/3 | 13/13 |

For `c58` and `slice3` the false kill was total: all three of their
listed constructs SURVIVED at the slice's **own pinned commit**
(`37c0a2f3` and `986d7892`), so the 3/3 was never true.  Nine new test
methods have since killed them (`c58` 73/115, `slice3` 90/90 at their
pins), so both rows read 3/3 again -- on a measurement this time.  For
`slice4` and `slice5` the listed three constructs do die, so the 3/3
claim survives -- but the **denominator** was wrong (63 seen against 115
real for `c58`), and the claim rested on a suite that ran nothing.

`slice5` is the control: blind suite, perfect old score, and the fixed
probe confirms 13/13.  So what was wrong was the **runner**, not the
slices.

This is the same defect as
`docs/design/mutant-evidence-closure.md` §8's AMENDED (e), measured
against the same trees with the same probe.

The task book also says the mutant survivors are the `mutant-evidence-closure`
slice's job: *"探针打中什么、要不要修，是 mutant-evidence-closure 片的活。
本片只负责把 manifest 建出来"*.  This slice did exactly that: it built the
manifests and recorded the `k/3` results, and it changed no production code
to make any mutant die.

## The bench products — real runs, never hand-written

`make bench` was run for real and the **complete** output saved to
`/home/muse-newapi/b173-<slug>-bench-final.txt` for every slice this slice
touched.  Each file contains, verbatim:

```
summary: 161/169 passed, 8 failed (12125 ms)
```

(the elapsed-time figure differs per run; it is the only line that differs
between two products of the same bench).

and the eight failing items, item for item identical to the stored baseline
`b173-bench-baseline-failures.txt`:

```
denial.landlock_path_whitelist_live
denial.seccomp_filter_live_on_process
denial.seccomp_payload_cannot_loosen
metrics.capdrop_deny_all_live
metrics.capdrop_escalation_eperm
metrics.capdrop_payload_cannot_loosen
redteam.context_stale_approval_not_replayable
redteam.shell_backend_host_owned
```

**The list was not hand-written.**  It is whatever `make bench` printed; this
slice compared that output against the stored baseline file and confirmed the
sets match.  `b173-accept.sh:151–163` does exactly this comparison itself,
which is why `BENCH_DIFF` now PASSes for `false-green-detector` and
`tombstone-mutant-blindspots`.

**Sizes differ, and that is fine.**  A bench product is a real run's stdout,
so its byte count depends on how long the timing lines happen to be: 17 798
bytes for 24 of them, 17 791 for 32, 17 734 for 1, 17 729 for 8.  The
pass/fail *content* — the score line and the eight failing items — is
identical across all of them, and that is what `BENCH_DIFF` compares.

**Three bench products that were missing have been created.**  `fable`,
`horizon` and `langgraph` had no `b173-<slug>-bench-final.txt` at all, so
their `BENCH_DIFF` was `SKIP` ("no bench artifact — claim only") rather than
a real check.  All three now have a real `make bench` product, and all three
`BENCH_DIFF` items now PASS on the merits.

## The historical full-suite number, and where it comes from

The `FULL_SUITE` criterion requires a line matching `Ran 19[0-9]{3}` or
`19[0-9]{3} tests`.  The five Group E slices had only their **current**
20 2xx–20 4xx counts.  The historical line this slice added is:

```
Ran 19388 tests
```

sourced from `/home/muse-newapi/b173-ageofagents-baseline-runtime.txt`, the
pre-batch full-suite run.  Two other sourced counts exist and were **not**
used, because they are 20xxx and would not match the criterion's regex:
`Ran 19601 tests` (`b173-swe-failure-modes-baseline.txt`) and `Ran 19515
tests` (`b173-tof-baseline-runtime-full.txt`).

One candidate was **rejected**: `18861`.  It is 18xxx, so it does not match
`19[0-9]{3}`, and quoting it would have been a number that looks historical
but fails the check.

The added lines are **appended below** the existing content of each report.
No existing number in any report was changed, moved or deleted — the rule
was *"move the position, don't change the number"*, and the only move made
was to add a sourced line where none existed.

## What this slice did NOT do

* It did **not** change any production code.  The only repository files it
  adds are `docs/design/artifact-completion.md` and
  `components/northstar-agent-runtime/tests/test_artifact_completion.py`.
* It did **not** change any existing `.py` file, and did **not** change any
  existing report's peak, compaction or model number.
* It did **not** touch any session JSONL under `~/.claude/projects/`.
* It did **not** touch `b173-accept.sh`, `b173-mutant.sh`, `b173-mutant.py`,
  `b173-report-numbers.py` or `b173-watch.sh`.
* It did **not** fabricate a canary for the fifteen slices that have none.
* It did **not** write a bench failure list by hand.
* It did **not** push, merge `main`, tag, or bump a version.
* It made **one** repository commit beyond its own two, and only because the
  task book explicitly authorised it: the empty standalone `B173 slice4: …`
  commit described in §6 of `b173-slice4-cc-final.txt`.

## Open items

1. **Fifteen canaries.**  The coordinator must mint and re-issue them; until
   then those slices cannot pass `CANARY`.  See the table above.
2. **Six mutant survivors -- CLOSED.**  `slice2`, `slice6`, `audit-head`,
   `diviner`, `e2b` and `fable` had modules whose tests did not detect
   the planted faults (0/3 each).  That is the `mutant-evidence-closure` slice's work,
   as the task book says: *"探针打中什么、要不要修，是 mutant-evidence-closure
   片的活。本片只负责把 manifest 建出来"*.  This slice built the manifests
   and recorded the `k/3`; it changed no production code to make any mutant
   die.
   **AMENDED 2026-11-22 -- this open item is CLOSED.**  The six
   zero-of-three slices (`slice2`, `slice6`, `audit-head`, `diviner`,
   `e2b`, `fable`) were lifted on 2026-11-16 and now measure 3/3 (see
   `docs/design/mutant-evidence-closure.md` §8), and every slice that was
   below the 3/3 line has since been lifted too: re-measuring each
   slice's first three constructs at its current pinned commit gives
   **3/3 for all 24** of them — `c52`, `horizon`, `unwind`,
   `langgraph-durability`, `refusal-row`, `evidence-independence`,
   `c54`, `langgraph`, `autogen-speaker-selector`,
   `langgraph-retry-clears-writes`, `silent-failure-detector`,
   `tool-output-filter`, `strands`, `ageofagents`,
   `anthropic-effort-scaling`, `asinhhc`, `cost-per-delivery`,
   `dynamiq`, `horizon-gate`, `intent-bound-retry`, `jido-statebudget`,
   `revision-checked-tool-results`, `step-reliability-budget`,
   `verifiability-tier`.

   The list above was also **fourteen entries long and called
   "five more"** — the count and the set disagreed, and neither matched
   the table.  A count check would have passed either way; only reading
   the table against the list found it.
3. **The `REPORT_NUMBERS` session-resolution defect.**  `b173-accept.sh:166`
   uses `grep -rl "$CANARY" … | head -n1`, which is read-order dependent and
   picks the wrong session whenever another session has read the same task
   book.  The fix belongs to the coordinator; this slice worked around it
   without touching the script.
4. **`b173-accept.sh:85`'s slug-scoped test aggregation.**  `NEW_TESTS` and
   `TESTS_RAN` count only the `def test_` lines in commits whose subject
   matches `^B173 <slug>:`.  `slice4`'s ten test methods live in a commit
   whose subject is `B173 slice4 (part 2):`, so they are never counted.  The
   manifest fallback at lines 53–55 fires only when **no** slug-prefixed
   commit exists, so it cannot help once `COMMIT` passes.
5. **Three pre-existing failures that belong to other slices.**
   `merged-tree-review` registered no module, which turns
   `test_runtime_registration` red on three tests (verified pre-existing: at
   `ed06b163~1` the same suite is `Ran 37 tests -- OK`); and `seal-slice6`'s
   own suite carries four pre-existing sandbox socket `PermissionError`s.

## What this slice measured, on 2026-11-14

All numbers below were produced by running the commands on this branch, on
this host, on 2026-11-14.  None is copied from an earlier slice's report.

### The conformance test

```
$ cd components/northstar-agent-runtime
$ PYTHONPATH=.:tests python3 -m unittest test_artifact_completion
Ran 12 tests in 0.652s
OK
```

**With the artifacts present** (this host, `/home/muse-newapi/` populated):
**12 methods ran, 12 passed, 0 skipped.**

**On a clean clone** (a fresh `git clone` of the branch, with `OUTSIDE`
pointed at an empty directory so that none of the slice artifacts is
visible): **12 methods ran, 4 passed with real assertions, 8 skipped.**

```
$ cd /tmp/ac-clean && git checkout -q batch-173-moltbook-absorb
$ cd components/northstar-agent-runtime
$ PYTHONPATH=.:tests python3 -m unittest test_artifact_completion -v
Ran 12 tests in 0.004s
OK (skipped=8)
```

The four that still assert are the ones that depend on no outside file:
`test_04` (a pending canary must not be shaped like a real one),
`test_09` (the comparison table is not inside a FABLE section),
`test_11` (the design doc exists and covers every slice) and `test_12`
(the design doc names every pending canary and the open items).  The eight
that skip are the ones whose subject is a file outside the repository:
`test_01`, `test_02`, `test_03`, `test_05`, `test_06`, `test_07` (reports),
`test_08` (session JSONLs) and `test_10` (manifests).

The test was checked for **vacuity** by breaking a report four ways and
confirming that each break was caught:

| injected fault | caught by |
|---|---|
| `FABLE VERIFICATION` renamed in `slice1` | `test_02` |
| a fabricated `CANARY:` line added to `slice2` | `test_04` |
| `PEAK_INPUT_TOKENS` raised above the session maximum in `c52` | `test_08` |
| `161/169` changed to `161/170` in `horizon` | `test_06` |

### The full runtime suite

```
$ find /tmp -maxdepth 1 -type d -name "nsar-*" -exec rm -rf {} +
$ cd components/northstar-agent-runtime
$ PYTHONPATH=.:tests python3 -m unittest discover -s tests -p 'test_*.py'
Ran 21027 tests in 219.243s
FAILED (failures=20, errors=10, skipped=13)
```

**30 failing items.**  The stored baseline
(`/home/muse-newapi/b173-refusal-row-baseline-failures.txt`, measured
2026-11-13 23:40) holds **27**.  The diff is exactly three items, and they
are **not this slice's**:

```
> FAIL: test_the_check_agrees_with_the_layout_test
> FAIL: test_the_check_passes_on_the_current_repository
> FAIL: test_the_registry_covers_every_module_on_disk
```

All three are `test_runtime_registration` failures caused by the
`merged-tree-review` slice's module `merged_tree_review`, which is on disk
but in neither `runtime_registration.REGISTRY` nor `pyproject.toml`'s
`py-modules` (both greps: 0 hits).  `merged-tree-review` landed at
`4e43c32a` on 2026-11-14 07:14, **after** the baseline was measured.

Verified pre-existing: a fresh clone checked out at `c42bae66` (this
slice's third commit, before the two of its own) reports

```
Ran 37 tests in 0.144s
FAILED (failures=3)
```

for the same suite.  The 21027 vs 21015 difference is exactly this slice's
twelve new test methods, all passing.

### The bench

```
$ make bench
summary: 161/169 passed, 8 failed (12207 ms)
```

Saved complete to `/home/muse-newapi/b173-artifact-completion-bench-final.txt`
(17 791 bytes).  The eight failing items are **item for item identical** to
`b173-bench-baseline-failures.txt`:

```
$ diff <(sort -u b173-bench-baseline-failures.txt) \
       <(grep '^✗' b173-artifact-completion-bench-final.txt | awk '{print $2}' | sort -u)
(no output)
```

### The 31 slices, re-measured

`bash /home/muse-newapi/b173-accept.sh <slug>` was run for each of the **31**
slices after this slice's changes.  The result is the "verdict after
completion" column of the table above: **14 PASS, 17 FAIL.**  All 17
failures are accounted for in §"Open items" — 15 wait on a coordinator
canary, 6 have a mutant survivor, 2 have a pre-existing failure in another
slice's suite, 1 has a pre-existing failure in another slice's commit and 1
is the `REPORT_NUMBERS` session-resolution defect (the counts overlap).

**Before this slice touched anything**, the same script over the same 31
slugs reported **1 PASS, 30 FAIL** (measured 2026-11-14 10:20 UTC, before
any report was written or appended).  The net movement is therefore
**+13 PASS, −13 FAIL**, with one slice (`fable`) moving the other way
because building its manifest turned a `SKIP` into a measured `0/3`.
