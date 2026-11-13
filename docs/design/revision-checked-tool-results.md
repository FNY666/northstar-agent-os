# Revision-checked tool results

**Slice:** B173 · **Source:** Moltbook `neo_konsi_s2bw`, "the last tool to
finish has no right to own agent state" (post
`87f799a1-245a-4d13-9fcc-5cd7cca53e31`, rank 2 in the sweep).

**Module:** `components/northstar-agent-runtime/revision_checked_tool_results.py`
**Tests:** `components/northstar-agent-runtime/tests/test_revision_checked_tool_results.py`

## The failure the source describes

Verbatim from the post:

> rev 41 的查询最晚返回，覆盖用户在 rev 42 的新目标，单步全成功、整体在昨天上工作。

A query that read revision 41 returned last, and overwrote the user's
newer goal at revision 42. Every individual step reported success; the run
as a whole was working on yesterday's state.

The mechanism, verbatim from the post:

* every tool result carries the **state revision** it was read at;
* writing to current state must perform an **atomic revision check**;
* on mismatch, the result goes to **reconciliation**; the old result is
  kept only as **evidence** and gains no ownership of state.

And the detail that makes it work — a check **before enqueueing does not
count**: the check and the commit can still be interleaved, so the check
must be atomic (check and commit in one indivisible step).

## What Northstar has today (read from the code)

| Question | Answer, with location |
|---|---|
| Is there a revision check when a tool result writes back? | **No.** |
| What revision-related field does the runtime keep? | `policy_revision` — *which policy revision approved this run's tool calls*. Declared at `loop.py:315`, copied into the run record at `loop.py:2252` and `loop.py:2919`. |
| Is that a check? | **No.** It is attribution ("who approved"), not a check ("which revision did you read, and is it still current?"). Nothing consults it at write-back time. |
| Where does write-back happen? | The tool report is appended to `state.tool_reports` at `loop.py:3027`, `loop.py:3032`, `loop.py:3197`, `loop.py:3232`. Nothing there asks the result which revision it read. |
| Does `vector_clock.py` help? | **No.** It orders *events* causally (`happens_before`, `concurrent_with`). It says nothing about which revision a tool result was computed against, and it cannot refuse a write. |
| Does `state_machine.py` help? | **Partly, but not here.** Transitions are guarded and taken under a `threading.RLock` (`state_machine.py:496`), so a guard *could* block a transition — but a guard is a caller-supplied predicate, and no caller supplies a revision guard for tool results. |
| What is the worst case today? | A late tool result that read an older revision can overwrite newer state. Every step reports success; the run silently operates on stale state. |

## What this slice adds

A tool result carries the revision it read. `commit()` verifies that
revision against the current state revision and applies the write **in the
same indivisible step**. A stale result is never applied, is retained
verbatim as evidence, and goes to reconciliation.

### Revision representation

A revision is a caller-supplied **integer seq** — no wall clock, matching
the ledger style used elsewhere in the repository (`vector_clock.py` counts
integer counters; `state_machine.py` sequences are integers).

Comparison is **exact equality**, never "greater or equal". A result that
read revision 41 is stale on a revision 42 state *regardless of how new or
old it looks*: the question is "is this still the state I read?", not "is
this newer than what I have?". A result claiming revision 43 on a
revision 42 state is equally rejected — it does not match either.

### The atomicity mechanism

The check and the write are one step, taken under a `threading.RLock`
(the same primitive `state_machine.py` uses for its transitions;
`ledger_concurrency.py`'s `SidecarLock` is the cross-process analogue and
was read, not copied, since this mechanism is in-process).

There is deliberately **no public "check" method**. A caller cannot run a
pre-check and apply later, because the state can move between the two —
the source's own detail about pre-enqueue checks. The only public write
path is `commit()`.

`commit()` compares twice, and both comparisons must hold:

1. `result.read_revision == current_revision` — the result names the
   revision it read, and that is the revision the caller believes is
   current;
2. `current_revision == ledger.current_revision` — and that revision is
   still the ledger's own.

The second condition is what makes the check *atomic* rather than
advisory. Checking only the caller's claimed revision would let two
commits that both read revision 41 both succeed — the second would
silently overwrite the first, which is precisely the failure the source
describes. Requiring the ledger's revision to still agree means the loser
of the race is **rejected**.

Verified by mutation: removing the second comparison makes
`test_interleaved_commits_do_not_both_succeed` fail with "2 != 1 :
exactly one commit may win" — both commits succeed, the source's failure
reproduced.

### Fail-closed construction

`RevisionCheckedResult.read_revision` is required and has no default.
Omitting it is a `TypeError`; passing `None` raises
`MissingReadRevisionError`; a non-integer or negative revision raises
`InvalidRevisionError`. A result that cannot name the revision it read has
no standing to write to state, and there is no "assume current" fallback.

### Evidence retention

A rejected result is retained in an `EvidenceSlot`, **verbatim** — the same
tool call id, the same read revision, and the *same payload object*. It is
never discarded and never silently overwritten: retaining a *different*
result under a tool call id already held raises
`RevisionCheckedToolResultsError`. Retaining the identical result again is
idempotent, so the original evidence survives.

### Reconciliation

`reconcile()` returns a `Reconciliation` record naming the old result's
tool call id, the revision it read, the current revision, and the
applicability verdict:

* `applicable` / `"applicable"` — the result still names the current
  revision; the recommendation is to re-read the state and re-run the tool.
* `stale_evidence` / `"stale_evidence"` — the state has moved on; the
  recommendation is to retain as evidence and not replay over the current
  state.

Reconciliation **records; it never rewrites state** and never replays
anything. Whether to replay is the caller's decision.

## The three driven paths

All three are driven end to end in the test file, not asserted in
isolation.

**(a) Normal write-back.** A result read at revision 41, state at
revision 41 → `commit()` applies it, the state is updated, revision 42 is
allocated, and nothing is retained as evidence.

**(b) The late overwrite.** A result read at revision 41, state at
revision 42 → `commit()` rejects it. The `apply` callable is **not
called at all** (asserted, so the write cannot run and be undone), the
state still holds the user's newer goal, no revision is allocated, and the
old result is retained verbatim as evidence. `reconcile()` then records the
tool call id, revision 41, revision 42, and the stale-evidence verdict.

**(c) The interleaving.** Two threads each commit a result read at
revision 41, released together by a barrier. Exactly one commits; the
other is **rejected**, not applied. The state holds the winner's value,
the loser is retained as evidence, and the revision advanced exactly once.

## Scope and honest limits

* The module is a **library**, not a wiring change. `loop.py` is **not**
  modified by this slice: connecting the runtime's write-back path
  (`loop.py:3027` and friends) to this check is a separate change, and
  this slice's writable-file set does not include it.
* The mechanism is **in-process**. A ledger is guarded by a
  `threading.RLock`, so it serializes threads in one process. It is not a
  cross-process lock; `ledger_concurrency.py`'s `SidecarLock` is the
  cross-process analogue in this repository.
* The revision is an **integer the caller supplies**. This module does not
  read a wall clock and does not invent revisions; it verifies and
  advances the ones the caller gives it.
* **The module is not declared in `pyproject.toml`.** The runtime
  component's `test_module_layout.test_every_module_is_installed` asserts
  that every module on disk appears in `[tool.setuptools] py-modules`. That
  test already fails at this slice's parent commit — with
  `annotation_pin`, `artifact_authority`, `cancellation_tombstone`,
  `coverage_manifest`, `endpoint_identity`, `evidence_independence`,
  `key_custody`, `ledger_concurrency`, `retry_config`, `state_budget` and
  `strands_checkpoint` undeclared — and `revision_checked_tool_results`
  joins the same list, so **no new test failure appears**. The declaration
  is still owed; this slice's writable-file set covers only the module,
  its tests and this design doc, so it is left to the slice that owns the
  packaging metadata.

## Mapping to the source

**Verbatim from the source:**

* The failure shape (rev 41 / rev 42, single steps all succeed, the run
  works on yesterday's state) — the post's own example numbers, not
  measurements.
* The mechanism: the result carries the revision it read; the write does
  an atomic revision check; a mismatch goes to reconciliation; the old
  result is kept only as evidence.
* The detail: a pre-enqueue check does not count, because the check and
  the commit can be interleaved; the check must be atomic.
* The heat figures: 108 up / 320 comments, as observed during the
  2026-11-14 00:48 sweep of post `87f799a1`.

**Northstar extensions (this repo's design, not the source's):**

* The revision is an integer seq rather than a wall clock — chosen to match
  the repository's ledger style (`vector_clock.py`, `state_machine.py`).
* The check is exact equality rather than an ordering comparison — a
  deliberate choice, since the question is identity with the state read,
  not recency.
* The second comparison (`claimed == ledger.current_revision`) is this
  implementation's way of making the check atomic under a lock; the source
  states the requirement ("the check must be atomic") without specifying
  the mechanism.
* `EvidenceSlot` refuses to overwrite a held tool call id, so evidence
  cannot be silently lost. The source says the old result is "kept only as
  evidence"; the slot's refusal is this repo's strengthening.
* The `Reconciliation` record's two status values (`applicable`,
  `stale_evidence`) and its replay recommendations are this repo's shape.
  The source says a mismatch "goes to reconciliation" and that the old
  result is applicable or stale; it does not specify a record format.
* The ledger's revision advances by one on each committed write. The
  source says the commit "allocates a new revision" without fixing the
  increment.
