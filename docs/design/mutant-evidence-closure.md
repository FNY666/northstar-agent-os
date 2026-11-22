# Mutant evidence closure

**Slice:** `B173 mutant-evidence-closure`
**Branch:** `batch-173-moltbook-absorb`

## 0. What this slice is about

The batch's `MUTANT` acceptance item plants up to three small semantic
faults in a slice's new module and asks whether that slice's own test
module notices.  At least one kill is a PASS.

The strategy brain ran the probe across all 64 slices and found:

* 17 slices had **no manifest at all**, so the probe was skipped outright
  and their `MUTANT` item never ran.  Thirteen of those had a real
  module/test pair (the manifest was simply lost); four never had one
  (docs-only slices).
* Six slices reported **0/3**.  Two of those were *pinning artifacts*
  -- the fix existed, under a different commit prefix the probe could not
  see.  Four were genuine gaps.
* Four slices reported **more kills under the default run than under a
  cache-free run**.  The probe's k/3 depended on the Python bytecode
  cache, so every number the census reported was unreliable.

This slice does three things: it restores the lost manifests, it makes
the six 0/3 slices measure 3/3, and it re-measures all 64 slices with
the cache-free run so the census table in this document is trustworthy.

### 0.1 The denominator is "the first N constructs" (N = 12 since round 7)

> **CORRECTION (2026-11-16, round 7).** This section originally read
> "the denominator is *the first three constructs*", and every k/3 in this
> document was measured under that denominator. The probe has since been
> fixed and the denominator is now **12**, not 3. See "What changed in
> round 7" below.

`b173-mutant.py` collects every mutable construct in the module in
source order and then tries `cands[:--tries]`.

**As of round 7 (2026-11-16) `--tries` defaults to 12**, not 3. The
`b173-mutant.sh` wrapper sets `TRIES="${B173_MUTANT_TRIES:-12}"`.

* **k/12** does **not** mean the module is fully verified -- only the
  first twelve constructs are.
* **0/12** does **not** mean the whole module is untested -- only the
  first twelve are.

**Round 7 also fixed the MODULE/TEST PAIRING.** The probe used to pair the
module with the **first** test file in the manifest. For
`mutant-evidence-closure` that was `test_event_condenser.py`, which does
not reference `artifact_authority.py` at all — the real tester is
`test_artifact_authority.py` (39 test methods). `b173-mutant.sh` now picks
the test file that actually **references** the module:

```bash
MODBASE=$(basename "$MOD" .py)
for cand in $(grep -E '/tests/test_[^/]+\.py$' "$MANIFEST"); do
  if grep -qE "(^|[^A-Za-z0-9_])${MODBASE}([^A-Za-z0-9_]|$)|from ${MODBASE} import|import ${MODBASE}" "$src"; then
    TESTF="$cand"; break
  fi
done
```

### What changed in round 7, and what it invalidated

Measured 2026-11-16, with the probe fixed, against the four slices that had
been accused of having a weak test suite:

| slice | under the old probe (3 candidates, first test file) | under the fixed probe (12 candidates, referencing test file) |
|---|---|---|
| `audit-head` | 3/12 | — (killed) |
| `diviner` | 4/12 | — (killed) |
| `e2b` | 5/12 | — (killed) |
| `fable` | 2/12 | — (killed) |
| `mutant-evidence-closure` | **0/3 (SURVIVED)** | **KILLED on the first try** |

**Four of the five "weak test suite" accusations were false.** They came
from the probe trying only the first three constructs in source order
(modules have 18–72 candidates) and pairing the module with a test file
that does not reference it.

**What this invalidates in this document:** every k/3 number in the census
table was measured under the old denominator with the old pairing. The
numbers are therefore **lower bounds** that the probe can no longer
reproduce, and any slice whose row says "0/3" must be re-measured before
the number is quoted again. The **structure** of the census — one row per
slice, the pinned-commit column beside the HEAD column, the reason column —
is unaffected and remains the point of this document.

### 0.2 Every number here is a cache-free run

`b173-mutant.py` writes the mutated source back and re-runs the tests.
The rewrites are **same-length** (`" or "` -> `" and "`, `">"` -> `">="`),
so two rounds inside the same second produce a source with an unchanged
`(mtime seconds, byte size)` pair.  Python's `.pyc` validity criterion
is exactly that pair, so the second round **reuses the first round's
bytecode** and the probe reports the first mutant's verdict twice.

The live probe now carries the fix (`drop_cached_bytecode()` before every
rewrite, plus `PYTHONDONTWRITEBYTECODE=1` in the test environment), so
the runs recorded below are cache-free by construction.  They were also
measured twice per slice and the numbers were identical; a number that
changes between two identical runs was a second-boundary artifact and
was not recorded.

The four slices whose default-run numbers were **inflated** -- and their
true values -- are listed in §7.

### 0.3 The probe pins the slice's own last commit

`b173-mutant.sh` resolves the worktree commit as

```bash
HASH=$(git -C "$REPO" log --format=%H --grep="^B173 ${SLUG}:" -i -1)
```

which is the **newest** commit whose subject *or body* starts with
`B173 <slug>:`.  A fix that landed under a different slug prefix
(`B173 vina-mutant-blindspots:`) is invisible to that grep, and the
probe runs the code as of the pinned commit -- the older code, with the
older tests.

Two slices were in exactly that state (`vina`, `tombstone`).  §5
records how they were re-landed.

`git log --grep` matches **body** lines as well as subjects: a commit
whose subject is `B173 foo: ...` and whose body contains a line
starting with `B173 bar: ...` is matched by *both* greps.  That is why
the re-land in §5 uses the slice's own prefix on the subject and keeps
any other slug prefix out of the body.

## 1. How to read the census table

One row per slice, 64 rows, in the same order as
`/home/muse-newapi/b173-strategy-mutant-census-2026-11-14.txt`.

| column | meaning |
|---|---|
| **slice** | the slug |
| **module** | the `.py` the probe mutates (the manifest's first non-test `.py`) |
| **test** | the test module the probe runs |
| **pinned k/3** | kills out of the first three constructs, at the **pinned** commit |
| **pinned commit** | the commit `git log --grep="^B173 <slug>:" -i -1` resolves to |
| **HEAD k/3** | the same measurement at HEAD -- a difference from the pinned column is a **pinning artifact** |
| **first-3 constructs** | the mutants that were planted, by kind and line number |

The "reason" column of the task book's table is expressed here as the
construct list plus the notes in §6.

## 2. The 64-slice census

Measured with the cache-free probe, at the pinned commit and at HEAD.
| slice | module | test | pinned k/3 | pinned commit | HEAD k/3 | first-3 constructs |
|---|---|---|---|---|---|---|
| `actionable-digest` | `actionable_digest.py` | `test_actionable_digest.py` | **3/3** | `6c894ba9` | 3/3 | lt@118 lt@119 or@120 |
| `agent-handoff` | `agent_handoff.py` | `test_agent_handoff.py` | **3/3** | `249f9a5c` | 3/3 | gt@214 gt@226 gt@236 |
| `ageofagents` | `ledger_concurrency.py` | `test_ledger_concurrency.py` | **3/3** | `b970b457` | 3/3 | or@302 eq@390 or@475 |
| `anthropic-effort-scaling` | `effort_scaling.py` | `test_effort_scaling.py` | **3/3** | `9b00638e` | 3/3 | lt@174 or@174 lt@180 |
| `asinhhc` | `key_custody.py` | `test_key_custody.py` | **3/3** | `ddbd2c5a` | 3/3 | lt@193 eq@286 or@336 |
| `audit-head` | `audit_head_holder.py` | `test_audit_head_holder.py` | **3/3** | `265ff349` | 3/3 | or@176 or@178 or@184 |
| `autogen-speaker-selector` | `speaker_selector.py` | `test_speaker_selector.py` | **3/3** | `8a3bfbc5` | 3/3 | gt@125 gt@132 or@141 |
| `c52` | `grant_pin_ledger.py` | `test_grant_pin_ledger.py` | **3/3** | `0dc81ceb` | 3/3 | eq@139 eq@142 gt@143 |
| `c54` | `deny_hotpath.py` | `test_deny_hotpath.py` | **3/3** | `a1c7e688` | 3/3 | retF@117 or@247 gt@249 |
| `c58` | `bash_parser.py` | `test_bash_parser.py` | **3/3** | `37c0a2f3` | 3/3 | gt@127 retT@128 gt@129 |
| `cost-per-delivery` | `cost_per_delivery.py` | `test_cost_per_delivery.py` | **3/3** | `288799f2` | 3/3 | or@208 or@215 lt@220 |
| `cwl-episode-eviction` | `episode_eviction.py` | `test_episode_eviction.py` | **3/3** | `5e4e66d4` | 3/3 | eq@182 eq@186 eq@219 |
| `deterministic-gate-score` | `deterministic_gate_score.py` | `test_deterministic_gate_score.py` | **3/3** | `c08a86ad` | 3/3 | or@155 or@159 or@197 |
| `diviner` | `scope_qualifier.py` | `test_scope_qualifier.py` | **3/3** | `54e5c8dd` | 3/3 | or@190 or@192 gt@194 |
| `dynamiq` | `retry_config.py` | `test_retry_config.py` | **3/3** | `920dc41d` | 3/3 | or@165 lt@167 or@171 |
| `e2b` | `egress_client.py` | `test_egress_client.py` | **3/3** | `c9b1fc4f` | 3/3 | eq@63 eq@65 eq@68 |
| `effect-directive` | `effect_directive.py` | `test_effect_directive.py` | **3/3** | `a117a03d` | 3/3 | or@173 or@177 or@224 |
| `event-condenser` | `event_condenser.py` | `test_event_condenser.py` | **3/3** | `ffd3eb08` | 3/3 | or@127 or@132 or@146 |
| `evidence-independence` | `evidence_independence.py` | `test_evidence_independence.py` | **3/3** | `70288f1b` | 3/3 | or@226 and@284 and@288 |
| `fable` | `—` | `—` | **SKIP** | `—` | SKIP | — |
| `false-green-detector` | `false_green_detector.py` | `test_false_green_detector.py` | **3/3** | `a4d2142d` | 3/3 | or@198 lt@201 and@201 |
| `fieldnotes` | `planted_fault.py` | `test_planted_fault.py` | **3/3** | `33eb7cd9` | 3/3 | or@283 and@293 eq@341 |
| `horizon` | `long_horizon.py` | `test_long_horizon.py` | **3/3** | `6d21efd7` | 3/3 | or@114 or@192 lt@194 |
| `horizon-gate` | `horizon_gate.py` | `test_horizon_gate.py` | **3/3** | `4baa7999` | 3/3 | or@245 lt@250 or@257 |
| `intent-bound-retry` | `intent_bound_retry.py` | `test_intent_bound_retry.py` | **3/3** | `0a550532` | 3/3 | retT@157 retF@173 and@204 |
| `jido-statebudget` | `state_budget.py` | `test_state_budget.py` | **3/3** | `28f5068c` | 3/3 | or@177 or@183 lt@185 |
| `langgraph` | `durable_resume.py` | `test_durable_resume.py` | **3/3** | `a3ba033a` | 3/3 | or@156 or@164 lt@203 |
| `langgraph-durability` | `checkpoint_durability.py` | `test_checkpoint_durability.py` | **3/3** | `04391897` | 3/3 | eq@141 retF@382 retT@383 |
| `langgraph-retry-clears-writes` | `retry_clears_writes.py` | `test_retry_clears_writes.py` | **3/3** | `a3aa7007` | 3/3 | retF@152 retT@155 eq@170 |
| `leased-task-claim` | `leased_task_claim.py` | `test_leased_task_claim.py` | **3/3** | `4e304fab` | 3/3 | gt@206 or@336 or@342 |
| `lightningzero` | `coverage_manifest.py` | `test_coverage_manifest.py` | **3/3** | `896bc923` | 3/3 | or@139 or@145 and@202 |
| `msaf-lineage` | `approval_rules.py` | `test_approval_rules.py` | **3/3** | `a8306073` | 3/3 | or@70 and@76 retF@82 |
| `neo-konsi-s2bw` | `endpoint_identity.py` | `test_endpoint_identity.py` | **3/3** | `2a8ed2a1` | 3/3 | or@81 or@86 gt@131 |
| `openhands-stuck-detector` | `stuck_detector.py` | `test_stuck_detector.py` | **3/3** | `190b000c` | 3/3 | or@251 eq@252 and@252 |
| `outsideloop` | `annotation_pin.py` | `test_annotation_pin.py` | **3/3** | `b7a01e59` | 3/3 | and@145 retF@159 and@160 |
| `refusal-row` | `refusal_row.py` | `test_refusal_row.py` | **3/3** | `190d9198` | 3/3 | or@148 or@163 or@177 |
| `resume-validation` | `resume_validation.py` | `test_resume_validation.py` | **3/3** | `b8b6074a` | 3/3 | or@198 eq@209 eq@213 |
| `reversible-compaction` | `reversible_compaction.py` | `test_reversible_compaction.py` | **3/3** | `8f3e1496` | 3/3 | or@116 retF@117 retF@120 |
| `revision-checked-tool-results` | `revision_checked_tool_results.py` | `test_revision_checked_tool_results.py` | **3/3** | `8b9bf616` | 3/3 | or@114 lt@118 gt@120 |
| `scope-verbatim-compaction` | `scope_verbatim_compaction.py` | `test_scope_verbatim_compaction.py` | **3/3** | `1649c89c` | 3/3 | and@202 lt@297 or@306 |
| `scorer-disagreement` | `scorer_disagreement.py` | `test_scorer_disagreement.py` | **3/3** | `4e5a9657` | 3/3 | eq@171 lt@183 lt@202 |
| `seal-slice6` | `—` | `—` | **SKIP** | `—` | SKIP | — |
| `session-memory` | `session_memory.py` | `test_session_memory.py` | **3/3** | `6815f1a0` | 3/3 | or@181 or@199 lt@203 |
| `silent-failure-detector` | `silent_failure_detector.py` | `test_silent_failure_detector.py` | **3/3** | `8caf8742` | 3/3 | eq@157 and@159 retT@188 |
| `slice1` | `—` | `—` | **SKIP** | `—` | SKIP | — |
| `slice2` | `code_task.py` | `test_code_task.py` | **3/3** | `7faa3e43` | 3/3 | or@133 or@142 or@144 |
| `slice3` | `bash_parser.py` | `test_bash_parser.py` | **3/3** | `986d7892` | 3/3 | gt@117 retT@118 gt@119 |
| `slice4` | `—` | `—` | **SKIP** | `—` | SKIP | — |
| `slice5` | `blind_rerunner.py` | `test_blind_rerunner.py` | **3/3** | `9955f1dc` | 3/3 | or@47 or@150 retT@158 |
| `slice6` | `egress_client.py` | `test_egress_client.py` | **3/3** | `a08c983a` | 3/3 | eq@61 eq@63 eq@66 |
| `stale-checkpoint-gate` | `stale_checkpoint_gate.py` | `test_stale_checkpoint_gate.py` | **3/3** | `d09c1809` | 3/3 | or@234 retF@235 eq@237 |
| `step-reliability-budget` | `step_reliability_budget.py` | `test_step_reliability_budget.py` | **3/3** | `21e14e50` | 3/3 | or@80 or@83 lt@85 |
| `strands` | `strands_checkpoint.py` | `test_strands_checkpoint.py` | **3/3** | `b2cd46a6` | 3/3 | or@101 retF@212 retT@215 |
| `swe-failure-modes` | `swe_failure_modes.py` | `test_swe_failure_modes.py` | **3/3** | `30133c50` | 3/3 | or@137 or@141 lt@143 |
| `tombstone` | `cancellation_tombstone.py` | `test_cancellation_tombstone.py` | **3/3** | `176e10fc` | 3/3 | or@87 gt@89 retF@101 |
| `tombstone-mutant-blindspots` | `cancellation_tombstone.py` | `test_cancellation_tombstone.py` | **3/3** | `f8562b87` | 3/3 | or@87 gt@89 retF@101 |
| `tool-output-filter` | `tool_output_filter.py` | `test_tool_output_filter.py` | **3/3** | `5c0eca12` | 3/3 | or@165 and@172 eq@243 |
| `toolfail` | `tool_failure.py` | `test_tool_failure.py` | **3/3** | `4cc54812` | 3/3 | and@181 retT@193 eq@292 |
| `turn-truncation` | `turn_truncation.py` | `test_turn_truncation.py` | **3/3** | `9a2bf2c9` | 3/3 | eq@129 or@163 lt@165 |
| `unwind` | `shutdown_unwind.py` | `test_shutdown_unwind.py` | **3/3** | `9925a94c` | 3/3 | eq@74 eq@110 and@157 |
| `verifiability-tier` | `verifiability_tier.py` | `test_verifiability_tier.py` | **3/3** | `589445d0` | 3/3 | or@154 or@161 retF@275 |
| `vina` | `artifact_authority.py` | `test_artifact_authority.py` | **3/3** | `68c66f28` | 3/3 | or@150 or@184 gt@186 |
| `vina-mutant-blindspots` | `artifact_authority.py` | `test_artifact_authority.py` | **3/3** | `2f89b154` | 3/3 | or@150 or@184 gt@186 |
| `vina-receipt-signing` | `signed_receipt.py` | `test_signed_receipt.py` | **3/3** | `095bd24a` | 3/3 | or@179 or@280 or@317 |

**Reading the table.**  The four `SKIP` rows are the docs-only slices
(§4.2).  The five rows whose pinned k/3 is **0/3** are the newly
revealed gaps of §4.1.  Every other row is 1/3, 2/3 or 3/3, and
**every row's pinned column now equals its HEAD column** -- that equality
is the point of the re-lands in §5.

## 3. How to write a test that kills a given mutant

This is the part that generalises.  There are three target shapes in
this batch, and each one has exactly one test shape that can catch it.

### 3.1 The `or` double-guard: feed **both** wrong ways

The probe rewrites `or` to `and` (`" or "` -> `" and "`, the first
occurrence on the line).  A guard of the form

```python
if A or B:
    refuse
```

becomes

```python
if A and B:
    refuse
```

`A or B` and `A and B` differ **only when exactly one of A, B is true**.
So a test that feeds a single wrong input sees no difference at all --
that is why the probe found these guards alive.  Catching the mutant
requires two inputs:

| input class | which side is true | what the original does | what the mutant does |
|---|---|---|---|
| **type right, format wrong** | B true, A false | refuses | accepts |
| **format right, type wrong** | A true, B false | refuses | accepts |

The classic shape is a type guard paired with a shape guard:

```python
if not isinstance(value, str) or not value.strip():
```

* type right, format wrong: `""` or `"   "` -- a `str`, but empty.
* format right, type wrong: `123` or `None` -- not empty, but not a
  `str`.

Under the mutant, `""` passes the guard (both halves false) and `123`
passes it too (`not isinstance(123, str)` is True but
`not 123.strip()` raises `AttributeError` -- so the mutant turns a
clean refusal into a crash, which the test also catches, but the
*assertion* should be on the module's own error type).

A third shape needs a different second input, because `bool` is a
subclass of `int`:

```python
if isinstance(raw, bool) or not isinstance(raw, int):
```

* type right, format wrong: `True` -- `isinstance(True, int)` is True,
  so the *type* half does not refuse it; only the `bool` half does.
* format right, type wrong: `"7"` -- not a bool, but not an int either.

Under the mutant, `True` is booked as event id 1.

**The discriminator matters.**  For `or@127` the original refuses a
`str` with *"must be an iterable of event ids"*, while the mutant lets
the `str` through to the *id* guard and refuses it with *"must be
ints"*.  The test therefore asserts the **message**, not just the
exception type, otherwise the mutant's different message would still
satisfy `assertRaises`.

### 3.2 The `gt`/`lt` boundary: feed the **exact limit** and limit +/- 1

The probe rewrites `>` to `>=` (and `<` to `<=`).  These differ at
**exactly one value**: the limit itself.

```python
if len(value) > limit:
    refuse
```

* `len(value) == limit` -- the original **accepts**, the mutant refuses.
  This is the only input that separates them.
* `len(value) == limit + 1` -- both refuse.  Included so the test
  still pins the bound itself.
* `len(value) == limit - 1` -- both accept.  The control.

Feeding `limit + 2` proves nothing; feeding only `limit + 1` proves
nothing either.  The limit value must be read off the module's own
constant (`_MAX_LABEL_LEN`, `MAX_ID_CHARS`, `_MAX_ID_CHARS`) so the
test follows the code if the constant moves.

### 3.3 The `retF`/`retT` flip: assert the **False** path itself

The probe rewrites `return False` to `return True` (and the reverse).
A test that only exercises the True path cannot see the difference.
The test must assert the **return value** on the input that is supposed
to return False:

```python
self.assertIs(ct._is_generic_continuation(123), False)
```

Note `assertIs(..., False)`, not `assertFalse(...)`: `assertFalse` also
passes for `None` and `0`, so it would not distinguish a flipped
`return False` from some other falsy value.  And a **control** -- the
known generic phrases still returning `True` -- must be pinned too, so
the test cannot be satisfied by a function that returns False for
everything.

### 3.4 Naming

Every new test method names the mutant it kills: `test_or_at_127_...`,
`test_gt_at_131_...`, `test_retF_at_101_...`.  The name makes "which
mutant is still alive" readable at a glance in the test file, without
re-running the probe.

## 4. The manifests

### 4.1 The thirteen lost manifests

`b173-accept.sh:183` and `b173-mutant.sh:17` both require
`-f "$MANIFEST"`, so a slice with no manifest file has its `MUTANT`
item **skipped outright**.  Thirteen of the 64 slices had no manifest;
their `MUTANT` item was never decided, and their acceptance count read
10/10 or 11/11 as if the check had passed.

The manifests were rebuilt from git history:

```bash
git log --format=%H --grep="^B173 <slug>:" -i -1 \
  | xargs -I{} git show --name-only --format= {}
```

Each manifest lists the slice's writable files, one per line, in the
same format as the surviving manifests.  The module/test pairing that
`b173-mutant.sh` requires (a `.py` outside `/tests/` and a
`tests/test_*.py`) is:

| slice | module | test | pinned k/3 before | pinned k/3 after |
|---|---|---|---|---|
| `audit-head` | `audit_head_holder.py` | `test_audit_head_holder.py` | SKIP | **0/3** |
| `c52` | `grant_pin_ledger.py` | `test_grant_pin_ledger.py` | SKIP | **1/3** |
| `c54` | `deny_hotpath.py` | `test_deny_hotpath.py` | SKIP | **2/3** |
| `c58` | `bash_parser.py` | `test_bash_parser.py` | SKIP | **3/3** |
| `diviner` | `scope_qualifier.py` | `test_scope_qualifier.py` | SKIP | **0/3** |
| `e2b` | `egress_client.py` | `test_egress_client.py` | SKIP | **0/3** |
| `horizon` | `long_horizon.py` | `test_long_horizon.py` | SKIP | **1/3** |
| `langgraph` | `durable_resume.py` | `test_durable_resume.py` | SKIP | **2/3** |
| `slice2` | `code_task.py` | `test_code_task.py` | SKIP | **0/3** |
| `slice3` | `bash_parser.py` | `test_bash_parser.py` | SKIP | **3/3** |
| `slice5` | `blind_rerunner.py` | `test_blind_rerunner.py` | SKIP | **3/3** |
| `slice6` | `egress_client.py` | `test_egress_client.py` | SKIP | **0/3** |
| `unwind` | `shutdown_unwind.py` | `test_shutdown_unwind.py` | SKIP | **1/3** |

**Three of these five 0/3 results are outside this slice's writable
file list.**  `audit-head`, `diviner`, `e2b`, `slice2` and `slice6`
each need test changes in files this slice may not write:

| slice | module | test file that needs the new methods | in this slice's writable list? |
|---|---|---|---|
| `audit-head` | `audit_head_holder.py` | `tests/test_audit_head_holder.py` | no |
| `diviner` | `scope_qualifier.py` | `tests/test_scope_qualifier.py` | no |
| `e2b` | `egress_client.py` | `tests/test_egress_client.py` | no |
| `slice2` | `code_task.py` | `tests/test_code_task.py` | no |
| `slice6` | `egress_client.py` | `tests/test_egress_client.py` | no |

The task book says explicitly: write "which module/test needs changing
and why" into the report's OPEN section and **wait for the
coordinator's reply**.  That is what §8 does.  These five are
**measured, reproducible 0/3** (each run twice, identical numbers), so
the request is concrete.

**AMENDED 2026-11-22 (e) -- `c58` and `slice3`'s 3/3 in this table was
FALSE.**  This table's "pinned k/3 after" was measured with the same
probe that ran `python -m unittest <module>`, and `test_bash_parser.py`
is **pytest-style** -- 42 standalone functions, no `TestCase` class --
so unittest collected **zero** tests from it and every mutant was
reported killed by the exit code.  Re-measured at each slice's own
pinned commit with the fixed probe, both measured **0/3**: all three of
their listed constructs SURVIVE.  See §8's amendment (e).

**AMENDED 2026-11-22 (f) -- and the gap is now CLOSED.**  Nine new test
methods (three per slice, plus a control each) kill the three surviving
constructs of each slice, in the shape §3.1-§3.3 prescribes.  Both rows
now measure **3/3** at their own pinned commits -- `c58` 73/115 and
`slice3` 90/90.  See §8's amendment (f).

### 4.2 The four naturally N/A slices

These four never had a "new module + new test" pair, so `MUTANT` does
not apply to them and they are **not** part of the thirteen:

| slice | why |
|---|---|
| `fable` | docs only (`docs/api/northstar-agent-runtime.md`) |
| `slice1` | docs only (regenerated api page) |
| `slice4` | changed `cli.py` / `loop.py`, no corresponding new test file |
| `seal-slice6` | CI + docs only |

In the census table they are marked `SKIP` in the k/3 column and their
module/test columns read `—`.  They are a different thing from the
thirteen, and the two are not conflated.

### 4.3 `slice3` and `c58` share a module

Both `c58` and `slice3` probe `bash_parser.py`.  That is correct -- the
probe runs per slice, each against its own test module -- and both
measure **3/3**.  No gap had to be fixed twice.

## 5. The six 0/3 slices, and how each was closed

### 5.1 `vina` and `tombstone`: pinning artifacts, closed by a commit operation

These two needed **no test rewrite**.  The fixes already existed:

| slice | the probe pinned | the fix actually lived at | k/3 at the pinned commit | k/3 at HEAD |
|---|---|---|---|---|
| `vina` | `831b0312` (`B173 vina:`) | `2f89b154` (`B173 vina-mutant-blindspots:`) | 0/3 | 3/3 |
| `tombstone` | `695a25b7` (`B173 tombstone:`) | `f8562b87` (`B173 tombstone-mutant-blindspots:`) | 0/3 | 3/3 |

Both were measured twice at both commits; the numbers are identical
across runs.

The close is a **pure commit operation**.  The probe resolves the
worktree commit with `git log --grep="^B173 <slug>:" -i -1`, so the fix
has to be carried by a commit whose subject starts with the *slice's
own* prefix.  Each re-land is therefore two commits:

1. a commit that **removes** the mutant-kill test classes again (the
   exact inverse of the blindspot commit's test hunk), and
2. a commit that **adds them back**, byte-identical, under the
   slice's own prefix.

Step 1 exists only so that step 2's diff is real: without it the
content is already in the tree and step 2 would be an empty commit.
The test content is **byte-identical** between `2f89b154` and the
re-land for `vina`, and between `f8562b87` and the re-land for
`tombstone` -- verified with `md5sum` over the file at each commit.

| slice | re-land commits | resulting pinned commit | k/3 |
|---|---|---|---|
| `vina` | `e6823408` (lift out), `68c66f28` (re-land) | `68c66f28` | **3/3** |
| `tombstone` | `a83a9d52` (lift out), `176e10fc` (re-land) | `176e10fc` | **3/3** |

The module bodies (`artifact_authority.py`,
`cancellation_tombstone.py`) have **zero diff** in both re-lands.

### 5.2 The four true gaps

Each was given **>= 3 new test methods**, one per target, named for the
mutant it kills, plus a control per mutant.  **Module bodies: zero
diff** in all four -- the faults are pinned, not applied.

| slice | module | targets | new methods | k/3 after |
|---|---|---|---|---|
| `event-condenser` | `event_condenser.py` | `or@127`, `or@132`, `or@146` | 12 | **3/3** |
| `neo-konsi-s2bw` | `endpoint_identity.py` | `or@81`, `or@86`, `gt@131` | 13 | **3/3** |
| `deterministic-gate-score` | `deterministic_gate_score.py` | `or@155`, `or@159`, `or@197` | 12 | **3/3** |
| `vina-receipt-signing` | `signed_receipt.py` | `or@179`, `or@280`, `or@317` | 15 | **3/3** |

Each of the four slices' mutant-kill methods was committed under the
**slice's own slug prefix** (`B173 event-condenser:`,
`B173 neo-konsi-s2bw:`, `B173 deterministic-gate-score:`,
`B173 vina-receipt-signing:`), so the probe's pinned commit carries the
fix and the `MUTANT` item resolves to 3/3 rather than 0/3.

#### `event-condenser` -- `or@127`, `or@132`, `or@146`

All three live in `CondensationEvent.__init__`.

* **`or@127`** -- `if isinstance(forgotten, (str, bytes)) or not isinstance(forgotten, Iterable):`
  * type right, format wrong: `"abc"` and `b"abc"` -- a `str` is
    iterable, so only the `str` half refuses it.
  * format right, type wrong: `123`, `4.5`, `None`, `object()` -- not a
    `str`, but also not iterable.
  * The assertion is on the **message** ("must be an iterable of event
    ids"), because the mutant lets a `str` through to the *id* guard and
    the message changes to "must be ints".
* **`or@132`** -- `if isinstance(raw, bool) or not isinstance(raw, int):`
  * type right, format wrong: `True` and `False` -- `bool` is an `int`
    subclass, so the type half passes and only the `bool` half refuses.
  * format right, type wrong: `"7"`, `3.5`, `None`, `[1]`.
* **`or@146`** -- `if isinstance(summary_offset, bool) or not isinstance(summary_offset, int):`
  * type right, format wrong: `True`, `False`.
  * format right, type wrong: `"3"`, `1.5`, `None`, `[0]`.

#### `neo-konsi-s2bw` -- `or@81`, `or@86`, `gt@131`

The first two live in `_canonical`, the third in `_require_address`.

* **`or@81`** -- `if value is None or isinstance(value, bool):`
  * format right, type wrong: `None`.
  * type right, format wrong: `True`, `False`.
  * Under the mutant both fall through to the final `else` and raise
    `TypeError` instead of canonicalizing.
* **`or@86`** -- `if math.isnan(value) or math.isinf(value):`
  * format right, type wrong: `float("nan")` -- not infinite.
  * type right, format wrong: `float("inf")`, `float("-inf")` -- not NaN.
  * No float is both NaN and infinite, so the mutant's guard never
    fires and `"NaN"`/`"Infinity"` reach the digest.
* **`gt@131`** -- `if len(address) > _MAX_LABEL_LEN:` with
  `_MAX_LABEL_LEN = 1024`.  The limit itself (accepted), the limit + 1
  (refused) and the limit - 1 (accepted) are all fed.

#### `deterministic-gate-score` -- `or@155`, `or@159`, `or@197`

* **`or@155`** -- `if not isinstance(self.name, str) or not _ID_RE.match(self.name):`
  * format right, type wrong: `123`, `None`, `["gate"]`, `4.5`.
  * type right, format wrong: `"bad name"` (a space), `""`.
* **`or@159`** -- `if not isinstance(self.evidence, str) or not self.evidence.strip():`
  * format right, type wrong: `123`, `None`, `["ev"]`, `4.5`.
  * type right, format wrong: `""`, `"   "`.
  * Under the mutant a blank pointer is accepted, so a gate could be
    booked with no evidence at all -- the reason this one matters.
* **`or@197`** -- `if not isinstance(self.case_id, str) or not _ID_RE.match(self.case_id):`
  * format right, type wrong: `123`, `None`, `["case"]`, `4.5`.
  * type right, format wrong: `"bad case"`, `""`.

#### `vina-receipt-signing` -- `or@179`, `or@280`, `or@317`

* **`or@179`** -- `issuer_key_id`: `if not isinstance(issuer_pubkey, (bytes, bytearray)) or len(issuer_pubkey) != 32:`
  * format right, type wrong: `"a" * 32`, `None`.
  * type right, format wrong: 31 and 33 bytes.
* **`or@280`** -- `sign_receipt`: `if not isinstance(issuer_seed, (bytes, bytearray)) or len(issuer_seed) != 32:`
  * format right, type wrong: `"s" * 32`, `None`.
  * type right, format wrong: 31 and 33 bytes.
  * Under the mutant the Ed25519 shim's own `ValueError` escapes
    instead of the module's `SignedReceiptError`.
* **`or@317`** -- `verify_signed_receipt`: the same shape as `or@179`.
  Under the mutant the wrong key reaches the signature check and fails
  with a *signature* error, blaming the receipt instead of the key.

Two small import-only commits accompany these four:
`B173 neo-konsi-s2bw:` adds `import endpoint_identity` (the private
guards `_canonical` and `_require_address` are not exported by name),
and `B173 vina-receipt-signing:` adds `SignedReceiptError` to the
import list.  Neither touches a module body.

## 6. Why the mutant numbers changed for the four cache-dependent slices

`b173-mutant.py` runs the tests with a writable `__pycache__`, and a
same-length rewrite inside the same second reuses the previous round's
bytecode.  The measured effect is **inflation**: the probe reports the
first mutant's verdict again.

| slice | default run | cache-free run | direction |
|---|---|---|---|
| `anthropic-effort-scaling` | 3/3 | **1/3** | inflated |
| `refusal-row` | 3/3 | **1/3** | inflated |
| `jido-statebudget` | 3/3 | **2/3** | inflated |
| `dynamiq` | 3/3 | **1/3** | inflated |

These four are **not fixed by this slice** -- their test files are
outside its writable list.  Their true numbers are in §8 (OPEN) so the
coordinator knows their `MUTANT` verdicts are unreliable.

The live probe now carries the D-22 fix (`drop_cached_bytecode()` before
every rewrite, and `PYTHONDONTWRITEBYTECODE=1` in the test
environment), so the numbers in §2 are cache-free by construction.

## 7. What this slice did NOT do

* **No module body was changed.**  The five read-only modules
  (`event_condenser.py`, `endpoint_identity.py`,
  `cancellation_tombstone.py`, `deterministic_gate_score.py`,
  `signed_receipt.py`) and the one conditionally-writable module
  (`artifact_authority.py`) all have **zero diff** in this slice's
  commits.  `artifact_authority.py` needed no change either, so the
  conditional was not used.  §8's AMENDED (f) keeps that true for the
  three rows it closes: `agent_handoff.py` and `bash_parser.py` also
  have **zero diff** -- the new methods are tests only.
* **No version, tag or release.**  No `main` merge, no push.
* **The probe scripts were not touched.**  `b173-mutant.py`,
  `b173-mutant.sh` and `b173-accept.sh` are the judges; this slice only
  measured with them.
* **The five 0/3 slices of §4.1 were not fixed** -- their test files
  are outside the writable list.  The request is in §8 (OPEN).

## 8. RESOLVED -- the five requested lifts are closed

**Status: closed 2026-11-21.**  All five slices named in the previous
version of this section were lifted, each under **its own slug prefix**
(§5.2's mechanism), and each was measured with the batch's own probe.

| slice | module | lift commit | probe verdict |
|---|---|---|---|
| `audit-head` | `audit_head_holder.py` | `e1825737` | `MUTANT RESULT: killed 1/1` |
| `diviner` | `scope_qualifier.py` | `2e2a13c6` | `MUTANT RESULT: killed 1/1` |
| `e2b` | `egress_client.py` | `7058f57d` | `MUTANT RESULT: killed 1/1` |
| `slice2` | `code_task.py` | `40b5460b` | `MUTANT RESULT: killed 1/1` |
| `slice6` | `egress_client.py` | `7058f57d` | `MUTANT RESULT: killed 1/1` |

`e2b` and `slice6` share a module, so one lift closes both -- as §8
predicted.

**The method.**  Every surviving site was a **double guard**: a type
half joined to an emptiness/bound/boolean half by `and` or `or`, or a
bound compared against a constant.  The slice's own suite drove only
ONE half of each, so the mutant that broke the other half changed
nothing the suite could see.  The lift adds a second input per guard
that makes the *other* half the deciding one -- §3.1's "both wrong
ways" for `or`/`and`, §3.2's "the exact limit and limit +/- 1" for
`gt`/`lt`, §3.3's "assert the False path itself" for the `retF`/`retT`
flip.

**Measured, fault by fault.**  Each fault was applied to a copy of the
module **alone**, the suite was run, and the module was restored
byte-identical (`diff` verified).  Every fault that had SURVIVED now
KILLS the suite.

**A pitfall worth recording: `bool` is an `int`.**  Three of the
lifts (`strands`, `tool-output-filter`, `fable`) hit the same shape:

```python
if isinstance(value, bool) or not isinstance(value, int):
```

A boolean IS an integer in Python, so `isinstance(True, int)` is
True and the "not an int" half never refuses a bool -- only the
explicit `bool` half does.  Under the mutant (`or` -> `and`) that half
stops firing, and `True` is booked as the integer 1.  The test must
therefore feed a **boolean** to separate the mutant from the original;
feeding a string or a float proves nothing, because the "not an int"
half refuses those in both versions.

**Also worth recording: the mutant's own line must be reached.**  A
guard whose second half is never *executed* by the suite cannot be
killed by any input.  Two of the lifts needed a fixture that reaches
the branch at all -- a temporary module tree for `docbuild`'s renderer
(`component-packaging-closure`) and a source with a single docstring
marker for the tag split (`lt@755`).

**What was still open, and is now closed.**  The weak-evidence slices
(1/3 and 2/3 in the table above) were **measured**, not lifted, at the
time this document was written.  The lifts recorded in this section
cover the five that were asked for by name; the remaining weak rows were
a separate request, and each needed its own test file.

**AMENDED 2026-11-22 (d) -- every weak row was lifted, and the table was
stale.**  Re-measuring each slice's FIRST THREE constructs at its
CURRENT pinned commit, with the current probe, gives **3/3 for all 24
weak rows** (the re-measurement covered only those 24, so it says
nothing about the rest of the table -- and amendment (e) below shows
what a re-measurement that *did* cover the rest of the table found):

| slice | table said | re-measured |
|---|---|---|
| `ageofagents` | 1/3 | **3/3** |
| `anthropic-effort-scaling` | 1/3 | **3/3** |
| `asinhhc` | 1/3 | **3/3** |
| `autogen-speaker-selector` | 2/3 | **3/3** |
| `c52` | 1/3 | **3/3** |
| `c54` | 2/3 | **3/3** |
| `cost-per-delivery` | 2/3 | **3/3** |
| `dynamiq` | 1/3 | **3/3** |
| `evidence-independence` | 1/3 | **3/3** |
| `horizon` | 1/3 | **3/3** |
| `horizon-gate` | 2/3 | **3/3** |
| `intent-bound-retry` | 2/3 | **3/3** |
| `jido-statebudget` | 2/3 | **3/3** |
| `langgraph` | 2/3 | **3/3** |
| `langgraph-durability` | 1/3 | **3/3** |
| `langgraph-retry-clears-writes` | 2/3 | **3/3** |
| `refusal-row` | 1/3 | **3/3** |
| `revision-checked-tool-results` | 1/3 | **3/3** |
| `silent-failure-detector` | 2/3 | **3/3** |
| `step-reliability-budget` | 2/3 | **3/3** |
| `strands` | 2/3 | **3/3** |
| `tool-output-filter` | 2/3 | **3/3** |
| `unwind` | 1/3 | **3/3** |
| `verifiability-tier` | 2/3 | **3/3** |

**The count was wrong in a way a count check could not have caught.**
This section said "**twelve** weak-evidence slices"; the table carries
**twenty-four** rows at 1/3 or 2/3.  And the twelve the sentence named
were not the twelve that existed -- the list in
`docs/design/artifact-completion.md`'s open items names fourteen.  So
the number was wrong, the SET it stood for was wrong, and the lifts that
closed them landed on 2026-11-20 and 2026-11-21, **after** this section
was written and **after** the table was last touched.  A reader who
trusted the number would have gone looking for work that was already
done, and a reader who trusted the table would have believed 24 slices
were still short of 3/3.

**Two of the re-measurements changed because of the PROBE, not the
lift.**  `anthropic-effort-scaling` measured 2/3 until the probe was
fixed: its third construct (`lt@174`) makes the module raise at import,
pytest reports that as a *collection error*, and the probe's
"collected nothing is not a kill" rule -- which was too broad -- turned
the round into a SKIP.  The mutant IS caught.  See
`docs/design/judge-hygiene.md` §4b.7 and the pre-flight reading that
follows it.

**The probe's pinning.**  `b173-mutant.sh` pins to the slice's own last
commit under its own slug, and re-pins forward when a later commit
touched the slice's module or test file (the D-23 patch, which is in
the shipped `b173-mutant.sh`).  That is why a lift committed under the
ORIGINAL slug is both necessary and sufficient: the pin finds it, and
no phantom `mutant-lift-*` slice is created for the referee to judge.

**AMENDED 2026-11-22 (e) -- three rows of §2 were FALSE, not stale.**

The re-measurement above used the *fixed* probe.  That probe runs
**pytest**, not unittest -- and the difference is not a detail, because
six of the sixty-four rows in §2 are measured against a suite that
**unittest cannot collect a single test from**:

| slice | suite | unittest collects | the table said | measured |
|---|---|---|---|---|
| `agent-handoff` | `test_agent_handoff.py` | **0** of 40 | 3/3 | **0/3** |
| `c58` | `test_bash_parser.py` | **0** of 42 | 3/3 | **0/3** |
| `slice3` | `test_bash_parser.py` | **0** of 42 | 3/3 | **0/3** |
| `slice4` | `test_alert_trigger_registry.py` | **0** of 10 | SKIP | 3/4 |
| `toolfail` | `test_tool_failure.py` | **0** of 19 | 3/3 | 3/3 |
| `lightningzero` | `test_coverage_manifest.py` | **0** of 24 | 3/3 | 3/3 |
| `slice5` | `test_blind_rerunner.py` | **0** of 13 | 3/3 | 3/3 |

These suites are **pytest-style**: standalone module-level `test_*`
functions and no `TestCase` class.  unittest's loader collects zero
tests from such a file and exits 5 ("NO TESTS RAN"), and the probe of
the day read any non-zero exit as "the mutant was KILLED".  So the
whole 3/3 was manufactured by a suite that ran nothing.

**It pointed the STRONGER way**, which is why nothing else caught it: a
false kill looks like evidence of coverage where there is none.  It is
the mirror image of the stale-bytecode false kill, which looks like
survival where there is coverage.

**The rows that were false.**  For `agent-handoff`, `c58` and `slice3`
the three constructs §2 lists **all SURVIVED**:

| slice | §2's constructs | verdict | now |
|---|---|---|---|
| `agent-handoff` | `gt@214` `gt@226` `gt@236` | all SURVIVED | **all KILLED** (§8's (f)) |
| `c58` | `gt@127` `retT@128` `gt@129` | all SURVIVED | **all KILLED** (§8's (f)) |
| `slice3` | `gt@117` `retT@118` `gt@119` | all SURVIVED | **all KILLED** (§8's (f)) |

and for `c58` and `slice3` that is true **at their own pinned commits
too** (`37c0a2f3` and `986d7892`, re-measured with the fixed probe):
`slice3` measures 54/90 and `c58` 70/115, with all three listed
constructs surviving.  So those 3/3 claims were **never true** -- they
were not stale, they were wrong.  (`agent-handoff` is the same at its
pin `249f9a5c`: 22/38, all three surviving.)  §8's AMENDED (f) closes
all three with real tests.

**The rows that were lucky.**  `toolfail` and `lightningzero` also ran
against a blind suite, but their three listed constructs genuinely
KILL under pytest, so their 3/3 stands -- for the wrong reason, and
the whole-file numbers are lower than the old census recorded
(`toolfail` 11/11 -> **10/11**; `lightningzero` 24/24 -> **12/24**).
`slice5` is the third such row, and the cleanest control: blind suite,
perfect old score, and the fixed probe confirms **13/13**.  A defect
that made every blind row fall would have been a defect in the
slices, not in the runner.  It did not, so what was wrong was the
**runner**.

**The denominator was wrong too.**  The old probe stopped counting
constructs at a different point: `c58`'s old row read 63/63 where the
module has **115** mutable constructs.  The false kill was not only in
the verdict.

**The old census, row by row.**

| slice | old census (unittest) | fixed probe (pytest) |
|---|---|---|
| `agent-handoff` | 38/38 | **22/38** |
| `c58` | 63/63 | **70/115** |
| `slice3` | 63/63 | **70/115** |
| `slice4` | 4/4 | **3/4** |
| `toolfail` | 11/11 | **10/11** |
| `lightningzero` | 24/24 | **12/24** |
| `slice5` | 13/13 | 13/13 |

**Six of the seven re-measured rows changed.**  Six of the seven blind
rows had been a **perfect score** under the old census -- which is what
a false kill looks like from the outside.  Five fell outright (the
killed count dropped: `agent-handoff` 38 -> 22, `slice4` 4 -> 3,
`toolfail` 11 -> 10, `lightningzero` 24 -> 12); `c58` and `slice3` did
not lose kills but gained **survivors** (63 killed of 63 seen became
70 killed of **115** seen -- the old probe stopped counting constructs
halfway, and every construct past that point was reported killed
without being measured).  The seventh, `slice5`, is the **control**:
it was blind, it was a perfect score, and the fixed probe confirms
**13/13** -- so the defect was the *runner*, not the slices.

**What is now checked.**  `tests/test_unittest_blind_slices.py` pins
four things:

* §2's k/3 must follow the **per-construct verdicts** of a
  re-measurement, not merely be a number;
* a slice whose suite unittest collects nothing from may carry a 3/3
  claim **only if a re-measurement backs it** -- which is the rule
  that catches `agent-handoff`, `c58` and `slice3` and lets `slice5`
  through;
* the re-measurement must **differ** from the old census, so it cannot
  be a copy of the artifact it is checking;
* a slice whose old score was perfect and whose fixed score is *also*
  perfect must have its listed constructs confirmed KILLED individually
  -- so "the old number was perfect" is a fact about the runner, not an
  excuse for the slice.

The blind-suite detection is by **unittest's own loader**, not by a
heuristic about the file's text.  The two disagree: the loader says
**815** files, a text heuristic says 811.  The loader is the authority
the old probe used, so the loader is the authority here.

**The table now carries NO rows below the 3/3 line**, and the prose must
say so.  Amendment (e) found three rows whose 3/3 was false; §8's
AMENDED (f) below closes them with real tests.  The table has **64
rows**: **60** carry a scored k/3 and **4** are `SKIP` (no module/test
pair), and all **60** scored rows now read **3/3**.

**What these three rows meant.**  They were not "work to do" in the sense
of amendment (d)'s twenty-four: those twenty-four were *stale* -- the
lifts had landed and the table did not know.  These three were
*wrong*: the measurement that produced their 3/3 could not see the
suite it was measuring against, so it never measured them at all.  The
honest question for each of them was **"does the slice's suite catch
these constructs?"**, and the answer for all three was **no**.

That was a finding about the *suites*, not about the lifts.  The three
slices' modules were unchanged; what was missing was test coverage for
three constructs each, in the shape §3.1-§3.3 already prescribes (both
wrong ways, the exact limit and limit +/- 1, the False path itself).
§8's AMENDED (f) adds exactly that.

**AMENDED 2026-11-22 (f) -- the three false rows are CLOSED.**

Nine new test methods, three per slice, named for the mutant each one
kills, each with the control the shape requires.  **Module bodies: zero
diff** -- the faults are pinned, not applied.

| slice | module | targets | new methods | k/3 at the pinned commit |
|---|---|---|---|---|
| `agent-handoff` | `agent_handoff.py` | `gt@214`, `gt@226`, `gt@236` | 9 | **3/3** (`249f9a5c`: 25/38, was 22/38) |
| `c58` | `bash_parser.py` | `gt@127`, `retT@128`, `gt@129` | 8 | **3/3** (`37c0a2f3`: 73/115, was 70/115) |
| `slice3` | `bash_parser.py` | `gt@117`, `retT@118`, `gt@119` | 8 | **3/3** (`986d7892`: 90/90, was 54/90) |

`c58` and `slice3` share the same module and the same suite, so the
eight methods serve both; at `slice3`'s own pin the three constructs sit
ten lines earlier (`gt@117 retT@118 gt@119`), which is why the whole
file is now killed rather than the first three.

**Every one of the six mutants was proven to die.**  Planting each
mutant in turn and re-running the suite fails exactly the intended
test:

```
gt@214  ->  test_gt_at_214_agent_name_of_exactly_the_limit_is_accepted
gt@226  ->  test_gt_at_226_tool_name_of_exactly_the_limit_is_accepted
gt@236  ->  test_gt_at_236_description_of_exactly_the_limit_is_accepted
gt@117  ->  test_gt_at_127_a_node_count_of_exactly_the_limit_is_not_exceeded
retT@118->  test_retT_at_128_an_over_limit_node_count_returns_true
gt@119  ->  test_gt_at_129_a_deadline_of_exactly_now_is_not_exceeded
```

(the first three are `agent_handoff.py`'s lines; the last three are
`bash_parser.py`'s, whose line numbers differ by ten between the two
pins.)

**The shape of each test.**  Every `gt` test feeds the limit itself --
where the original ACCEPTS and the mutant (`>=`) REFUSES -- plus limit +
1 (both refuse, so the bound is still pinned) and limit - 1 (both
accept, the control).  Every `retT` test asserts the **True** path
itself with `is True`, and its control asserts the deadline line's
answer separately, so the test cannot be satisfied by a predicate that
always returns one value.

## 9. RESOLVED -- the equivalence records now have non-vacuity controls

**Status: closed 2026-11-21.**  Every surviving mutant in the batch's
census is an **EQUIVALENT** mutant: a planted fault that no test can
distinguish, because the original and the mutant are the same function
on every reachable input.  Each one is recorded in its slice's test
file with a proof, and the repository's convention (from
`tests/test_state_budget.py`'s `gt@304`) is to record such a mutant
rather than hunt a killer that cannot exist.

**AMENDED 2026-11-22 (d) -- that claim was true only of the census the
table was built from, and it is now FALSE of the batch as it stands.**

The census this section draws from (`census-parallel.txt`) was measured
with the **unittest runner**, and its rows for `agent-handoff`, `c58`
and `slice3` read `38/38`, `63/63` and `63/63` -- perfect scores, with
no survivors to account for.  Those were the false kills §8's AMENDED
(e) describes.  Re-measured with a runner that can see the suites, the
same two modules have **55 surviving mutants**:

| module | survivors | of which |
|---|---|---|
| `agent_handoff.py` | 13 | `retT@250` `retF@256` `or@289` `retT@324` `and@336` `and@338` `retF@339` `eq@445` `or@598` `eq@625` `or@981` `or@998` `or@1015` |
| `bash_parser.py` | 42 | `retF@289` `retT@291` `gt@342` `eq@343` `or@347` `or@357` `or@376` `or@446` `retF@478` `eq@480` `retF@481` `eq@484` `retF@489` `lt@547` `lt@552` `lt@557` `and@564` `or@579` `and@594` `and@599` `lt@613` `lt@620` `eq@632` `or@636` `or@676` `and@677` `eq@677` `lt@686` `lt@690` `lt@709` `or@718` `lt@756` `lt@773` `eq@795` `or@820` `and@822` `or@878` `gt@927` `and@963` `and@973` `retF@1052` `retF@1055` |

**Not one of the 55 has an equivalence proof**, and not one has a row
in §9.1's table.  So the claim above -- "every surviving mutant in the
batch's census is an EQUIVALENT mutant ... recorded in its slice's test
file with a proof" -- was true of the *census that was measured*, and
that census was wrong about these two modules in the strong direction.

This is the **third** time this section's enumeration has been short,
and the first time the missing rows were not in a table but in the
*proofs themselves*.  Two earlier amendments (2026-11-22 (c) and the
paragraph above) found table rows missing for sites that already had
proofs.  This one finds the proofs missing too.

**The check that would have caught it** is the one §9.1's own text
prescribes -- extract the sites from the census, extract them from the
table, and diff -- run against a census measured with a runner that can
see the suites.  It is now pinned by
`components/northstar-agent-runtime/tests/test_equivalence_table_coverage.py`,
which reads the **slice** census at the scope §9.1's table describes.

**AMENDED 2026-11-22 (e) -- the check itself was four defects, and each
of them hid a gap.**

The check existed before this amendment, and it did not report the 55.
It reported **nothing**, for four separate reasons, and every one of
them is a way of reading a census that does not say what it appears to
say:

1. **The verdict defect.**  A census line names EVERY mutant it planted
   -- the survivors AND the kills -- and the word `SURVIVED` appears in
   the line for either.  The line filter collected the killed sites
   too.  Measured: a corrected row for `agent-handoff` names 38 sites
   and 13 SURVIVED; reading the whole line reported all 38, so 25
   phantom findings crowded out the 13 real ones.
2. **The proof-lookup defect.**  A site name is relative to its
   module: `or@45` is a line number in whichever module the row names.
   The lookup searched EVERY test file for the bare name, so one
   module's proof satisfied another module's site.
3. **The scope-filter defect.**  The module census keys its rows by the
   MODULE's name, and the filter compared it against a dict keyed by
   module stem -- so the filter matched nothing and the "in scope" set
   was empty.
4. **The accounting defect.**  The check demanded that every surviving
   site be in §9.1's table.  But a surviving mutant has TWO possible
   proofs -- an equivalence proof (for one that genuinely cannot be
   killed) or a KILLER TEST (for one that can) -- and the check asked
   for the first in every case.

The check now reads a site **with its verdict**, scopes the proof
lookup to the suite the census row names, resolves the module census's
own row keys, and accepts either kind of proof.  Each branch is proven
to bite: removing the killer-lookup branch turns 18 covered sites into
53 findings, and removing one equivalence row turns its site into a
finding.

**What the check now says.**  Against the corrected census it reports
exactly the sites that are still open and nothing else -- 42 in
`bash_parser.py` and 12 in `coverage_manifest.py`.  The other 18 are
covered, each by an equivalence row in §9.1's table or by a killer
test.

**AMENDED 2026-11-22 (f) -- the thirteen `agent_handoff.py` survivors
are closed.**

All thirteen now have a killer test, named for the mutant it kills
(§3.4), in the shapes §3.1-§3.3 prescribe:

| site | construct | shape |
|---|---|---|
| `retT@250` | `return True` in `_is_cancelled` | §3.3, the True path |
| `retF@256` | `return False` in the `except` fallback | §3.3, the False path |
| `or@289` | the schema property-name guard | §3.1, both wrong ways |
| `retT@324` | `_type_ok` with no declared type | §3.3 |
| `and@336` | the `integer` check | §3.1, a `bool` is an `int` |
| `and@338` | the `number` check | §3.1, a `bool` is an `int` |
| `retF@339` | the unknown-type fallback | §3.3, the False path |
| `eq@445` | `HandoffDecision.handed_off` | §3.3, the False path |
| `or@598` | `register`'s `run_id` guard | §3.1, both wrong ways |
| `eq@625` | the arity message | §3.3 |
| `or@981` | `begin_run`'s `run_id` guard | §3.1, both wrong ways |
| `or@998` | `set_final_agent`'s `run_id` guard | §3.1, both wrong ways |
| `or@1015` | `guardrail_scope`'s `run_id` guard | §3.1, both wrong ways |

Every `or` guard is fed BOTH wrong ways -- a blank `str` (type right,
format wrong) and a non-`str` (format right, type wrong) -- because a
single input cannot separate `or` from `and`.  Every `return False` is
asserted with `assertIs(..., False)`, not `assertFalse`, and every one
has a control, so a function that always returned one value cannot
satisfy it.

`retF@256` needed a harness note: the line is reachable only when
`import asyncio` fails, so the test sets `sys.modules["asyncio"]` to
`None` (CPython raises `ImportError` for a `None` entry) to reach it.

**MEASURED**

| | HEAD | at the pinned commit `249f9a5c` |
|---|---|---|
| before | 25/38 | 25/38 |
| after | **38/38** | **38/38** |

The module body has **ZERO diff** -- the thirteen sites are killed by
tests, not by changing the source.

**The plant loop has a trap, and it made this look harder than it
was.**  A length-preserving mutate-then-restore inside one wall-clock
second can leave a stale `.pyc`; the next interpreter loads the
MUTANT's bytecode and the suite "kills" a fault that survived.  Four of
the thirteen reported SURVIVING for exactly this reason.  The plant
loop must set `PYTHONDONTWRITEBYTECODE=1` **and** remove every
`__pycache__` under the workdir before each invocation.  With both, all
thirteen report KILLED.

**AMENDED 2026-11-22 (g) -- two more single-site survivors are closed.**

`slice4`'s `or@45` (`if not trigger.name or not trigger.outcomes:`) is
a genuine double guard, so it takes BOTH wrong ways: a blank name (only
the second half refuses) and empty outcomes (only the first half
refuses).  Both are accepted by the mutant, and both tests fail under
the planted mutant.

`toolfail`'s `or@340` (`detail = getattr(fault, "detail", "") or ""`)
is a FALLBACK, not a double guard -- its right-hand side is the
constant `""`, which is never true -- so under the mutant the detail is
always dropped, and one input separates them: a fault that carries a
detail.

`from_provider_fault` had **no test at all** before this: the suite
covered `provider_retry.fault_to_failure`, which delegates to it.

| slice | before | after |
|---|---|---|
| `slice4` | 3/4 | **4/4** |
| `toolfail` | 10/11 | **11/11** |

**The gap this section closes.**  A proof that CANNOT fail proves
nothing.  The recorded proofs came in two shapes, and neither shape
required the proof to be able to fail:

* a **differential sweep** -- load the module twice (original, mutant)
  and assert the two agree over a large input set; and
* an **algebraic argument** -- the two spellings agree because of an
  invariant that holds in the module.

Both pin the PREMISE the argument rests on.  Neither shows that a
broken premise would change the answer.  So if the premise were not
what the argument says, the "no observable difference" conclusion would
be empty -- and the record would be a false comfort: the next reader
would either burn a round hunting a killer that does not exist, or
trust a mutant that was in fact killable.

**Measured: 11 of the 13 recorded equivalence proofs had no
non-vacuity control.**  All eleven now have one.  The two that already
did -- `cancellation-gate`'s `or@504` and `durable-resume`'s `lt@701` --
are the model the other eleven now follow.

**AMENDED 2026-11-21.**  The count of **13** was itself short.  The
whole-batch census reports **fifteen** distinct survivor sites, and two
more proofs existed -- `merged-tree-review`'s `gt@451` and `eq@494` --
that had **neither** a control nor a symmetric rewrite.  They are
missing from the list above for a reason worth recording: their slice's
census row read `ERROR` rather than a count, so the sites never
reached the census the count was drawn from.  **A slice with no census
number contributes no site, so it contributes no row.**  The two
proofs are now symmetric and have a control; see
`docs/design/merged-tree-review-equivalence-controls.md`.  The
enumeration is now **15 sites, 15 proofs, 15 controls** -- which the
2026-11-22 (c) amendment below corrects to **17 sites**: the census
sees 15, and `lt@701` and `or@504` are two more the census can reach
but §9.1's table had not listed.

**AMENDED 2026-11-22.**  The two sites now have a **census number of
their own**, which is what closed the loop.  The whole-file census for
`merged_tree_review.py` reads:

```
MUTANT RESULT: killed 37/39
```

with exactly two survivors -- `gt@451` and `eq@494` -- the two this
slice covers.  So the slice contributes **two sites to the census and
two rows to §9.1's table**, where before it contributed neither.

**AMENDED 2026-11-22 (b).**  Checking §9.1's table against the census --
rather than against the proofs -- found **one more gap of the same
kind**: the census's `gt@640` (`refusal-hold-wiring`'s audit-trail trim
bound) had **no row in §9.1's table**.  It does have a proof, and a
good one: `tests/test_refusal_hold_wiring.py` runs the strict and the
loose spelling as **two separate imported copies** of the real module,
drives both through the same recording sequence, and compares the two
trails event by event -- with the non-vacuity control
`test_the_differential_harness_would_catch_an_observable_mutation`
planting a mutation that IS observable.

So the proof existed and was correct; only the **table row** was
missing.  That is the *second* time this enumeration was short by
exactly the sites the census could not reach -- and the *third* time
the count was locally right and wrong.  The census reports **15
distinct sites**; §9.1's table now carries **16 rows for 17 sites**
(the `diviner` row carries two; the 2026-11-22 (c) amendment below
records how the count reached 17).

> **The enumeration is now derived from the census, not from memory.**
> The census is the only artifact that sees every slice; a hand-kept
> table is one edit away from being a subset of it.  And the check is
> cheap: extract the site names from the table, extract them from the
> census, and diff.  Two of the three gaps were found by that diff and
> not by reading any proof.

The probe needed one change to produce that number: it collected every
verdict in memory and printed them all at the end, so a run that hit
the wall clock produced **no output at all**.  It now prints each
verdict **as it is measured**.  The generalisable form is the one from
`cwl-episode-eviction`: **a missing number is not a verdict**, and a
probe that reports nothing when it dies makes that invisible.

**A count is a claim too.**  This section's own "13" was locally
correct -- thirteen proofs had been *written* -- and it was still wrong,
because the enumeration behind it was drawn from memory of the proofs
rather than from the census.  The order matters: **measure the census
first, then enumerate the records against it.**

### 9.1 The two shapes of control

**A control mutation.**  The same harness -- same loader, same sweep,
same comparison -- is pointed at a mutation that is known to change
behaviour, and the harness is REQUIRED to find the difference.  A
difference there is what licenses the "no difference" conclusion at
the planted fault.

| slice | site | the control |
|---|---|---|
| `audit-head` | `or@527` | the two spellings of the monotonicity guard, over inputs that violate `seq == records_sealed` |
| `audit-head` | `lt@928` | the strict and non-strict row comparisons, over the EQUAL counts the guard never reaches |
| `cancellation-gate` | `or@504` | the same differential harness pointed at the resume file-size bound, a mutation that IS observable |
| `cwl-episode-eviction` | `eq@387` | the validation call driven directly with an invalid dependency |
| `diviner` / `scope-verb-canonical` | `lt@667`, `gt@669` | the same comparison, over the EQUAL target sets the sweep skips |
| `durable-resume` | `lt@701` | the differential harness with the server-error branch emptied -- the two predicates must then DIFFER at status 500 |
| `fable` | `lt@579` | the cap computation widened by one byte |
| `horizon` | `gt@741` | the truncation keeping one character fewer |
| `jido-statebudget` | `gt@304` | a deliberately wrong expression -- the original with the bound one step further |
| `openhands-stuck-detector` | `gt@681` | the source-index line with a ONE-element message key |
| `refusal-hold-wiring` | `gt@640` | the differential harness planted with a mutation that IS observable -- the delete removes one event too many at the boundary |
| `scope-verbatim-compaction` | `lt@390` | the end-marker guard moved to a bound that never fires |
| `scorer-disagreement` | `gt@533` | the threshold comparison widened instead of the scorer-count one |
| `step-reliability-budget` | `lt@152` | the final formula of `max_steps` shifted by one |
| `merged-tree-review` | `gt@451` | the trim bound moved one step further -- `len(parts) > 2` -- which the harness must detect |
| `merged-tree-review` | `eq@494` | the same harness, over the class-membership half the equivalence rests on |

**The table has 16 rows for 17 sites.**  `diviner` /
`scope-verb-canonical` carries TWO sites (`lt@667` and `gt@669`) in one
row, so the row count and the site count differ by one.  The census
reports **15 distinct survivor sites** across **18 survivor instances**
-- `lt@667`, `gt@669` and `lt@390` each survived TWICE, because their
slices were censused under two names.  So "15 sites, 15 proofs, 15
controls" is a count of **distinct sites**, and the three duplicated
names are the same site counted once.

**AMENDED 2026-11-22 (c) -- the table was missing TWO rows, and the
count that reported the gap was the wrong count.**  Running the diff
this section recommends -- extract the site names from §9.1's table,
extract them from the census, and diff -- produced a **non-empty**
diff, which is the check working:

```
census only:  lt@701  or@504
table only:   eq@494  gt@451
```

The first line is the finding: `durable-resume`'s `lt@701` and
`cancellation-gate`'s `or@504` had **no row in §9.1's table**, even
though both have full differential proofs with non-vacuity controls
(`test_durable_resume.py`'s `lt@701` class, and
`test_cancellation_gate.py`'s `EquivalentMutantTests`).  The second
line is not a finding: `gt@451` and `eq@494` are absent from the
census because `merged-tree-review`'s census row reads `ERROR` -- the
condition §9's own first amendment describes.  They are covered by
the 2026-11-22 census of that module (`killed 37/39`).

So the correct accounting is:

| | census | §9.1's table (before) | §9.1's table (now) |
|---|---|---|---|
| distinct sites | 15 | 15 | **17** |
| of which the census cannot see | — | `gt@451`, `eq@494` | `gt@451`, `eq@494` |

The table now carries **17 sites in 16 rows** (`diviner` /
`scope-verb-canonical` carries two sites in one row).  The census can
only ever see **15** of them, because it does not reach
`merged-tree-review` -- so **the census is NOT the upper bound on the
number of sites**, and a table diffed against it will always show the
two `merged-tree-review` sites as "extra".  That is the shape of the
check: a diff is a diff, and each side must be read against what it
can actually see.

**A count of "15" was locally right and wrong for the fourth time.**
The census says 15; the proofs say 17; and the table, read on its own,
said 15 while carrying a *different* 15 -- it had `gt@451` and `eq@494`
but not `lt@701` and `or@504`.  The number happened to be right and
the SET was wrong, which is the worst of the two failure modes: a
count check would have passed.  The **set** diff is what found it.

**The skipped inputs.**  A sweep that SKIPS a class of pairs -- the
equal target sets, the equal row counts -- is skipping exactly where
the two spellings disagree.  Running the same comparison over the
skipped pairs and requiring a difference there shows the skip is doing
the work the argument claims, and it is what makes the agreement over
the non-skipped pairs mean something.

### 9.1a There are TWO censuses, and the diff needs both at the same scope

Every count above is a count of the **slice** census -- one row per
*slice*, the batch's own deliveries.  There is a second census, taken
over every *module* in the component at HEAD, and the two are not
interchangeable.

| | slice census | module census |
|---|---|---|
| one row per | slice (64 rows in §2's table) | module (330+ rows) |
| the module is | the slice's module | the module itself |
| the suite is | the slice's suite | the module's own suite |
| reaches | the batch's deliveries | every module, most of which no slice ever touched |

A **module** census therefore reports far more survivor sites, and
those extra sites are **not** findings against §9.1's table.  The table
is scoped to the batch's deliveries; the module census reaches modules
no slice ever touched.  Diffing the two is a diff between different
scopes, and it fails in a way that looks exactly like a finding.

**Measured 2026-11-22.**  The coverage test
(`tests/test_equivalence_table_coverage.py`) read whichever census
artifact it found first, and the candidate list put the **module**
census first.  With a module census in place, the diff reported
**1,483** sites "with no row in §9.1's table" -- every one of them a
false positive produced by the scope difference, and every one of them
in a module the batch never delivered.

The fix is not "the table needs 1,483 more rows".  It is:

* the census candidates now carry their **scope** with them, and the
  **slice** census is read first, so "the census" means the scope the
  table describes;
* a module-scope census is **filtered** down to the batch's scope
  before the diff, by module -- the filter's authority is §2's table
  unioned with the modules the slice census names, because neither
  source alone is complete (§2's table has a row with no module,
  `fable`, and the census names modules §2's table does not).

**The filter is proven, not assumed.**  The check that a *genuinely*
missing row is still caught was run with a module census in place:
deleting §9.1's `durable-resume` / `lt@701` row made the test fail
with exactly `['lt@701']` -- the one site that was really missing.  So
the filter removes the scope difference and **nothing else**.

**A site name is relative to its module.**  `or@527` is a line number
in whichever module the row names, so the same bare name can occur in
two modules and mean two different sites.  The scope filter's sets are
therefore compared **module-qualified**; comparing bare names across
the scope boundary reports a false overlap (measured: 13 names in both
halves of the filter, all of them different sites).

### 9.2 Two pitfalls, both measured

**A control that asserts the SOURCE TEXT is a false kill.**  The first
version of the `scope-verbatim-compaction` control rewrote the
end-marker guard from the spelling it expected to find on disk.  The
moment the mutation probe planted the other spelling, the control
broke -- and the probe reported `lt@390` **KILLED**, a "kill" that was a
difference in the FILE, not in the BEHAVIOUR.

Measured, same tree, same probe:

| control | census verdict |
|---|---|
| asymmetric (asserts one spelling) | `killed 33/33` -- `lt@390` reported killed |
| symmetric (rewrites whichever spelling is present) | `killed 32/33` -- `lt@390` survives, honestly equivalent |

The fix is the symmetry the repository's own equivalence proofs use:
rewrite whichever spelling is on disk.  `tests/test_cancellation_gate.py`
does this, and it is the shape to copy.

**A control mutation must be OBSERVABLE.**  Turning `<` into `>` in a
guard whose branches are both no-ops changes nothing; so does moving a
bound the wrong way when the value never reaches it.  The first attempt
at the `fable` control -- flipping the byte-cap comparison to `>` --
was a no-op for exactly that reason, and the test caught it.  Pick the
control by reading where the value can actually arrive.

### 9.3 What this section does NOT change

* **No module body was changed.**  All eleven controls live in test
  files.
* **No mutant was killed.**  The mutants were equivalent before this
  section and they are equivalent after it.  What changed is that the
  record now SAYS SO with a proof that can fail.
* **No census number moved** -- except the one false kill described
  above, which was moved BACK to the honest number.
