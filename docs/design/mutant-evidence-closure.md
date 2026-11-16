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
| `ageofagents` | `ledger_concurrency.py` | `test_ledger_concurrency.py` | **1/3** | `b970b457` | 1/3 | or@302 eq@390 or@475 |
| `anthropic-effort-scaling` | `effort_scaling.py` | `test_effort_scaling.py` | **1/3** | `9b00638e` | 1/3 | lt@174 or@174 lt@180 |
| `asinhhc` | `key_custody.py` | `test_key_custody.py` | **1/3** | `ddbd2c5a` | 1/3 | lt@193 eq@286 or@336 |
| `audit-head` | `audit_head_holder.py` | `test_audit_head_holder.py` | **0/3** | `265ff349` | 0/3 | or@176 or@178 or@184 |
| `autogen-speaker-selector` | `speaker_selector.py` | `test_speaker_selector.py` | **2/3** | `8a3bfbc5` | 2/3 | gt@125 gt@132 or@141 |
| `c52` | `grant_pin_ledger.py` | `test_grant_pin_ledger.py` | **1/3** | `0dc81ceb` | 1/3 | eq@139 eq@142 gt@143 |
| `c54` | `deny_hotpath.py` | `test_deny_hotpath.py` | **2/3** | `a1c7e688` | 2/3 | retF@117 or@247 gt@249 |
| `c58` | `bash_parser.py` | `test_bash_parser.py` | **3/3** | `37c0a2f3` | 3/3 | gt@127 retT@128 gt@129 |
| `cost-per-delivery` | `cost_per_delivery.py` | `test_cost_per_delivery.py` | **2/3** | `288799f2` | 2/3 | or@208 or@215 lt@220 |
| `cwl-episode-eviction` | `episode_eviction.py` | `test_episode_eviction.py` | **3/3** | `5e4e66d4` | 3/3 | eq@182 eq@186 eq@219 |
| `deterministic-gate-score` | `deterministic_gate_score.py` | `test_deterministic_gate_score.py` | **3/3** | `c08a86ad` | 3/3 | or@155 or@159 or@197 |
| `diviner` | `scope_qualifier.py` | `test_scope_qualifier.py` | **0/3** | `54e5c8dd` | 0/3 | or@190 or@192 gt@194 |
| `dynamiq` | `retry_config.py` | `test_retry_config.py` | **1/3** | `920dc41d` | 1/3 | or@165 lt@167 or@171 |
| `e2b` | `egress_client.py` | `test_egress_client.py` | **0/3** | `c9b1fc4f` | 0/3 | eq@63 eq@65 eq@68 |
| `effect-directive` | `effect_directive.py` | `test_effect_directive.py` | **3/3** | `a117a03d` | 3/3 | or@173 or@177 or@224 |
| `event-condenser` | `event_condenser.py` | `test_event_condenser.py` | **3/3** | `ffd3eb08` | 3/3 | or@127 or@132 or@146 |
| `evidence-independence` | `evidence_independence.py` | `test_evidence_independence.py` | **1/3** | `70288f1b` | 1/3 | or@226 and@284 and@288 |
| `fable` | `—` | `—` | **SKIP** | `—` | SKIP | — |
| `false-green-detector` | `false_green_detector.py` | `test_false_green_detector.py` | **3/3** | `a4d2142d` | 3/3 | or@198 lt@201 and@201 |
| `fieldnotes` | `planted_fault.py` | `test_planted_fault.py` | **3/3** | `33eb7cd9` | 3/3 | or@283 and@293 eq@341 |
| `horizon` | `long_horizon.py` | `test_long_horizon.py` | **1/3** | `6d21efd7` | 1/3 | or@114 or@192 lt@194 |
| `horizon-gate` | `horizon_gate.py` | `test_horizon_gate.py` | **2/3** | `4baa7999` | 2/3 | or@245 lt@250 or@257 |
| `intent-bound-retry` | `intent_bound_retry.py` | `test_intent_bound_retry.py` | **2/3** | `0a550532` | 2/3 | retT@157 retF@173 and@204 |
| `jido-statebudget` | `state_budget.py` | `test_state_budget.py` | **2/3** | `28f5068c` | 2/3 | or@177 or@183 lt@185 |
| `langgraph` | `durable_resume.py` | `test_durable_resume.py` | **2/3** | `a3ba033a` | 2/3 | or@156 or@164 lt@203 |
| `langgraph-durability` | `checkpoint_durability.py` | `test_checkpoint_durability.py` | **1/3** | `04391897` | 1/3 | eq@141 retF@382 retT@383 |
| `langgraph-retry-clears-writes` | `retry_clears_writes.py` | `test_retry_clears_writes.py` | **2/3** | `a3aa7007` | 2/3 | retF@152 retT@155 eq@170 |
| `leased-task-claim` | `leased_task_claim.py` | `test_leased_task_claim.py` | **3/3** | `4e304fab` | 3/3 | gt@206 or@336 or@342 |
| `lightningzero` | `coverage_manifest.py` | `test_coverage_manifest.py` | **3/3** | `896bc923` | 3/3 | or@139 or@145 and@202 |
| `msaf-lineage` | `approval_rules.py` | `test_approval_rules.py` | **3/3** | `a8306073` | 3/3 | or@70 and@76 retF@82 |
| `neo-konsi-s2bw` | `endpoint_identity.py` | `test_endpoint_identity.py` | **3/3** | `2a8ed2a1` | 3/3 | or@81 or@86 gt@131 |
| `openhands-stuck-detector` | `stuck_detector.py` | `test_stuck_detector.py` | **3/3** | `190b000c` | 3/3 | or@251 eq@252 and@252 |
| `outsideloop` | `annotation_pin.py` | `test_annotation_pin.py` | **3/3** | `b7a01e59` | 3/3 | and@145 retF@159 and@160 |
| `refusal-row` | `refusal_row.py` | `test_refusal_row.py` | **1/3** | `190d9198` | 1/3 | or@148 or@163 or@177 |
| `resume-validation` | `resume_validation.py` | `test_resume_validation.py` | **3/3** | `b8b6074a` | 3/3 | or@198 eq@209 eq@213 |
| `reversible-compaction` | `reversible_compaction.py` | `test_reversible_compaction.py` | **3/3** | `8f3e1496` | 3/3 | or@116 retF@117 retF@120 |
| `revision-checked-tool-results` | `revision_checked_tool_results.py` | `test_revision_checked_tool_results.py` | **1/3** | `8b9bf616` | 1/3 | or@114 lt@118 gt@120 |
| `scope-verbatim-compaction` | `scope_verbatim_compaction.py` | `test_scope_verbatim_compaction.py` | **3/3** | `1649c89c` | 3/3 | and@202 lt@297 or@306 |
| `scorer-disagreement` | `scorer_disagreement.py` | `test_scorer_disagreement.py` | **3/3** | `4e5a9657` | 3/3 | eq@171 lt@183 lt@202 |
| `seal-slice6` | `—` | `—` | **SKIP** | `—` | SKIP | — |
| `session-memory` | `session_memory.py` | `test_session_memory.py` | **3/3** | `6815f1a0` | 3/3 | or@181 or@199 lt@203 |
| `silent-failure-detector` | `silent_failure_detector.py` | `test_silent_failure_detector.py` | **2/3** | `8caf8742` | 2/3 | eq@157 and@159 retT@188 |
| `slice1` | `—` | `—` | **SKIP** | `—` | SKIP | — |
| `slice2` | `code_task.py` | `test_code_task.py` | **0/3** | `7faa3e43` | 0/3 | or@133 or@142 or@144 |
| `slice3` | `bash_parser.py` | `test_bash_parser.py` | **3/3** | `986d7892` | 3/3 | gt@117 retT@118 gt@119 |
| `slice4` | `—` | `—` | **SKIP** | `—` | SKIP | — |
| `slice5` | `blind_rerunner.py` | `test_blind_rerunner.py` | **3/3** | `9955f1dc` | 3/3 | or@47 or@150 retT@158 |
| `slice6` | `egress_client.py` | `test_egress_client.py` | **0/3** | `a08c983a` | 0/3 | eq@61 eq@63 eq@66 |
| `stale-checkpoint-gate` | `stale_checkpoint_gate.py` | `test_stale_checkpoint_gate.py` | **3/3** | `d09c1809` | 3/3 | or@234 retF@235 eq@237 |
| `step-reliability-budget` | `step_reliability_budget.py` | `test_step_reliability_budget.py` | **2/3** | `21e14e50` | 2/3 | or@80 or@83 lt@85 |
| `strands` | `strands_checkpoint.py` | `test_strands_checkpoint.py` | **2/3** | `b2cd46a6` | 2/3 | or@101 retF@212 retT@215 |
| `swe-failure-modes` | `swe_failure_modes.py` | `test_swe_failure_modes.py` | **3/3** | `30133c50` | 3/3 | or@137 or@141 lt@143 |
| `tombstone` | `cancellation_tombstone.py` | `test_cancellation_tombstone.py` | **3/3** | `176e10fc` | 3/3 | or@87 gt@89 retF@101 |
| `tombstone-mutant-blindspots` | `cancellation_tombstone.py` | `test_cancellation_tombstone.py` | **3/3** | `f8562b87` | 3/3 | or@87 gt@89 retF@101 |
| `tool-output-filter` | `tool_output_filter.py` | `test_tool_output_filter.py` | **2/3** | `5c0eca12` | 2/3 | or@165 and@172 eq@243 |
| `toolfail` | `tool_failure.py` | `test_tool_failure.py` | **3/3** | `4cc54812` | 3/3 | and@181 retT@193 eq@292 |
| `turn-truncation` | `turn_truncation.py` | `test_turn_truncation.py` | **3/3** | `9a2bf2c9` | 3/3 | eq@129 or@163 lt@165 |
| `unwind` | `shutdown_unwind.py` | `test_shutdown_unwind.py` | **1/3** | `9925a94c` | 1/3 | eq@74 eq@110 and@157 |
| `verifiability-tier` | `verifiability_tier.py` | `test_verifiability_tier.py` | **2/3** | `589445d0` | 2/3 | or@154 or@161 retF@275 |
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
  conditional was not used.
* **No version, tag or release.**  No `main` merge, no push.
* **The probe scripts were not touched.**  `b173-mutant.py`,
  `b173-mutant.sh` and `b173-accept.sh` are the judges; this slice only
  measured with them.
* **The five 0/3 slices of §4.1 were not fixed** -- their test files
  are outside the writable list.  The request is in §8 (OPEN).

## 8. OPEN -- for the coordinator

**Request: extend the writable list to the five test files below, so the
five newly-revealed 0/3 slices can be lifted to 3/3.**

Each was measured twice at its pinned commit with identical numbers
(0/3 both times), so these are real gaps, not measurement noise.  For
each, the module/test pair and the three planted faults are:

| slice | test file to extend | module | planted faults (all SURVIVED) | why |
|---|---|---|---|---|
| `audit-head` | `components/northstar-agent-runtime/tests/test_audit_head_holder.py` | `audit_head_holder.py` | `or@176`, `or@178`, `or@184` | the three `or` double-guards in the head-holder's validation |
| `diviner` | `components/northstar-agent-runtime/tests/test_scope_qualifier.py` | `scope_qualifier.py` | `or@190`, `or@192`, `gt@194` | two `or` guards plus a length bound |
| `e2b` | `components/northstar-agent-runtime/tests/test_egress_client.py` | `egress_client.py` | `eq@63`, `eq@65`, `eq@68` | three `==` string comparisons inside `_strict_json_loads` -- the escaped / quote / closing-quote branches of the JSON scanner |
| `slice2` | `components/northstar-agent-runtime/tests/test_code_task.py` | `code_task.py` | `or@133`, `or@142`, `or@144` | three `or` double-guards |
| `slice6` | `components/northstar-agent-runtime/tests/test_egress_client.py` | `egress_client.py` | `eq@61`, `eq@63`, `eq@66` | the same module as `e2b`, but the probe's first three constructs are the three earlier `==` comparisons (`== "\\"`, `== '"'`, `== '"'`) in the same scanner |

Note that `e2b` and `slice6` probe the **same module**
(`egress_client.py`) with the same three constructs, so one fix closes
both.

The test shape for each is §3's, applied to the guard in question:
`or` -> feed both wrong ways, `gt` -> feed the exact limit and limit
+/- 1, `eq` -> feed the value that takes the branch *and* a value that
does not, since `==` -> `!=` swaps which of the two the branch is
taken on.  For `e2b`/`slice6` the `==` constructs are the character
comparisons in the JSON string scanner, so the input has to contain the
escaped, the quoted and the closing-quote cases that reach those
branches.

**Also for the coordinator:**

1. The twelve weak-evidence slices (1/3 and 2/3) were **measured**, not
   lifted.  Their true k/3 is in §2's table.  Lifting them would need
   their own test files, which are outside this slice's writable list.
2. `b173-mutant.sh` still pins the slice's own last commit.  The
   re-lands in §5.1 work around it; the judge-hygiene slice's D-23
   patch (pin the later commit that touched *this slice's* module or
   test file) would fix the class of problem.  That patch is outside
   this slice's scope -- the probe scripts are the judges' tools.
