# Merged-tree review: the B173 cross-slice conflict report

**What this is.** B173 landed 64 slices, each with a module, a test and a
design doc. Every slice was accepted against its own tree. **No slice was
ever accepted against the tree that carries all 64.** `b173-lessons.md`
records the gap:

> Merged-tree adversarial review: two slices each pass, merged they break
> (semantic conflict) is an acceptance blind spot.

This document is that review. It has two halves:

* the **tool** (`components/northstar-agent-runtime/merged_tree_review.py`)
  — four mechanically checkable rules, read-only, re-runnable;
* the **manual semantic review** below — the parts a tool cannot judge:
  which path a real call actually takes, whether two vocabularies can be
  combined, whether two key shapes can be matched.

Every finding states **why each slice's own tests didn't catch it**. That
is the point: a conflict that no slice's own test could have caught is
exactly what a per-slice acceptance process cannot see.

## 0. Method, and what the tool can and cannot decide

The tool parses the tree with `ast`. It never imports the modules it
inspects (importing a runtime module has side effects, and importing is
not a read of the tree under review) and never writes anything. Rules:

| Rule | Question | Where |
| --- | --- | --- |
| 1 | Does every `module.symbol` a design doc names still exist? | `scan_dangling_symbols`, `scan_missing_modules` |
| 2 | Does a public name exist in two modules with different signatures? | `find_same_name_symbols` |
| 3 | Do two modules of one semantic group mint the same verdict word? | `vocabulary_overlap` |
| 4 | Can two record types of one group be joined? | `record_shape_conflicts` |

**The tool does not decide whether two same-spelled things mean the same
thing.** Rule 3 reports *that* `scope_qualifier` and `refusal_hold` both
write `denied`; whether the two denials are the same denial is the human
reader's call, and section 2.4 makes that call.

**The tool's known blind spot.** Rule 2 sees 154 same-name groups across
the 1612 runtime modules, and most of them are the `ai_*` slice family
calling a shared `stdlib_only()` / `main()` helper. That is noise, not
signal: the count is large because the tree is large, not because the
tree is broken. The useful signal is the groups that involve a
**semantic-adjacency group module** — those are listed in section 2.

## 1. The mechanically checkable results

Run over the merged tree: 1612 runtime modules, 62 design docs.

```
rule1 dangling symbols: 6
rule2 same-name symbols: 154 (103 different-signature)
rule3 vocabulary overlaps: 2
rule4 record shape conflicts: 23
```

### 1.1 Rule 1 — dangling cross-slice symbol references

Six references in the design docs point at something the tree does not
have, or at a file that is not in this repository at all.

| Location | Reference | Verdict |
| --- | --- | --- |
| `docs/design/capability-ceiling-probe.md:124` | `ledger.verdicts` | **drift** — `ledger.py` has no `verdicts` attribute, no `verdicts` constant, and never records a verdict at all |
| `docs/design/deterministic-gate-score.md:75` | `main.py` | foreign citation |
| `docs/design/event-condenser.md:44` | `agent_controller.py` | foreign citation |
| `docs/design/lineage-checkpoints.md:267` | `_compaction.py` | foreign citation (MSAF) |
| `docs/design/lineage-checkpoints.md:272` | `_compaction.py` | foreign citation (MSAF) |
| `docs/design/retry-clears-writes.md:223` | `types.py` | foreign citation (LangGraph) |

**Finding D1 — `ledger.verdicts` does not exist.**
`docs/design/capability-ceiling-probe.md:124` says "The module records the
verdict in `ledger.verdicts`; it does not send anything to a human and it
does not split anything." `components/northstar-agent-runtime/ledger.py`
is a double-entry accounting ledger: it has `post()`, `trial_balance()`,
accounts, journal entries and a digest pin. It has no verdict concept
whatsoever. The sentence describes a module the slice read but did not
build.

*Why the slice's own tests didn't catch it.* The capability-ceiling slice
tested the **routing decision** (`HUMAN` / `DECOMPOSE` / `ALLOW`), not
the ledger's API surface. The claim "the verdict is recorded in
`ledger.verdicts`" is a sentence in the doc, and no test asserts that
`ledger` has a `verdicts` attribute. A doc claim about a *different*
module is invisible to a slice's own tests by construction: the slice
never imports `ledger`.

*Severity.* **should fix** — the sentence is false and it describes a
persistence mechanism that does not exist. If a verdict really is
recorded somewhere, the doc must name where.

*Suggested action.* Dispatch a fix slice that either (a) implements the
verdict-recording sidecar the doc describes, or (b) rewrites the sentence
to name the module that actually holds the routing decision.

**The other five are not drift** — they cite foreign projects (MSAF's
`_compaction.py`, LangGraph's `types.py`, an external
`agent_controller.py`, and an open-sourced reference task tree's
`main.py`). The tool separates them by the `foreign-citation` reason
precisely so the human reviewer does not have to.

## 2. The four semantic groups

### 2.1 Budget group — `state_budget`, `context_budget`, `step_reliability_budget`

**Conclusion: the three budget modules are never chained together, and
two of the three are not wired into the runtime at all.**

Measured over the runtime with `grep` on real import statements
(`from X import` / `import X`), excluding tests and excluding
`runtime_registration.py`, which only records module metadata:

| Module | Production importers | Chained with the others? |
| --- | --- | --- |
| `context_budget` | `context_controller.py:26`, `loop.py:363`, `episode_eviction.py:63` | — |
| `state_budget` | **none** | no |
| `step_reliability_budget` | **none** | no |

**Finding B1 — `state_budget` has zero production importers.**
`state_budget.py` caps agent state *size* in bytes and checks it at every
transition. Its own docstring says exactly why it exists: *"`long_horizon.py`
rebuilds a `RoundState` per round and keeps `verified_progress` /
`failures` / `context` growing; nothing in the runtime caps the size of
that state."* Nothing in the runtime does. The module is a guard with
nothing behind it.

*Why the slice's own tests didn't catch it.* The slice tested
`StateBudget.check()`, `.transition()`, `.try_transition()` and
`.would_fit()` as a unit — the cap works, in the unit. The slice never
wired it into `long_horizon.py`, and there is no test anywhere that
asserts "the runtime's state transition goes through a budget". A
per-slice acceptance is a unit test; it cannot detect that a unit is not
plugged in.

*Severity.* **should fix** — this is the batch's clearest instance of the
merged-tree blind spot: a whole slice, fully tested, doing nothing.

*Suggested action.* Dispatch a separate fix slice that wires
`state_budget.StateBudget` into the `long_horizon` round transition, and
adds a test that a round whose state exceeds the cap is refused.

**Finding B2 — `step_reliability_budget` has zero production importers.**
`step_reliability_budget.admit(p_meas, p_target, n)` answers "is this run
admissible at this measured per-step success rate", and
`required_step_rate` / `max_steps` convert between the three views. The
module has no caller. The admission gate it was built for is not
attached to the loop.

*Why the slice's own tests didn't catch it.* Same shape as B1: the slice
tested the arithmetic and the `AdmissionVerdict` fail-closed rule. The
slice's own test file is its only caller.

*Severity.* **should fix**, same reasoning as B1. If the intended
integration point is a policy the operator sets rather than a hard-wired
one, that intent should be written down — but then the module should say
so, and it currently reads as a gate that was meant to be one.

**Finding B3 — `context_budget` and `state_budget` measure different
things and say so, but nothing enforces the distinction.**
`context_budget` budgets **tokens** (`estimate_text_tokens`, four UTF-8
bytes per token); `state_budget` budgets **bytes of canonical JSON**.
`state_budget.py:18` says it outright: *"`context_budget.py` budgets
tokens, not bytes of state."* The vocabulary is split but the split is
**documented and disjoint** — the two modules do not mint the same word
for the same concept, and neither claims the other's unit. The tool's
Rule 3 finds **no vocabulary overlap in the budget group at all**.

*Severity.* **record only.** This is the one group whose vocabulary split
is clean. Recording it matters: it is the counter-example that shows the
other three splits are not inevitable.

**Finding B4 — `admit` is defined in two modules with different
signatures** (Rule 2, same-name-different-signature):

```
admit  cost_per_delivery(per_attempt_cost, resolution_rate, max_cost_per_delivery)
       step_reliability_budget(p_meas, p_target, n)
```

Both are "can this run be admitted at this rate". `cost_per_delivery` is
a money-per-outcome admission; `step_reliability_budget` is a
reliability-per-step admission. Both even return a type called
`AdmissionVerdict` — so a caller that reads the return type first will
not notice the swap, and only the arguments will differ. A caller that
means one and writes the other gets a `TypeError` — which is the *good*
outcome, but only by accident of arity.

*Why each slice's own tests didn't catch it.* Each slice tested its own
`admit` in isolation. Neither slice imported the other, so neither test
could have observed the collision.

*Severity.* **record only** — the arities differ enough that a mistake
raises rather than silently changing behaviour. But `cost_per_delivery` is
not in the four semantic groups; it entered the review because it shares
a name with a group member.

**Conclusion for the budget group.** One vocabulary overlap: **none**.
Two modules unwired: **yes** (B1, B2). One clean separation: **yes**
(B3). The budget group's problem is not vocabulary, it is **wiring**.

### 2.2 Evidence group — `verifiability_tier`, `scorer_disagreement`, `evidence_independence`

**Conclusion: no. The three verdict sets cannot be combined into one
consistent "final verdict", and the three modules never meet.**

Measured production importers, excluding tests:

| Module | Production importers |
| --- | --- |
| `verifiability_tier` | **none** |
| `scorer_disagreement` | **none** |
| `evidence_independence` | **none** |

**Finding E1 — the three verdict sets are disjoint, and there is no
combinator.**

| Module | Vocabulary | Shape |
| --- | --- | --- |
| `verifiability_tier` | `UNTESTED`, `CLAIMED`, `CHECKABLE`, `VERIFIED`, `REPLICATED` | an **ordinal** ladder of 5 tiers (`Tier.strength` 0..4) |
| `scorer_disagreement` | `pass`, `fail` (per-scorer); `pass`, `fail`, `contested` (per-case) | a **binary** verdict, plus `contested` as a third state |
| `evidence_independence` | `MIRROR`, `INDEPENDENT`, `UNDECIDABLE` | a **ternary** relation between a dissent and a seal |

The three answer three different questions:

* `verifiability_tier.grade(claim)` — *how checkable is this claim?*
  (5 levels, ordered)
* `scorer_disagreement.aggregate_verdict(verdicts, reducer)` — *did the
  scorers agree?* (2 levels, or `contested` / `None` on a tie)
* `evidence_independence.mirror_status(dissent, seal)` — *is the dissent
  independent of the seal?* (3 levels, unordered)

A "final verdict" would need to collapse an **ordered** 5-level ladder, a
**binary** pass/fail and an **unordered** 3-way relation into one value.
There is no such collapse, and there is no code that attempts one.

*Why each slice's own tests didn't catch it.* Each slice tested its own
vocabulary exhaustively against its own definition — `verifiability_tier`
tests all five tiers and the ordering, `scorer_disagreement` tests all
three reducers and the tie behaviour, `evidence_independence` tests all
three mirror statuses. What none of them tested is **whether a second
slice's verdict can be consumed**: the slices never import one another,
so there is no seam at which a conflict could show up. The conflict is
not "the tests were wrong"; it is "the tests were about different
questions and nobody asked whether the answers compose".

*Severity.* **should fix** — but the fix is a design decision, not a
bug. The right shape is probably a small `final_verdict` combinator that
takes the three inputs and refuses to answer when they disagree (the
fail-closed pattern this codebase already uses everywhere), rather than a
mapping table.

*Suggested action.* Dispatch a separate fix slice that writes the
composition rule down and implements it fail-closed, plus a test that a
`MIRROR` dissent can never produce a `VERIFIED`/`REPLICATED` tier on its
own.

**Finding E2 — `verifiability_tier`'s tier names are not Bronze/Silver/Gold
in the code.**
The task background calls them "Bronze/Silver/Gold". The code calls them
`CHECKABLE` / `VERIFIED` / `REPLICATED`, with the docstring mapping them
(`#: Bronze -- steps are described well enough to attempt verification.`).
The mapping is one-to-one and documented, so this is **record only** —
but a coordinator comparing this review against the background's wording
should know the code uses the long names, and that `CHECKLIST_QUESTIONS`
is the 10-question source checklist (`Q1`–`Q3` gate the grade).

**Finding E3 — Rule 3 finds no verdict-word overlap in the evidence
group.** The word sets are genuinely disjoint: no module writes `pass`,
`mirror` or `replicated` in another module's sense. The evidence group's
problem is **missing composition**, not **ambiguous vocabulary** — the
opposite of the refusal group's problem below.

**Conclusion for the evidence group.** Vocabulary overlap: **none**.
Combination into one final verdict: **not possible as the code stands**.

### 2.3 Compaction group — `compaction`, `event_condenser`, `reversible_compaction`, `scope_verbatim_compaction`

**Conclusion: a real compaction takes exactly one path, and the other
three paths are not on it. The three record shapes have no join key.**

**Which path a real compaction takes.** Traced from the caller down:

```
loop.py:2106   if should_compact(state.transcript, config.compaction_threshold_tokens):
loop.py:2107       outcome = self._compact(state, turn_index=turn_index)
loop.py:5140       outcome = compact(source_transcript, force=True, keep_messages=..., summarizer=..., instructions=...)
                          ^ compaction.compact  (components/northstar-agent-runtime/compaction.py)
```

`compaction.py` is the **only** compaction module a running agent
reaches. `loop.py:36` is its only production import
(`from compaction import CompactionOutcome, compact, should_compact`).
The `context_controller` may offload oversized tool results into
pointers *before* the summary is written, but the compaction itself is
`compaction.compact`.

Measured production importers:

| Module | Production importers | On the real path? |
| --- | --- | --- |
| `compaction` | `loop.py:36` | **yes** |
| `event_condenser` | none | no |
| `reversible_compaction` | none | no |
| `scope_verbatim_compaction` | none | no |

**Finding C1 — three of the four compaction paths are unreachable from
the runtime.**

`event_condenser` (condense a *log* by forgetting event ids, with a
replayable view), `reversible_compaction` (compact and keep a ticket back
to the original transcript, addressed by `transcript_hash`) and
`scope_verbatim_compaction` (carry a scope block *verbatim* across a
compaction boundary, addressed by `scope_hash` / `block_hash`) are three
different answers to "what should a compaction do", each fully
implemented and fully tested, and **none of them is what the runtime
does**.

*Why each slice's own tests didn't catch it.* Each slice tested its own
mechanism against its own contract: `event_condenser` tested replay
fidelity, `reversible_compaction` tested `revert()`, `scope_verbatim_compaction`
tested that the scope survives the boundary. Every one of those tests
passes, and every one of them would keep passing if `loop.py` called a
completely different module. The question "which of us does the runtime
call?" was never asked by any of them, because answering it requires
looking at `loop.py` — a file none of the three slices owns.

*Severity.* **should fix** — three substantial mechanisms
(compact-and-revert, scope-preservation-across-compaction,
log-condensation) that the runtime cannot use. The scope-preservation
one matters most: `b173-lessons.md` records *"Compaction 会丢 scope"*
(compaction loses scope) as a **known trap of this batch**, and
`scope_verbatim_compaction` is the slice that closes it — but the
runtime's compaction is `compaction.compact`, which does not carry the
scope. The trap is still open on the real path.

*Suggested action.* Dispatch a separate fix slice that decides the
compaction story — either `compaction.compact` grows the scope-carrying
contract, or `scope_verbatim_compaction` becomes the compaction the loop
calls — and adds a test that a scope qualifier survives a *real* loop
compaction, not just a unit call.

**Finding C2 — the three record shapes have no join key.**
Rule 4, on the compaction group:

```
event_condenser.CondensationEvent     {forgotten, summary, summary_offset}
reversible_compaction.CompactionRecord {summary, transcript_hash, prompt_hash, revert_token, schema}
scope_verbatim_compaction.CompactedSession {scope_block, transcript, summary, manifest, scope}
scope_verbatim_compaction.ScopeManifest {scope_hash, block_hash, scope_block, verbatim_fields, summarized_fields, scope_block_bytes, grants, scope_id}
```

The only field any two of them share is `summary` — free text, not a key.
`CondensationEvent` has `forgotten` (event ids) and `summary_offset` (an
index into a derived view). `CompactionRecord` has `transcript_hash` and
`prompt_hash`. `ScopeManifest` has `scope_hash` and `block_hash`. **There
is no field that names the same thing in two of them.** A record written
by one path cannot be looked up by another, and there is no key to
reconstruct one from.

*Why each slice's own tests didn't catch it.* Each slice's test
constructs and asserts on its *own* record type. There is no test that
takes a record from one module and looks it up in another, because no
slice knows the other exists.

*Severity.* **should fix** — a fork with no join key means the choice of
path is not reversible after the fact and records cannot be correlated
across paths.

*Suggested action.* Same fix slice as C1: one compaction path, one record
type, or an explicit translation layer with a documented join key.

**Finding C3 — `replay` is defined in two modules with different
signatures** (Rule 2):

```
replay  event_condenser(log)
        event_sourcing(events, handlers, initial)
```

`event_condenser.replay(log)` rebuilds the derived view from a
condensation log; `event_sourcing.replay(events, handlers, initial)`
rebuilds state from an event stream. Different arity, so a mix-up raises
— but both are called `replay` and both mean "rebuild from a log", which
is the classic same-name-different-meaning case.

*Why each slice's own tests didn't catch it.* Each tested its own
`replay` in isolation; neither imported the other.

*Severity.* **record only** — the arity protects it. `event_sourcing` is
not in the four semantic groups; it entered because it shares a name
with a group member.

**Conclusion for the compaction group.** Real path: **`compaction.compact`,
via `loop.py`**. Unreachable paths: **three**. Record shapes joinable:
**no**.

### 2.4 Refusal group — `refusal_row`, `scope_qualifier`, `refusal_monitor`, `refusal_hold`

**Conclusion: this is the group with a real vocabulary conflict. The
`denied` word is minted by three modules for at least three different
things. The `refusal_hold` slice narrows the gap but does not close it,
and this review's independent opinion on its key shape is in R4.**

**Finding R1 — the word `denied` is minted by three modules of the
refusal group, for three different things** (Rule 3).

| Module | Where | What `denied` means there |
| --- | --- | --- |
| `scope_qualifier` | `ROW_DENIED = "denied"` (a **row kind**) | "the scope did not match the source line; the action is BLOCKED" — a *scope verdict*, decided by the gate |
| `refusal_row` | inline literal (a **row field**) | the free-text `verdict` a caller recorded on a `RefusalRow` — a *refusal claim*, backed by four evidence digests |
| `refusal_hold` | inline literal (a **reason**) | `REASON_BLOCKED_BY_REFUSAL` / `REASON_BLOCKED_ROW_INVALID` / … — a *decision the hold made* |

`scope_qualifier`'s `denied` is a **scope** verdict: it says "this
permission's scope does not cover this line". `refusal_row`'s `verdict`
is a **refusal claim**: it says "a refusal happened, and here are the
four hashes that prove it". `refusal_hold`'s reasons are **hold
decisions**: they say "the hold looked and here is what it concluded".

The same word on all three, three different predicates.

*Why each slice's own tests didn't catch it.* Each slice tested its own
`denied` against its own contract: `scope_qualifier` tested that a
`ROW_DENIED` row blocks; `refusal_row` tested that a row with an
arbitrary verdict string round-trips (its `_VERDICT_RE` is
`^[a-z0-9][a-z0-9._-]*$` — deliberately open, so `denied` is legal
there); `refusal_hold` tested that each of its five reason constants is
produced in the right branch. **No slice could have caught this**, because
`refusal_row` accepts *any* verdict string by design, so no test of
`refusal_row` constrains what `scope_qualifier` means by `denied`, and
vice versa. The conflict is created by the *combination* of two open
sets.

*Severity.* **should fix** — a caller writing `"denied"` into a
`RefusalRow` and a caller writing `ROW_DENIED` into a `DenialRow` produce
two records that a reader will read as the same event.

*Suggested action.* Dispatch a separate fix slice that names the three
predicates distinctly (`scope_denied` / `refusal_recorded` /
`hold_blocked`) or introduces one shared refusal-vocabulary module that
all three import, so the words cannot drift apart again.

**Finding R2 — `refusal_row`'s key shape and `scope_qualifier.DenialRow`'s
key shape cannot be matched.**

```
refusal_row.RefusalRow          verdict, evidence_hash, ruleset_hash,
                                verifier_key, population_digest,
                                refused_at, reason, instruments,
                                single_instrument, row_digest

scope_qualifier.DenialRow       scope, kind, reason, signature
```

`RefusalRow` is keyed by **what proved the refusal**: the verdict plus
the evidence/ruleset/population digests. `DenialRow` is keyed by **what
was denied**: the scope text. There is no common field. `RefusalRow`
carries no scope; `DenialRow` carries no evidence digest and no
verifier. A `RefusalRow` cannot be looked up by scope, and a
`DenialRow` cannot be re-verified as a refusal.

*Why each slice's own tests didn't catch it.* Same shape as R1: each
slice tested its own row against its own contract, and neither slice
imported the other. `refusal_row` tests that a row round-trips and
`verify_row` detects tampering; `scope_qualifier` tests that a
`ROW_DENIED` row blocks the dispatch. There is no test that could ask
"does a refusal row answer the scope question?" — the question needs
both modules in scope.

*Severity.* **should fix**.

**Finding R3 — `refusal_monitor` is the third vocabulary, and it is
unwired.**

`refusal_monitor` counts refusals over time and reports an *efficacy*:
`RefusalEvent`, `EfficacyReport`, `EFFICACY_ALERT_THRESHOLD = 0.5`. It
answers "is refusing actually accomplishing anything?" — a different
question again from "was this action refused" (`refusal_row`) and "does
this grant cover this line" (`scope_qualifier`).

Measured production importers: **none**. Only `tests/test_refusal_monitor.py`
imports it.

*Why the slice's own tests didn't catch it.* The slice tested the
monitor's counting and its alert threshold. Nothing tested that the
runtime produces the `RefusalEvent`s the monitor consumes — because
nothing produces them.

*Severity.* **should fix**, same class as B1/B2.

**Finding R4 — independent opinion on `refusal_hold`'s key shape.**
The coordinator asked for an opinion it can compare against the
`refusal-hold` slice's own reasoning. Here it is, stated plainly.

`refusal_hold.RefusalHoldKey` is a triple: `(scope_kind, scope_id,
action)`, with `scope_kind ∈ {queue, task}`, canonicalised as
`"<scope_kind>:<scope_id>:<action>"`, and colons forbidden inside a part
so the string form is unambiguous. That is a **good key**: it names
*this action, in this scope*, at the granularity of the thing that
re-dispatches (a queue job id or a task id). It is strictly finer than
`DenialRow.scope` (a rendered scope text) and strictly coarser than
`RefusalRow` (which carries no scope at all).

What `refusal_hold` does with the *second* refusal family is the
important part, and here this review **disagrees with the framing** in
the task background. The background says today's `refusal-hold` slice is
"filling this gap". It is not, and the slice does not claim to be:
`refusal_hold.py:287` says it outright —

> A `scope_qualifier.DenialRow` is **not** [a refusal row]: it is a scope
> verdict sidecar with no evidence hash, no ruleset hash, no instrument
> and no population digest, so it cannot be re-verified and it does not
> carry the "two instruments or none" basis. **The second refusal family
> is explicitly excluded.**

and the behaviour is *fail-closed*: a `DenialRow` registered in the hold
produces `REASON_BLOCKED_ROW_INVALID` and **blocks** the dispatch
(`refusal_hold.py:527-536`).

**This review's opinion:** that exclusion is *correct*, and it is the
right shape for the gap — but it closes the gap by **refusing**, not by
**joining**.

* The `DenialRow` → `RefusalHoldKey` mapping is not merely missing; it
  **cannot** be built from the data the two rows carry. `DenialRow.scope`
  is a rendered scope line; `RefusalHoldKey.scope_id` is a job or task
  id. Nothing in `DenialRow` names a job or a task. A bridge would have
  to be *invented*, and an invented bridge is exactly the kind of
  silently-wrong mapping that lets a refused action through.
* So the honest closure is: the hold does not try to read the
  scope-qualifier store. It holds `RefusalRow`s (which carry their own
  evidence) and refuses anything it cannot verify. A `DenialRow` in the
  hold blocks, loudly, with a named reason.
* The residual gap is therefore **not** in `refusal_hold`; it is that
  `scope_qualifier.DenialRowStore` and the refusal machinery are two
  parallel gates that never consult each other. `loop.py:671` reads the
  scope registry; `refusal_hold` is not called from `loop.py` at all.
  **The scope gate and the refusal gate do not meet.**

*Why the refusal-hold slice's own tests didn't catch it.* The slice
tested its own behaviour exhaustively, including the `DenialRow`
exclusion case (`tests/test_refusal_hold.py:431-451`). It could not
observe the *absence of a bridge*, because the absence is only visible
from the outside: no test asserts "the scope gate and the refusal gate
agree", because that assertion would need a seam that does not exist.

*Severity.* **should fix** — but the fix is *not* "make `refusal_hold`
accept `DenialRow`s". The fix is a shared refusal vocabulary and an
explicit statement of which gate is authoritative for which question.

*Suggested action.* Dispatch a separate fix slice that (a) introduces one
shared refusal-vocabulary module (R1), (b) documents that the scope gate
answers "does this grant cover this line" and the refusal gate answers
"was this action already refused", and (c) either wires the two gates
together at the dispatch site or states in the design docs that they are
independent and why.

**Finding R5 — Rule 4 on the refusal group: the record shapes do not
join.** `RefusalRow` (10 fields, four of them evidence digests),
`DenialRow` (4 fields), `RefusalEvent` and `RefusalHoldEntry` — the
tool reports 4 record-shape conflicts in this group, all with an empty
shared-field set for the row pairs. This is R2 seen from the mechanical
side.

**Conclusion for the refusal group.** Vocabulary overlap: **yes, three
modules mint `denied` for three different predicates**. Key shapes
matchable: **no**. `refusal_hold`'s exclusion of `DenialRow` is
**correct and fail-closed**, and it does **not** close the gap — the
gap moved, it did not close.

## 3. Doc sampling — 12 design docs, every cross-slice reference checked

Twelve design docs were sampled, chosen to cover every group and every
slice that touches another slice's module. For each, the tool resolved
every `module.symbol` reference the doc makes against the tree as it
stands today.

| Design doc | `module.symbol` refs into the tree | Dangling | Result |
| --- | --- | --- | --- |
| `refusal-hold.md` | 5 | 0 | clean |
| `refusal-row.md` | 2 | 0 | clean |
| `scope-verbatim-compaction.md` | 6 | 0 | clean |
| `tool-output-filter.md` | 8 | 0 | clean (after resolution fix) |
| `durable-resume.md` | 12 | 0 | clean |
| `signed-receipt.md` | 5 | 0 | clean |
| `declarative-retry-config.md` | 5 | 0 | clean |
| `checkpoint-durability.md` | 5 | 0 | clean |
| `annotation-pin.md` | 5 | 0 | clean |
| `event-condenser.md` | 0 | 0 | clean (1 foreign citation) |
| `verifiability-tier.md` | 0 | 0 | clean |
| `scorer-disagreement.md` | 0 | 0 | clean |
| `evidence-independence.md` | 0 | 0 | clean |
| `state-budget.md` | 0 | 0 | clean |
| `step-reliability-budget.md` | 0 | 0 | clean |

**Across all 62 design docs there are 89 `module.symbol` references into
the tree; exactly one of them (`ledger.verdicts`) does not resolve.**

**Finding DOC1 — the doc-drift risk is real but small, and it is
concentrated in one place.** The `tool-output-filter.md` doc cites
`context_controller._offload_tool_results` and `context_controller._screen`
— both of which are **private methods of `ContextController`**, cited
without naming the class. The first version of the tool reported them as
dangling; they are not. They are a *citation style* risk: a doc that
cites a private method without its class is one refactor away from
drift, and a tool that only looks at module-level names cannot tell the
difference. The tool now resolves a method name against the classes of
the module.

*Why no slice's own test caught it.* No slice's test asserts anything
about another slice's doc. Doc correctness is not a test surface in this
repository at all — which is why the *tool* had to be built before the
finding could be made.

*Severity.* **record only** — the references resolve today. The tool
fix is the guard.

**Finding DOC2 — the docs that cite the *most* are the ones the tool
found clean.** `durable-resume.md` (12 references), `tool-output-filter.md`
(8) and `scope-verbatim-compaction.md` (6) all resolve. The doc-drift
risk that did materialise (`ledger.verdicts`) is in a doc that makes
**zero** `module.symbol` references into a runtime module — it names an
attribute of a module in prose. That is the shape of drift the tool is
weakest at, and it is worth knowing: **a doc that cites no symbols
cannot be checked by symbol resolution.**

*Severity.* **record only**, with the tool's own blind spot named.

## 4. Summary of findings

| ID | Location | Conflict | Severity | Action |
| --- | --- | --- | --- | --- |
| D1 | `docs/design/capability-ceiling-probe.md:124` | doc names `ledger.verdicts`; no such attribute | should fix | fix slice: implement or rewrite |
| B1 | `state_budget.py` | zero production importers; the state-size cap is not on the round transition | should fix | fix slice: wire into `long_horizon` |
| B2 | `step_reliability_budget.py` | zero production importers; the admission gate is not attached | should fix | fix slice: wire or document intent |
| B3 | `state_budget` / `context_budget` | bytes vs tokens — **documented and disjoint** | record only | none |
| B4 | `cost_per_delivery.admit` / `step_reliability_budget.admit` | same name, different signature, same return type name | record only | none (arity protects) |
| E1 | the three evidence modules | three disjoint verdict sets; no combinator exists | should fix | fix slice: a fail-closed combinator |
| E2 | `verifiability_tier.Tier` | code names are `CHECKABLE`/`VERIFIED`/`REPLICATED`, not Bronze/Silver/Gold | record only | none (mapping is documented) |
| E3 | the three evidence modules | no vocabulary overlap | record only | none |
| C1 | `event_condenser`, `reversible_compaction`, `scope_verbatim_compaction` | three unreachable compaction paths; the scope-loss trap is still open on the real path | should fix | fix slice: one compaction path |
| C2 | the four compaction record types | only `summary` in common; no join key | should fix | fix slice: one record type or a join key |
| C3 | `event_condenser.replay` / `event_sourcing.replay` | same name, different signature | record only | none (arity protects) |
| R1 | `scope_qualifier`, `refusal_row`, `refusal_hold` | `denied` minted by three modules for three predicates | should fix | fix slice: one shared vocabulary |
| R2 | `RefusalRow` / `DenialRow` | key shapes not matchable | should fix | fix slice: shared vocabulary |
| R3 | `refusal_monitor.py` | zero production importers; the third vocabulary is unwired | should fix | fix slice: wire or document |
| R4 | `refusal_hold.RefusalHoldKey` | the `DenialRow` exclusion is correct and fail-closed, and it does **not** close the gap — the scope gate and the refusal gate never meet | should fix | fix slice: shared vocabulary + wire the two gates |
| R5 | the refusal record types | no shared fields | should fix | same fix slice as R1 |
| DOC1 | `tool-output-filter.md` | private methods cited without their class — resolves today | record only | none (tool guards it) |
| DOC2 | `capability-ceiling-probe.md` | the tool's blind spot: prose-only citations cannot be symbol-checked | record only | none |

**Seven findings that need a fix slice** (D1, B1, B2, E1, C1, C2, R1,
R2, R3, R4 — the refusal ones share one slice), **the rest are
record-only**.

**The one-line conclusion.** The B173 batch did **not** produce a
semantic conflict between two slices that both run. It produced
something the merged-tree review was supposed to look for and did find:
**four coherent mechanisms that the runtime never calls.** `state_budget`,
`step_reliability_budget`, `refusal_monitor` and the three alternative
compaction paths are each fully tested, each internally consistent, and
each unreachable from a running agent. The per-slice acceptance process
is structurally blind to this: a slice that is never wired in passes
every test it has. **The merged-tree review's main finding is not a
conflict between two slices — it is that half of the batch is
disconnected.**





