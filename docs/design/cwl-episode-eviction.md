# CWL structured context eviction — typed episodes, dependency DAG, graduated eviction

Status: implemented (module + tests + this document). Slice: B173
`cwl-episode-eviction`.

## What this slice is

Northstar today compresses a long context with `compaction.compact()`: the
prefix of a transcript is replaced by one extractive summary string
(`compaction.extractive_summary`, clipped at 4000 chars) plus a
tool-provenance ledger, and the original bytes are gone
(`components/northstar-agent-runtime/compaction.py`). The sibling slices
`reversible_compaction.py` (a ticket back to before the cut) and
`scope_verbatim_compaction.py` (the scope block crosses a compaction
verbatim) both work on *that* mechanism: they govern what a summary may
lose and how a cut may be undone.

This slice is a different mechanism. It implements **structured eviction**:
the trajectory is cut into typed episodes by an explicit delimiter protocol,
the episodes form a typed dependency DAG, and an over-budget session is
shrunk by a deterministic, graduated policy that never calls the model and
never writes a summary. Eviction is not a fallback for a failed
compaction; it is a structural operation on a graph.

Module: `components/northstar-agent-runtime/episode_eviction.py`
Tests: `components/northstar-agent-runtime/tests/test_episode_eviction.py`

## Source mapping — verbatim vs Northstar extension

### Verbatim from arXiv:2606.11213

Source: Andrew Semenov & Svyatoslav Dorofeev (Kiz8), "Beyond Compaction:
Structured Context Eviction for Long-Horizon Agents", 2026-04-21,
<https://arxiv.org/html/2606.11213>. The quotes below are verbatim from
that paper (or, where the paper states a rule in its own words, the rule is
quoted with the paper's wording marked).

**The three elements.** CWL has typed episodes, an explicit dependency
graph, and a graduated eviction policy that is deterministic and
model-free.

**The delimiter schema.** One tool whose "sole purpose is to segment the
trajectory". Fields: `action` "start"|"end"; `name` required when `action`
is "start"; `type` "expl"|"act" required when `action` is "start";
`dependencies` a string array, "Required when starting an "act" chunk" and
"must reference names of earlier "expl" chunks"; `description` "Required
when ending an "expl" chunk" and "rejected when ending an "act" chunk".

**The four canonical invocations.** `{"action":"start","name":"…","type":"expl"}`,
`{"action":"start","name":"…","type":"act","dependencies":["expl-a",…]}`,
`{"action":"end","description":"…"}`, `{"action":"end"}`.

**Episode types.** Exploratory episodes gather information; "Raw content is
usually unneeded once the inference is drawn", and the description the
agent supplies on close "is the only content retained after full eviction".
Action episodes are the agent's work — writes, edits, tool calls — whose
effects are durable in the environment, "making them the first candidates
for eviction".

**The graph.** `G = (V, E)` with an edge `(u, v)` meaning action episode `v`
declared a dependency on exploratory episode `u`. "Compression removes
nodes but never alters edges."

**Invariants.**

* Acyclicity — "dependencies may only reference already-closed episodes, so
  cycles cannot form."
* Typed edges — "all edges run expl → act"; action-to-action and
  expl-to-expl dependencies "are not expressible in the protocol".
* Prologue protection — everything predating the first `start` call
  (system prompt, tool definitions, initial user turns) is "not eligible for
  eviction under any circumstances".
* Active episodes — `start` issued but `end` not yet arrived: "Active
  episodes are never eligible for eviction".

**Algorithm 1.** While the counted tokens exceed the budget: candidates are
episodes that are closed, non-prologue, non-active, and whose dependents
are all fully evicted; the target is the "oldest ACT episode in candidates,
or oldest EXPL episode if no ACT exists"; levels are tried least destructive
first and "after each applicable strip, re-check the budget and return
immediately if satisfied".

**The dependency constraint.** An exploratory episode `u` is eligible only
once every action episode `v` with `(u, v) ∈ E` has been fully evicted —
otherwise "the reasoning behind a decision" would be dropped while the
decision stays on record.

**The four levels, least destructive first.** (1) reasoning-trace
stripping (exploratory only); (2) bulk-output stripping — "large enumerable
tool outputs (search results, grep/glob listings)"; (3)
intermediate-artifact stripping — "smaller interactions (file reads, bash
commands and outputs)"; (4) full episode removal, the "last resort if
stripping is exhausted and budget is still exceeded".

**User turns.** "User turns are preserved exactly at every level"; if the
budget cannot be met without touching them, "the system surfaces the
condition rather than degrading silently".

**The budget.** `τ = 80,000` tokens, "roughly 30% of the evaluated models'
context window". The paper reports "20–70% inference cost reduction" from
the resulting prefix stability.

**The six principles.** P1 "Compression is part of the protocol, not a
recovery action." P2 "The agent is the authority on structure." P3 "User
content is inviolable." P4 "Causal dependencies dominate recency." P5
"Compression must not invoke the model." P6 "Graduated, not catastrophic."

**The tradeoffs the paper names.** Annotation burden; dependence on
annotation quality (with the conservative default that unannotated content
counts as exploratory with unknown dependencies, "retained until action
episodes are exhausted"); episode-graph overhead; KV-cache invalidation,
since "eviction mutates the prompt prefix".

### Northstar extensions (designed here, not quoted from the paper)

* **The receipt shape** (`EvictionReceipt`: episodes touched, levels
  applied, tokens freed, budget met or not, plus the unmeetable flag and
  reason) is Northstar's. The paper describes an eviction *pass*; it does
  not describe a receipt format.
* **The integration point with `compaction.py`** — eviction first, summary
  as the fallback — is Northstar's. The paper does not mention Northstar's
  compaction path at all.
* **Token counting** uses Northstar's existing yardstick,
  `context_budget.estimate_text_tokens` ("four UTF-8 bytes per token"),
  which `context_budget` documents as "the same rule the runtime's
  transcript estimator uses (`providers.base.estimate_transcript_tokens`)".
  The paper says only "token accounting" and never fixes a counting
  function.
* **The single-active-episode rule** — a `start` while another episode is
  active is refused with a message naming the rule — is Northstar's
  enforcement of the paper's "only single linear episode streams plus
  dependency edges" limitation. The paper does not spell out the refusal.
* **The token split into parts** (reasoning / bulk output / intermediate
  artifacts / core) is Northstar's, made so that the paper's four levels
  have something to strip; the paper names the levels and the kinds of
  content, but not a per-episode token accounting structure.
* **The UNMEETABLE verdict** is Northstar's name for the paper's "surfaces
  the condition rather than degrading silently".

## What was read in this repository before designing (read, not assumed)

* `compaction.py` — `compact()` returns a `CompactionOutcome` whose
  `transcript` is `(boundary,) + kept`; the summary is a single string from
  `extractive_summary`, clipped at 4000 chars. This is the model-invoking
  mechanism this slice deliberately does **not** extend.
* `context_budget.py` — `estimate_text_tokens()` is the runtime's token
  yardstick ("four UTF-8 bytes per token", "the same rule the runtime's
  transcript estimator uses"); `ContextThresholds` is where every
  context-engineering number lives. The paper's `τ = 80,000` is therefore
  *not* hard-coded into another threshold dataclass here: the module takes
  the budget as an argument, with `DEFAULT_TOKEN_BUDGET = 80_000` as the
  paper's value.
* `checkpoints.py` — checkpoint lineage and transcript digests. Not
  touched by this slice; the episode graph is a live structure in the host
  process, which is exactly the "episode graph overhead" tradeoff the paper
  names.

## The module

`components/northstar-agent-runtime/episode_eviction.py`

| Public name | Role |
| --- | --- |
| `Episode` | one typed episode: `name`, `type` (expl/act), `dependencies`, `description`, `status` (open/closed/evicted), `prologue`, token parts, `token_count` |
| `EpisodeGraph` | the append-only typed DAG: `add_prologue`, `add_episode`, `close_episode`, `add_dependency`, `add_user_turn`, `set_tokens`, `handle_delimiter`, `dependents`, `token_count` |
| `parse_delimiter_call` | the paper's schema check; raises `DelimiterError` naming the broken rule |
| `handle_delimiter` | schema check + graph rules (one active episode; dependencies reference closed expl episodes) |
| `EvictionPolicy` | Algorithm 1: `candidates`, `select_target`, `evict_to_budget` |
| `EvictionLevel` | the four levels in the paper's order |
| `EvictionReceipt` | Northstar's receipt |
| `count_tokens` | episodes + user turns |
| `evict_to_budget` | module-level convenience wrapper |

### Invariants, and how each one fails closed

* **Acyclicity** — `add_episode(..., dependencies=[...])` and
  `add_dependency(source, target)` both require the dependency source to be
  an existing, *closed* `expl` episode. An unclosed or unknown reference
  raises `EpisodeGraphError` / `DelimiterError`; it is never recorded.
* **Typed edges** — the dependency target must be an `act` and the source
  an `expl`. `act -> act` and `expl -> expl` are refused with a message
  naming the rule. An `expl` episode may not declare dependencies at all.
* **Prologue protection** — `add_prologue()` marks an episode `prologue`;
  it is never a candidate, and no level can touch it.
* **Active protection** — an episode that was started but not ended has
  status `open`; it is never a candidate.
* **User turns** — stored outside the episode graph as `UserTurn` records.
  They count toward the budget but no level can touch them.

### The eviction loop

`EvictionPolicy.evict_to_budget(graph)`:

1. If the graph already fits the budget, the receipt says `budget_met` and
   nothing is touched.
2. Otherwise loop: pick the target (oldest eligible `act`, else oldest
   eligible `expl`; oldest = smallest `seq`), apply **one** level, re-count
   the tokens, and stop the moment the budget is met.
3. When no candidate remains and the budget is still unmet, the receipt
   carries `unmeetable=True` and a reason naming the protected content
   (prologue, active episode, user turns). Nothing is silently dropped.

One level per round is what makes "re-check the budget after each
applicable strip" observable: the receipt's `levels_applied` list is the
exact sequence the policy took, and it is reproducible.

### The loop's termination guarantee

The loop's natural exits are steps 2's "budget is met" and step 3's "no
candidate remains". Both depend on an invariant that **spans two
methods**: a level that `_level_applicable` reports must be one that
`_apply_level` **strictly reduces**. `_level_applicable` asks whether
`reasoning_tokens > 0`; `_apply_level` sets it to `0`. The two agree
because they are edited in the same file — and nothing *enforced* that
agreement.

Measured 2026-11-21: **eleven mutations** of this module broke that
invariant, and each one turned the loop into an **infinite** one. With
`gt@735` mutated (`reasoning_tokens > 0` → `>= 0`), `_level_applicable`
kept reporting `STRIP_REASONING` after `_apply_level` had already zeroed
the field, and the loop never ended.

The consequence was not a wrong answer but a **hung test run**, and it
had a second-order effect: the mutation probe reports a timed-out test as
`SKIP (test timeout)`, which is neither a kill nor a survival. So the
slice's whole-file census **never produced a number** — eleven sites
each burned the probe's 180-second timeout, every run, forever. The
slice's own accept metric said `1/1` only because the accept probe stops
at the first kill, which came long before the hanging sites.

The fix is a **bound**: `EvictionPolicy` takes `max_rounds` (default
`DEFAULT_MAX_EVICTION_ROUNDS = 64`), and the loop runs at most that many
rounds. The bound turns "the loop terminates" from a coincidence of two
methods agreeing into a property of the loop itself. It is generous —
every episode takes at most four levels, so 64 rounds cover sixteen
episodes — and the bound is a **parameter**, so a caller that knows its
graph shape can raise it.

The bound also makes the mutants killable: with the loop bounded, the
hanging mutants now *fail* the suite instead of hanging it, and the
census completes.

### The dependency constraint, precisely

`EpisodeGraph.dependents(name)` lists the episodes that declare `name` as a
dependency and are not yet evicted. An `expl` episode with a non-empty
dependent list is **not** a candidate. It becomes a candidate only once
every dependent `act` has been fully evicted (status `evicted`), which is
the paper's rule that the reasoning behind a decision must not be dropped
while the decision is still on record.

## The three driven paths

The slice drives three paths end to end (they are the `RealPathTests` in
the test file, not a description of intent):

* **(a) Over-budget session, mixed expl and act.** A session with a
  prologue, a user turn, two expl and two act episodes (the second act
  depending on the second expl) is pushed over budget. The two ACT
  episodes are touched before any EXPL episode, oldest first. An EXPL
  episode whose dependent is still live is never touched.
* **(b) Dependency violation.** An `act` that depends on an `expl`: while
  the act is live the expl is not a candidate; after the act is fully
  evicted the expl becomes eligible and is evicted in the same pass if the
  budget still demands it.
* **(c) Prologue and active under extreme pressure.** With a 900-token
  prologue, a user turn and an open episode, the budget cannot be met. The
  policy evicts what it legally can, then reports `unmeetable` with a
  reason naming the prologue, the active episode and the user turns. It
  does not degrade silently and does not touch protected content.

## Relation to `compaction.py` (the integration point — Northstar extension)

The two mechanisms answer different questions and neither replaces the
other:

* `compaction.py` asks "can a lossy summary stand in for this prefix?" —
  it is model-invoking, lossy, and one-way (the sibling slice
  `reversible_compaction.py` adds the way back).
* `episode_eviction.py` asks "which *structured* parts of the context can
  be dropped without touching user content, the prologue, an active
  episode, or the reasoning a live decision depends on?" — it is
  model-free, deterministic, and structural.

The intended order is **eviction first, summary as the fallback**: run
`EvictionPolicy.evict_to_budget()`; if it returns `budget_met`, the
session continues with the structured context and no summary is written at
all; if it returns `unmeetable`, the host has an explicit condition to
surface and may then fall back to `compaction.compact()`. This module does
**not** call `compaction.py` — wiring that order into a host is left open
(see "Open items"), because no host file is in this slice's writable scope.

## Open items

* The host-side wiring (eviction first, summary fallback) is not in this
  slice; the module is a library with no caller.
* The paper's conservative default for *unannotated* content ("counts as
  exploratory with unknown dependencies, retained until action episodes are
  exhausted") is not implemented here: the module only knows episodes the
  agent explicitly delimited. An unannotated region would have to be
  modelled by the caller as an `expl` episode with unknown dependencies.
* The paper's `τ ∈ [80,000, 120,000]` sensitivity discussion, its
  cross-task-dependency case study, and its accuracy table (Terminal Bench
  2.0 68.25% vs 68.40% baseline, SWE Bench Lite 43.00% vs 40.00%, Recovery
  Bench 66.80% vs 69.75%, LongCLI Bench 20.00% vs 20.00%) are results of
  the paper's own harness with GPT-5.4 on a fork of pi.dev. **No live
  provider was run for this slice**: nothing here was measured against a
  model, and the numbers above are the paper's, quoted as the paper's.
* The paper's KV-cache-invalidation tradeoff is not mitigated here beyond
  the budget being an explicit argument.
