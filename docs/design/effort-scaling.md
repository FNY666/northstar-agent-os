# Effort scaling: task complexity → parallelism

Slice: `anthropic-effort-scaling`
Module: `components/northstar-agent-runtime/effort_scaling.py`
Tests: `components/northstar-agent-runtime/tests/test_effort_scaling.py`

## 1. The gap this slice fills

Northstar already had the pieces around a multi-agent run:

| module | what it owns |
|---|---|
| `planner_gates.py` | plan shape: subgoal count, cycle detection, critic verdicts |
| `budget.py` | money: `max_budget_usd`, per-model pricing, parent/child roll-up |
| `compute_budget.py` | signed compute ceilings (`units_total`, hardware tier, device class) |
| `agents.py` | subagent definitions: `max_turns`, `max_tool_calls`, `max_budget_usd` |
| `multi_agent.py` | the coordination ledger: `spawn` / `coordinate` / `merge` |

What none of them had was the *explicit mapping* from "how hard is this
task" to "how much parallelism should the host spend". A host could read
`max_tool_calls=40` off an `AgentDefinition`, but nothing said whether a
task deserved one agent or a dozen.

This slice is that mapping, and nothing more.

## 2. Source

**Anthropic Engineering, "How we built our multi-agent research system"**
(Jeremy Hadfield et al., 2025-06-13),
<https://www.anthropic.com/research/multi-agent-research-system>.

Every claim marked **[Anthropic]** below is a verbatim sentence from that
article. Every claim marked **[Northstar]** is this slice's own work and
is **not** Anthropic content.

### 2.1 [Anthropic] The effort-scaling table

> "Simple fact-finding requires just 1 agent with 3-10 tool calls"

> "direct comparisons might need 2-4 subagents with 10-15 calls each"

> "complex research might use more than 10 subagents with clearly divided
> responsibilities"

> "These explicit guidelines help the lead agent allocate resources
> efficiently"

> "prevent overinvestment in simple queries, which was a common failure
> mode in our early versions"

### 2.2 [Anthropic] The two levels of parallelization

> "Our early agents executed sequential searches, which was painfully slow"

> "the lead agent spins up 3-5 subagents in parallel rather than serially"

> "the subagents use 3+ tools in parallel"

> "These changes cut research time by up to 90% for complex queries"

### 2.3 [Anthropic] Where multi-agent fits — and where it does not

> "multi-agent systems excel at valuable tasks that involve heavy
> parallelization"

> "information that exceeds single context windows"

> "require all agents to share the same context"

> "involve many dependencies between agents are not a good fit for
> multi-agent systems today"

> "most coding tasks involve fewer truly parallelizable tasks than research"

### 2.4 [Anthropic] Compression via subagents

> "Subagents facilitate compression by operating in parallel with their own
> context windows"

### 2.5 [Anthropic] Orchestrator-prompt sensitivity

> "small changes to the lead agent can unpredictably change how subagents
> behave"

> "Early agents made errors like spawning 50 subagents for simple queries"

### 2.6 [Anthropic] Background numbers — **not** an acceptance criterion

> "agents typically use about 4x more tokens than chat interactions"

> "multi-agent systems use about 15x more tokens than chats"

> "Claude Opus 4 as the lead agent and Claude Sonnet 4 subagents"

> "outperformed single-agent Claude Opus 4 by 90.2% on our internal research
> eval"

> "token usage by itself explains 80% of the variance"

The 90.2% figure and the 4x/15x token multiples are Anthropic's *internal
evaluation* numbers, taken from a different system (Opus 4 lead + Sonnet 4
subagents on a research eval). They are background here. **Nothing in this
slice's test suite asserts against them**, and no Northstar number is
derived from them.

## 3. What is Anthropic's and what is Northstar's

| rule | owner | where it lives |
|---|---|---|
| Simple → 1 agent, 3–10 tool calls | **[Anthropic]** | `EFFORT_SCALING_TABLE[COMPLEXITY_SIMPLE]` |
| Moderate → 2–4 subagents, 10–15 calls each | **[Anthropic]** | `EFFORT_SCALING_TABLE[COMPLEXITY_MODERATE]` |
| Complex → 10+ subagents, clearly divided responsibilities | **[Anthropic]** | `EFFORT_SCALING_TABLE[COMPLEXITY_COMPLEX]` |
| Lead spawns 3–5 subagents in parallel | **[Anthropic]** | `LEAD_PARALLEL_SPAWN_MIN/MAX`, `ParallelPlan.parallel_spawn_count` |
| Each subagent uses 3+ tools in parallel | **[Anthropic]** | `TOOLS_PER_SUBAGENT_MIN`, `ParallelPlan.tools_per_subagent` |
| Shared-context / dependency / non-parallel disqualifiers | **[Anthropic]** | `check_applicability` |
| **How a Northstar task is graded** | **[Northstar]** | `classify_complexity` |
| **Concrete counts inside Anthropic's bands** (Moderate→4, Complex→12) | **[Northstar]** | `MODERATE_DEFAULT_SUBAGENTS`, `COMPLEX_DEFAULT_SUBAGENTS` |
| **The tool-call budget seam to `budget.py` / `agents.py`** | **[Northstar]** | `plan_effort(remaining_tool_call_budget=...)` |
| **The window-card degradation rule** | **[Northstar]** | `parallel_plan_for`, `ParallelPlan.degraded` |
| **The 3-window card cap itself** | pre-existing | `WINDOW_CARD_LIMIT` — this slice never changes it |

## 4. The mapping, end to end

`plan_effort(signals)` runs four steps in this order, and the order is the
point:

1. **`classify_complexity(signals) -> ComplexityAssessment`** — grades the
   task and returns the reasons that produced the grade.
2. **`check_applicability(signals) -> Applicability`** — decides whether a
   multi-agent shape fits *at all*.
3. **`effort_scaling_for(tier) -> EffortScaling`** — Anthropic's row.
4. **`parallel_plan_for(row, window_cards=...) -> ParallelPlan`** — the two
   levels of parallelization plus the card degradation.

If step 2 closes the gate, steps 3–4 do **not** run on the original row:
the plan becomes a single agent and the disqualifiers are recorded in
`EffortPlan.degradation_reasons`. The tier is still reported (the task
*is* complex), but no multi-agent shape is forced onto it.

### 4.1 The classifier [Northstar]

Inputs (`TaskSignals`): `independent_directions`,
`info_exceeds_context_window`, `tool_complexity`, `dependency_degree`,
plus the applicability inputs `shared_context_required` and
`truly_parallelizable`.

The rule, in the order it is applied:

1. Start at `simple`.
2. `independent_directions` in `[2, 4]` → `moderate`; `>= 5` → `complex`.
3. `info_exceeds_context_window` → raise to at least `moderate`.
4. `tool_complexity >= 3` → raise one step (capped at `complex`).
5. `dependency_degree == "high"` → cap at `moderate`.

Band edges are inclusive on both ends: 1 direction is simple, 2 and 4 are
moderate, 5 is complex. Steps 3–5 are what turn a task that *looks*
single-direction into a multi-agent shape: a task with one direction but
five complex tools still needs more than one agent.

Every step that fires appends a human-readable reason, so
`ComplexityAssessment.reasons` explains the grade rather than restating it.

### 4.2 The table rows

| tier | Anthropic band | Anthropic tool band | concrete mapping | who chose it |
|---|---|---|---|---|
| simple | `1` agent | `3-10` tool calls | 1 agent × 3 tools | **[Anthropic]** band, **[Northstar]** concrete 3 |
| moderate | `2-4` subagents | `10-15` calls each | 4 subagents × 10 tools | **[Anthropic]** band, **[Northstar]** concrete |
| complex | `10+` subagents | (not stated in the source) | 12 subagents × 10 tools | **[Anthropic]** band, **[Northstar]** concrete |

Anthropic states a tool-call band for the simple and moderate rows but
**not** for the complex row; the complex row's per-agent tool count (10)
is this slice's choice and is marked as such in the code.

### 4.3 The two levels of parallelization

- **Level 1 — the lead's fan-out.** `ParallelPlan.parallel_spawn_count`:
  how many subagents the lead agent creates *at the same time*. Anthropic's
  band is 3–5; the plan takes `min(5, subagent_count)` when at least 3
  subagents fit, the subagent count when fewer than 3 fit (with a recorded
  reason), and 1 for a single-agent row.
- **Level 2 — the tools inside a subagent.**
  `ParallelPlan.tools_per_subagent`: how many tools each subagent uses at
  the same time. Anthropic's floor is 3; the plan takes
  `max(row.tools_per_subagent, 3)`.

`ParallelPlan.scale` returns the pair `(subagent_count,
tools_per_subagent)` the task book asks for.

### 4.4 The applicability gate

`check_applicability` names each disqualifier separately:

| reason constant | Anthropic's wording |
|---|---|
| `shared_context_required` | agents that "require all agents to share the same context" |
| `agent_dependencies` | tasks that "involve many dependencies between agents" |
| `not_truly_parallelizable` | work that cannot actually be run in parallel |

When any of them fires, `plan_effort` returns a **single agent** with the
reasons attached. It does not fall back to "some smaller number of
subagents" — Anthropic's own reading is that these shapes are not a
multi-agent task at all.

Note that `dependency_degree == "high"` feeds **both** the classifier (it
caps the tier at `moderate`) and the gate (it disqualifies multi-agent
outright). The two are consistent: a task with heavy dependencies is
graded down *and* refused a multi-agent shape.

### 4.5 The window-card degradation [Northstar]

Northstar's host may hold a fixed number of context-window cards. This
slice models that cap as `WINDOW_CARD_LIMIT = 3` and never changes it.

When a row asks for more subagents than there are cards, the mapping is
degraded **for that call only**:

- `ParallelPlan.subagent_count` becomes the card count;
- `ParallelPlan.requested_subagent_count` keeps what was asked for;
- `ParallelPlan.degraded` is `True`;
- `ParallelPlan.degradation_reasons` explains it in words.

So a Complex task (12 subagents) on a 3-card host becomes 3 subagents,
and the plan still says 12 were requested. The cap itself is untouched:
nothing in this module writes a cap anywhere.

### 4.6 The budget seam [Northstar]

`plan_effort(..., remaining_tool_call_budget=N)` is where the mapping meets
`budget.py` and `agents.py`. When the row's total tool-call count
(`subagent_count * tools_per_subagent`) exceeds what is left, the
per-agent tool count is clamped down to `remaining // subagent_count` (at
least 1), `EffortPlan.tool_calls_clamped` is set, and the clamp is
recorded as a degradation reason.

This module does **not** import `budget.py` or `compute_budget.py` and does
not mutate a budget object. It computes the number a host should enforce;
the host enforces it. That keeps the slice read-only with respect to
every other module (see the SCOPE note in the task book).

## 5. The three driven paths

Driven for real in the module's `main()` self-check and asserted in
`tests/test_effort_scaling.py`:

**(a) A simple query.** `TaskSignals(independent_directions=1,
tool_complexity=1)` → tier `simple` → row `1` agent / `3-10` tool calls →
`scale == (1, 3)`, `parallel_spawn_count == 1`, `multi_agent` is False. No
subagent is spawned.

**(b) A complex query.** `TaskSignals(independent_directions=9,
info_exceeds_context_window=True, tool_complexity=4)` → tier `complex` →
row `10+` subagents → level 1 fan-out inside Anthropic's 3–5 band, level 2
at 3+ tools per subagent. On the standard 3-card host the mapping is
degraded to 3 subagents and the degradation is recorded.

**(c) An inapplicable task.** `TaskSignals(independent_directions=9,
shared_context_required=True, dependency_degree="high",
truly_parallelizable=False)` → the gate closes → **one agent**, all three
disqualifiers recorded, no multi-agent shape forced.

## 6. Honest scope

- This module computes a mapping. It spawns no agent, runs no LLM, spends
  no budget, reads no clock and writes no cap. The parallelism it returns
  is a *declared plan*, not an observed execution.
- The classifier is a declared-input classifier: the host tells it how
  many independent directions the task has. It does not parse a task
  description and does not count anything itself.
- The concrete counts (4 and 12 subagents, 10 tools) are this slice's
  choices inside Anthropic's bands. A different host may pick different
  points; the bands are the contract, the points are not.
- The 3-window card cap is modelled here as a constant. If the host's real
  cap is different, pass it as `window_cards`.

## 7. Open items

1. The classifier consumes *declared* signals. Wiring it to a host that
   derives `independent_directions` from a plan is a separate slice.
2. The complex row has no Anthropic tool-call band; the value 10 is
   Northstar's. If a source with a complex-row band appears, the table
   row should be revisited.
3. The budget seam computes a number; it does not yet call
   `Budget.reserve` or `AgentDefinition.max_tool_calls`. The enforcement
   side is the host's.
