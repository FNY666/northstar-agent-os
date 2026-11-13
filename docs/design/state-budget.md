# State budget: a hard cap on agent state size, enforced at every transition

This document describes one slice of Northstar: a **hard byte cap on the
agent's state** that is checked at **every state transition**, so state
growth is an enforced invariant rather than a hope.

Source: jido, `agentjido/jido` — Elixir/BEAM, v2.0 (March 2026), 1,912 stars
(pushed 2026-11-10); frontier rank 7. The upstream repository was **not**
crawled for this slice: Jido is Elixir/BEAM and Northstar is not, so the
brief's quotation of the mechanism is the source of record. Quoted text below
is marked *verbatim as briefed*; everything else is marked as a **Northstar
extension** and is this repository's own design.

The module: `components/northstar-agent-runtime/state_budget.py`.
The tests: `components/northstar-agent-runtime/tests/test_state_budget.py`.

---

## 1. What Northstar has today (read from the code, not assumed)

### 1.1 Is there a cap on state size today?

No. A search of the runtime for a state-size bound (`max_state`,
`state_size`, "state budget") returns only `formal_verif.py`'s `max_states`
guardrail — the number of *states* an explicit-state BFS may visit, a
model-checking bound, not a bound on the size of an agent's state.

`components/northstar-agent-runtime/long_horizon.py` defines `RoundState`
(line 283) with the fields `round_index`, `objective`, `verified_progress`,
`failures`, `context`, `context_digest`. Each round appends to
`verified_progress` and `failures` (the `LongHorizonLoop.run` loop, lines
1015-1107) and the context tuple is rebuilt per round by the manager. No
field of that record carries a size bound, and nothing in the runtime caps
the accumulated state.

### 1.2 Where does the state grow?

* `long_horizon.py`: `RoundState.verified_progress` and `.failures` grow
  one entry per round/evidence item; `RoundState.context` is rebuilt per
  round from the manager backend.
* `memory.py`: `WorkspaceMemory` (line 162) holds one discovered memory
  file per name, with a `chars` count in `as_dict()` — a *report* of size,
  not a limit on it.
* `compaction.py`: `compact()` (line 450) summarises a *transcript* by
  token threshold (`should_compact`, line 444).

### 1.3 Is compaction the only brake?

For the *transcript*, yes: `compaction.py` is the only thing in the runtime
that shrinks anything, and it shrinks the transcript, not the state. Two
reasons that brake is the wrong place for a hard bound:

* it is a *threshold* brake, not a cap — the transcript is allowed to
  exceed the threshold until a compaction actually runs;
* compaction is itself the consent-boundary risk the frontier round named
  (scope qualifiers get dropped, cancellation gets lost), so it should not
  also be the only thing standing between a run and unbounded state.

`context_budget.py` is a different quantity: it budgets **tokens** of
context engineering (offload/summarize thresholds, measured harness
defaults), not bytes of agent state. There is no byte cap on state anywhere.

---

## 2. The source: Jido's StateBudget

Verbatim as briefed (the frontier round's reading of
`lib/jido/agent/state_budget.ex`):

    StateBudget.transition/2, check/1, check!/1

    every state transition is budget-checked (agent declares max_state_size),
    so state growth is an enforced invariant, not a hope.

and, from the frontier round's conclusion about Northstar:

    a hard cap on agent state size enforced at every transition — is the
    missing guard for Northstar's long-horizon runs, where context/state
    grows unboundedly until compaction (which is itself the consent-boundary
    risk).

Three things travel from that mechanism:

1. the agent **declares** a `max_state_size`;
2. **every** transition is checked against it;
3. there is a `check` and a `check!` (the raising form).

---

## 3. The Northstar module

### 3.1 The unit

`state_budget.py` measures state in **bytes of canonical JSON**: sorted
keys, compact separators, UTF-8. Canonicalization is what makes the number
reproducible — two states that differ only in dict insertion order measure
the same, so a size in a report can be recomputed by anyone.

Python object memory is deliberately **not** used: it is not reproducible
across runs, and a budget that cannot be reproduced cannot be audited.

The canonicalizer is the runtime's shared `canonical_json` module (RFC 8785
JCS), with a local `json.dumps` fallback — the same try/except shape
`ai_constitution.py` and `failure_bundle.py` use, so the module stays
importable standalone.

*Northstar extension*: Jido's brief does not name a unit. The byte unit
and the canonicalization rule are Northstar's choice, and the module
documents them (`UNIT = "bytes"`).

### 3.2 Declaration fails closed

```python
budget = StateBudget(max_state_size=1_048_576)   # bytes
```

`max_state_size` must be a positive `int`. `0`, a negative number, a
`bool`, a `float` and a `str` are all refused with `ValueError`. A budget
without a cap is not a budget, so there is no "unlimited" mode: the module
has no way to be constructed that does not bound state.

### 3.3 The enforced path

```python
result = budget.transition(state, {"step": 3, "note": "..."})
result.state          # the new state
result.current_size   # measured bytes of the new state
result.budget         # the budget, current_size updated
```

`transition()` measures the state *after* applying the delta, checks it
against the cap, and only then updates `current_size`. The check happens on
**every call**. There is no accumulate-now-reconcile-later path: the
module exposes no "deferred" or "checkpoint" entry point, and the only way
to grow the state is through `transition()`.

When the new state does not fit, `OverBudget` is raised:

| attribute | meaning |
|---|---|
| `current_size` | bytes of the state before the refused transition |
| `max_state_size` | the declared cap |
| `delta_bytes` | how many bytes this delta would have added |
| `projected_size` | the size the state would have reached |

The refusal is explicit and checkable: the delta is **not** applied, the
caller's state is not mutated, and `current_size` does not move. Nothing is
silently truncated and nothing is quietly dropped — a truncation would make
the state smaller than the agent believes it is, which is the failure this
slice exists to prevent.

`try_transition()` is the same enforcement with the refusal returned
instead of raised (`TransitionOutcome.accepted` is `False`, `.refusal`
carries the `OverBudget`). It is a different *surface*, not a different
*rule*: the check still happens at the transition.

### 3.4 The check pair (Jido's `check` / `check!`)

```python
budget.check(state)          # bool
budget.check_or_raise(state) # raises OverBudget when over budget
```

`check_or_raise` is the mirror of Jido's `check!/1`: silent inside the
budget, `OverBudget` outside it. A state that cannot be canonicalized is
*not* within budget — an unmeasurable state cannot be shown to fit.

### 3.5 The compaction interface (interface only, no compaction here)

```python
budget.would_fit(state, delta)   # bool -- predict before committing
budget.bytes_over_budget(state)  # int -- how many bytes to reclaim
```

`would_fit()` uses the same measurement and the same rule as `transition()`,
so a caller that asks first gets the answer the transition would give.
`bytes_over_budget()` is the caller's signal for how much to compact away.

This slice does **not** implement compaction and does **not** touch
`compaction.py`. It supplies the number; the caller decides what to drop —
and that decision stays in the caller's hands, where the consent boundary
lives.

---

## 4. Mapping to the source

| Source (Jido, verbatim as briefed) | Northstar | Note |
|---|---|---|
| agent declares `max_state_size` | `StateBudget.max_state_size` | positive int only, fails closed |
| `StateBudget.transition/2` | `StateBudget.transition(state, delta)` | returns a `TransitionResult`; checks on every call |
| `StateBudget.check/1` | `StateBudget.check(state)` | bool |
| `StateBudget.check!/1` | `StateBudget.check_or_raise(state)` | raises `OverBudget` |
| "every state transition is budget-checked" | the check is inside `transition()`; there is no other way to grow state | *Northstar extension*: the refusal is a typed exception carrying the numbers |

Northstar extensions beyond the brief:

* the byte unit and the canonical-JSON measurement rule;
* `OverBudget` carrying `current_size` / `max_state_size` / `delta_bytes` /
  `projected_size`;
* `try_transition()` (returned refusal instead of raised);
* `would_fit()` and `bytes_over_budget()` — the compaction interface;
* `measure_state()` as a public, testable measurement function.

Not absorbed from Jido: the BEAM supervision tree and the action/directive
split. Only the budget-check pattern travels.

---

## 5. Honest scope

* This module is a **guard**, not an integration. It is not wired into
  `long_horizon.py`, `state_machine.py` or `loop.py` in this slice, so
  nothing in the runtime calls it yet. The wiring is where the value is,
  and it is left open on purpose: `long_horizon.py` is a read-only module
  for this slice.
* The delta is a **shallow key-wise update**. A caller with a nested state
  must pass the nested part it wants changed; the module does not merge
  recursively.
* The measurement counts the state as it is handed in. If a caller keeps
  state outside the mapping it passes, that state is not measured — the
  budget covers the state the caller presents.
* A state that cannot be canonicalized is refused rather than estimated.
