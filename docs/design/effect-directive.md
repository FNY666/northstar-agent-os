# effect-directive — directive/action separation

Status: implemented (B173, slice `effect-directive`).
Module: `components/northstar-agent-runtime/effect_directive.py`
Tests: `components/northstar-agent-runtime/tests/test_effect_directive.py`

## 0. What a directive is (read this first)

**A directive is an effect *description*, not an instruction.**

It is *not* a "user instruction" and *not* a "system instruction". The
source text this slice absorbs says a directive is a bare struct that
"只描述外部效应、永不改状态" — it only describes an external effect and never
changes state. The safety properties that are actually borrowable are
three, and they are about *where code comes from*, not about instructions
versus behaviour:

1. **LLM/tool output is only data.** It arrives as a signal; it never
   parses into a directive.
2. **Only host code can mint a directive.**
3. **The routing table is fixed at compile time.**

Anything in this document that says "directive" must be read as
"effect description". The word "instruction" appears in exactly one
directive kind name (`RunInstruction`), copied verbatim from the source.

## 1. Source mapping

### 1.1 Verbatim from the source (Jido, `agentjido/jido`)

These are the source's own words and are reproduced here as the rule, not
as a paraphrase:

| Source fact | Where this slice puts it |
| --- | --- |
| `Agent.cmd/2` is pure: takes an agent + a signal, returns (updated agent, directives list) | `decide(state, signal, router) -> DecideResult`, a `NamedTuple` of `(state, directives)`; pure, no effects, input state not mutated |
| A directive is a bare struct describing an external effect; it never mutates state | `Directive` (frozen dataclass): `kind`, `payload_json`, `idempotency_key` — a description, nothing more |
| The directive type set is closed: `Emit / Error / SpawnAgent / StopChild / Schedule / RunInstruction / Stop / Cron / CronCancel` | `DIRECTIVE_KINDS` (exactly those nine); `mint()` and `Directive.__post_init__` reject anything else with `UnknownDirectiveKind` |
| The runtime interprets and executes directives (`AgentServer` + `DirectiveExec`) | `DirectiveExec`: the only object holding an effect sink; the only place an external effect is produced |
| Internal state operations (`StateOp`) never leave `cmd/2` | `decide()` returns a new state; it never mutates the caller's state and never performs an effect |
| The turn pipeline has seven steps: signal → route → run action → validate candidate → persist commit → dispatch directive → settle | `TURN_PIPELINE_STEPS` (exactly those seven names, in order); `run_turn()` walks them in that order and reports which step it reached |
| A failed turn keeps the pre-commit state | `run_turn()` returns `committed=False` and the *pre-commit* state on any pre-commit failure; nothing is dispatched |
| A directive that fails after the commit cannot be undone; it needs an idempotency key | `Directive.idempotency_key`, derived deterministically by `derive_idempotency_key()`; `DirectiveExec` executes a key at most once |
| `SignalRouter` maps signals to actions through a routing table fixed at compile time | `SignalRouter` — the table is frozen (`MappingProxyType`) at construction; `install_router()` is the single entry point and happens in host code at setup time |

The source line reference given in the slice brief is
`lib/jido/agent.ex` 34–60 for the directive struct and the closed type set.

### 1.2 Northstar extensions (not in the source)

These are Northstar's own additions, needed to make the pattern hold in
Python and in this runtime:

* **A host capability object.** The source enforces "only host code can
  mint" by virtue of being Elixir: a directive struct can only be built
  by calling the constructor, and the constructor lives in host code. In
  Python a caller can construct any object, so the boundary is made
  explicit: `mint()` requires `HostCapability`, and the module's single
  capability instance `HOST_CAPABILITY` is the only accepted one
  (`MintError` otherwise). `HostCapability(proof=...)` is *not* an escape
  hatch: `mint` compares identity (`is`), not the proof value, so a
  hand-built capability is refused.
* **`parse_untrusted()` — the anti-injection boundary.** The source has
  no equivalent: untrusted text simply never reaches the directive
  constructor. In Northstar, model and tool output cross a trust
  boundary as text/JSON, so there must be an explicit function that says
  "no". `parse_untrusted()` returns a `ParseResult` with `accepted=False`
  and `directive=None` for **every** input, including a payload that
  literally contains `Emit(...)` or a JSON object shaped like a
  directive. It returns rather than raises, so a caller that forgets to
  check still receives no directive.
* **A routing-table registry.** `install_router()` / `default_router()` /
  `installed_routers()`: the analogue of the compile-time route table in
  a language with import-time setup.
* **`run_turn()` with pluggable validator / persister / executor.** The
  source's pipeline is fixed; Northstar's is a function with explicit
  injection points so the failure branches are testable offline.
* **A receipt ledger on the executor.** `ExecReceipt` records, per
  dispatch, whether the effect actually happened and why.

### 1.3 Honest corrections (things the source does *not* say)

* A directive is not a "user instruction" or a "system instruction" — see
  §0.
* The nine kind names and the seven pipeline steps are the source's; the
  *semantics* attached to them here are Northstar's.
* Nothing in this module has been run against a live provider, a live
  queue or a live clock. Every test is offline and deterministic; the
  only sink is a recording callable in the test.

## 2. Northstar gap this closes

Read from the code, not assumed:

* `deliberative_spec.py` (136 lines) is an audit gate requiring spec
  citations before a decision. It is not effect separation.
* `constitutional_ai.py` (809 lines) is a principle / self-review /
  revision ledger. It is not effect separation.
* `safety_envelope.py` bounds *physical* actuation (torque, speed,
  exclusion zones) for a human authority. It says nothing about generic
  external effects.
* A repo-wide grep for `class .*Directive` returned nothing: there was no
  typed effect envelope, no host-only minting path, and no interpreter
  that is the sole source of external effects.
* `state_budget.py` (the `jido-statebudget` slice, commit `2c48ef0a`) is a
  hard cap on state *size* — a different layer. It is read-only here and
  is not touched.

**Can today's model output mint an executable action?** Before this
slice: there is no module that turns model output into an action at all —
the runtime's tool path is a separate concern (`tool_use.py`,
`tool_failure.py`, permissions) and none of it offers a typed effect
envelope with a host-only minting boundary. So the gap is not "the model
can mint"; it is that **there is no envelope to mint into and no single
place where effects are produced**. This slice adds the envelope, the
boundary and the interpreter, and leaves the existing tool path alone.

## 3. API

```python
from effect_directive import (
    DIRECTIVE_KINDS, TURN_PIPELINE_STEPS, HOST_CAPABILITY,
    Directive, Signal, SignalRouter, DecideResult, TurnResult,
    DirectiveExec, ExecReceipt,
    mint, parse_untrusted, decide, run_turn,
    install_router, default_router, installed_routers,
)
```

### 3.1 Minting

```python
d = mint("Emit", {"text": "hello"}, capability=HOST_CAPABILITY)
```

* `kind` must be in `DIRECTIVE_KINDS`; otherwise `UnknownDirectiveKind`.
  A near-miss (`"Emit "`, `"emmit"`, `"EMIT"`) raises — it is never
  folded into a neighbouring kind.
* `capability` must be `HOST_CAPABILITY`; otherwise `MintError`.
* `idempotency_key` defaults to `derive_idempotency_key(kind, payload_json)`
  — deterministic over the canonical JSON payload, so the same effect
  description always carries the same replay guard.

### 3.2 Untrusted input

```python
result = parse_untrusted(model_output)
# result.accepted is False, result.directive is None, always.
```

There is no input for which `parse_untrusted` returns a directive.

### 3.3 Pure decide

```python
new_state, directives = decide(state, signal, router)
```

* `router` may be omitted, in which case the installed default router is
  used.
* The input state is never mutated; the returned state is a fresh
  `MappingProxyType` over a copy.
* Two calls with the same `(state, signal)` give equal results.
* No effect sink is reachable from the decide path — the executor is
  never passed to `decide`.
* An action returns either a new state or `(new_state, directives)`. A
  non-`Directive` in the directives tuple is an explicit
  `EffectDirectiveError`.

### 3.4 Routing

```python
router = SignalRouter({"say": action})
router.known_types()          # ("say",)
router.action_for(Signal("x")) # raises UnknownSignal
```

The table is frozen at construction; `router.routes[...] = ...` raises
`TypeError`. There is **no default action**: an unknown signal type is
an error, because a fallback is precisely what turns a routing mistake
into a silent wrong effect.

### 3.5 The turn pipeline

```python
result = run_turn(
    state, signal, router,
    validator=None,   # (state, directives) -> bool
    persister=None,   # (state) -> None, raises CommitFailure
    executor=None,    # DirectiveExec
)
```

The seven steps, in order:

1. `signal` — supplied by the caller.
2. `route` — `router.action_for(signal)`; unknown type → failed turn at
   step `route`.
3. `run_action` — the action runs; `ActionFailure` → failed turn; a
   non-directive in the result → failed turn.
4. `validate_candidate` — the optional validator; `False` or
   `ValidatorFailure` → failed turn.
5. `persist_commit` — the optional persister; `CommitFailure` → failed
   turn.
6. `dispatch_directive` — the executor runs the directives.
7. `settle` — done.

**Failure semantics (fixed):**

| Failure | State | Dispatched |
| --- | --- | --- |
| route / action / validate / commit | the **pre-commit** state | nothing |
| dispatch, after the commit | the committed state | the failure is reported, the commit is *not* rolled back (it cannot be undone) |

A post-commit effect failure is therefore visible in `result.failure`,
and the retry path is the idempotency key: the executor does not re-execute
a key it has already executed, and a key whose effect *failed* was not
recorded as executed, so a later retry can still perform it exactly once.

### 3.6 Execution

```python
executor = DirectiveExec(sink)
receipts = executor.dispatch(directives)
```

`DirectiveExec` is the only holder of the sink and therefore the only
place an external effect is produced. A key already executed is a no-op
and yields a receipt with `executed=False` and `detail` starting with
`"replay"`.

## 4. Rules and thresholds, written down

| Rule | Value |
| --- | --- |
| Directive kinds | exactly the nine source names; anything else raises |
| Idempotency key format | `ed.v1:<sha256 hex>` over `kind\n` + canonical payload JSON |
| Canonical JSON | `sort_keys=True, separators=(",", ":"), ensure_ascii=False` |
| Unknown signal | explicit error, no fallback |
| Pre-commit failure | pre-commit state kept, no dispatch |
| Post-commit failure | commit stands, failure reported, no double execution |
| Replay | same key executed at most once per executor |
| Router table | frozen at construction; runtime edits raise `TypeError` |
| Registry | a router name can be installed once |
| External effects | only inside `DirectiveExec._sink` |

No thresholds are configurable: this module has no budget, no timeout and
no counter. Anything of that kind belongs to the surrounding runtime.

## 5. Tests

`components/northstar-agent-runtime/tests/test_effect_directive.py` — 40
test methods in five classes:

* `ClosedTypeSetTests` — the nine kinds, kinds outside the set,
  near-miss spellings not folded into a neighbour, the seven pipeline
  steps.
* `MintingBoundaryTests` — missing capability, forged capability,
  injection payloads (`Emit(...)`, directive-shaped JSON, every shape
  refused), and that an injection payload never reaches the effect sink.
* `PurityTests` — determinism, the input state is not mutated, the pair
  return, no effect during decide, an action may *describe* a directive
  but not perform one, a non-directive action result is refused.
* `FrozenRoutingTests` — the table cannot be edited, unknown signals
  raise and name the known types, a router name cannot be reused.
* `TurnSemanticsTests` — success commits and dispatches; action /
  validator / commit failures roll back to the pre-commit state and
  dispatch nothing; unknown signal fails at `route`; a replay executes
  once; a post-commit failure is reported but not rolled back; a failed
  effect can be retried and then executes exactly once.
* `IdempotencyKeyTests` — deterministic key, distinct keys for distinct
  effects, key format, an empty key is refused.
* `ExecutionIsolationTests` — the executor is the only effect producer,
  a non-directive is refused, a non-callable sink is refused, every
  dispatch is receipted, and the module source contains no `os.system` /
  `subprocess` / `socket` (it cannot produce an effect on its own).

## 6. Open items

* The module is **not yet wired into the runtime's tool path**. Wiring it
  in means routing tool calls through `decide` + `run_turn` and moving
  the tool side effect into a `DirectiveExec` sink. That touches files
  outside this slice's scope (`tool_use.py`, `permissions.py`, …) and is
  left for a follow-up slice.
* The host capability is an in-process object, not a cryptographic
  capability. It defends the code/data boundary (untrusted text cannot
  become a directive); it does not defend against malicious code running
  in the same process. A future slice could bind the capability to a
  signed host receipt.
* `RunInstruction` is carried as a kind name only; Northstar has not
  defined what an instruction payload means, and no action in this slice
  mints one.
* `Schedule` / `Cron` / `CronCancel` are carried as kind names only;
  no scheduler is attached. The executor treats every kind uniformly,
  which is enough to prove the boundary but not to schedule anything.
* The 8 failing governance-bench cases and the 27 failing runtime tests
  are the **pre-existing baseline** of this branch; this slice adds no
  new failure. See the slice report for the item-by-item comparison.
