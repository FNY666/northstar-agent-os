# Agent handoff: `transfer_to_<name>` tool with a fixed destination

Status: implemented for B173 slice "agent-handoff". Northstar had no way
for one agent to hand a conversation to another specialist.

Module: `components/northstar-agent-runtime/agent_handoff.py`
Schema pin: `northstar.agent-handoff.v1` — module version pin:
`agent-handoff.v1`

## Source of the mechanism

OpenAI Agents SDK, official documentation
<https://openai.github.io/openai-agents-python/handoffs/> and API
reference <https://openai.github.io/openai-agents-python/ref/handoffs/>.
The `handoff()` source was read in full on 2026-11-14.

Throughout this document:

* **[OpenAI]** marks a rule transcribed from that source.
* **[Northstar]** marks an extension of this repo that is **not** OpenAI
  content.

## What the code said before this slice

Read from the code, not assumed:

* **`multi_agent.py`** mentions OpenAI Swarm only in a module docstring
  (line 7: *"**OpenAI Swarm** (github.com/openai/swarm, MIT) -- agent
  handoffs"*). That is a documentation reference in a comment, not an
  implementation: there is no tool, no destination, no filter.
* **`a2a_gates.py`** is a *gate*, not a handoff. `A2AGate.check_handoff(
  from_agent, to_agent, payload)` returns `allow` / `deny_sabotage` /
  `deny_turf_war`. It runs *before* a handoff is accepted and decides
  whether the handoff may proceed; it never chooses a destination, never
  presents a tool to a model, and never filters an input.
* **`hinted_handoff.py`** is Dynamo-style *write buffering*
  (DeCandia et al. 2007): `HintedHandoff.store(hint_id, key, value,
  target_node, seq, ttl_seqs)` books a hinted write for an unavailable
  owner; `deliver()` and `expire()` move it to `delivered` / `expired`.
  The unit is a key/value write and a *node*; the words "handoff" and
  "target" appear, but the semantics are a durable write buffer, not an
  agent-to-agent conversation transfer.
* **`tripwire_guardrails.py`** owns the three-valued gate outcome
  (`TripwireOutcome.ALLOW` / `REJECT_CONTENT` / `HALT`) and the scope
  vocabulary (`CHAIN_ENTRY` / `TERMINAL` / `PER_ACTION`). It does **not**
  contain the rule about *which agent* a guardrail applies to.

A grep of the repository for `transfer_to` returned nothing: **no
handoff tool existed**.

## What this module does

`HandoffRegistry` is a registry of handoff *tools* plus the validation
around invoking one. It is a pure data structure: no LLM, no Runner,
no network, no model call.

### Registration — the tool the model sees

```python
registry = HandoffRegistry()
registry.register_agent("triage_agent")
registry.register_agent("refund_agent")

record = registry.register(
    "triage_agent", "refund_agent",
    input_schema=order_schema,
    input_filter=strip_secrets,
    on_handoff=on_handoff,
)
record.tool_name  # -> "transfer_to_refund_agent"
```

**[OpenAI]** "handoffs are tools to the LLM, default name
`transfer_to_<agent_name>`". `Handoff.default_tool_name(agent)` produces
the default; `tool_name_override` / `tool_description_override` replace
it.

**[OpenAI]** "without a `tool_name_override`" the default tool identity
is recorded — `_default_tool_identity = (agent.name, tool_name)`. This
module mirrors it exactly: `HandoffRecord.default_tool_identity` is
`(target_name, tool_name)` when the tool name was *not* overridden and
`None` when it was.

**[Northstar]** The registry stores agent **names** (strings) only. It
never holds an agent object.

### Construction-time validation — errors surface immediately

**[OpenAI]** "construction-time arity validation (input_type =>
`on_handoff` takes exactly 2 args, else exactly 1, else `UserError`)".

This module enforces it in `register()`, never later:

| situation | outcome |
|---|---|
| `input_schema` given, `on_handoff` missing | `HandoffConfigError` |
| `input_schema` given, `on_handoff` takes 1 arg | `HandoffConfigError` |
| `input_schema` given, `on_handoff` takes 2 args | accepted |
| no `input_schema`, `on_handoff` takes 2 args | `HandoffConfigError` |
| no `input_schema`, `on_handoff` takes 1 arg | accepted |
| `target_name` was never registered as an agent | `HandoffConfigError` |

`HandoffConfigError` is this repo's fail-closed analogue of the OpenAI
`UserError`. The arity is counted with `inspect.signature`; a variadic
callback (`*args`) satisfies either arity.

### Invocation — the destination is fixed

```python
target = registry.invoke(record, {"order_id": "o-1"}, ctx=ctx)
```

**[OpenAI]** "`handoff()` captures one agent and always returns it,
`on_handoff` is side effects only". `invoke()` returns
`record.target_name` — the target captured at registration — and the
return value of `on_handoff` is discarded. A callback that returns a
different agent name is ignored; the destination does not move.

### Strict input validation

**[OpenAI]** "strict JSON validation of model input (partial=False,
strict=True, contains_tool_data=True)" and "input_json None with
input_type => span error + ModelBehaviorError".

The module reimplements the strict rules:

* an unknown property is refused;
* a missing required property is refused;
* a property whose declared type does not match is refused (`bool` is
  not an `integer`; `integer` is not a `boolean`);
* `input_json` that is not valid JSON is refused.

**[OpenAI]** "input_json_schema always forced strict" — this module
only ever validates strictly; there is no lenient mode.

**[OpenAI]** "input_json None with input_type => span error +
ModelBehaviorError" — when a schema is present and `input_json` is
`None`, an `HandoffErrorRecord` is booked **first** and only then is
`HandoffValidationError` (this repo's `ModelBehaviorError` analogue)
raised. The booking order is observable: `registry.errors()` is
non-empty even though the exception was raised.

### `input_filter` — opt-in

**[OpenAI]** "input_filter opt-in (without it full context incl. tool
history passes)".

**[Northstar]** The filter is a **pure function over a canonical
record** (a mapping), not a callback over an SDK context object.

Without a filter the full context passes through unchanged, and the
booked `HandoffDecision` carries `filtered=False` so the caller can
see that the payload was *not* filtered. With a filter the decision
carries `filtered=True` and the filtered mapping.

A filter that raises is wrapped in `HandoffFilterError` and
**propagates**: the handoff does not happen and no decision is booked.
The error is never swallowed and never degrades into "pass the context
through unfiltered".

### `is_enabled` — hiding a handoff from the caller

**[OpenAI]** "`is_enabled` bool or callable, disabled handoffs hidden
from the LLM".

`is_enabled` is a bool or a callable `(ctx, target) -> bool`. A handoff
whose predicate is false is **not** in `visible_handoffs(agent_name)` —
it is hidden from the caller, exactly as the OpenAI runtime hides a
disabled handoff from the model. Invoking a disabled handoff anyway
raises `HandoffTargetError`: the record is known but not usable.

**[OpenAI]** "the internal `_is_enabled` will assert the target must be
an `Agent`" — the module asserts the destination is a registered agent
name and fails closed (`HandoffTargetError`) otherwise.

### Failure semantics

**[OpenAI]** "`failure_error_function` semantics (calling agent stays
active after handled failure, callback errors handled without rolling
back side effects, cancellation/formatter/hook/filter errors
propagate)".

`invoke()` propagates every failure. `invoke_handled()` adds the
OpenAI wrapper:

| situation | behaviour |
|---|---|
| `on_handoff` raises | `HandoffCallbackError` propagates; **side effects that already happened are not rolled back**; the calling agent stays active (`HandoffErrorRecord.caller_stays_active is True`); no `STATUS_HANDOFF` decision is booked — the error is never disguised as a successful handoff |
| `failure_error_function=None` | the exception keeps propagating (the OpenAI default) |
| `failure_error_function` set | the failure is formatted and booked as a `STATUS_FAILED` decision with `caller_stays_active=True`; the calling agent stays active |
| the formatter itself raises | the formatter's exception propagates |
| cancellation (`HandoffCancelled`, `asyncio.CancelledError`) | always propagates, even with a formatter configured |
| an `input_filter` raises | always propagates, even with a formatter configured |

**[OpenAI]** "redaction wrapper on invoke" — the OpenAI SDK wraps the
invocation entry point in `_invoke_handoff_with_redaction`. This
module does not implement redaction; it is **not** claimed here.

### Guardrail placement — recorded, not executed

**[OpenAI]** "handoffs stay within one run, input guardrails first agent
only, output guardrails final agent only".

**[Northstar]** The registry *records* the placement and hands it to the
caller; it does not execute any guardrail.

```python
registry.begin_run("run-1", "triage_agent")     # first agent of the chain
registry.set_final_agent("run-1", "refund_agent")  # produced the final output
scope = registry.guardrail_scope("run-1")
scope.input_agent   # -> "triage_agent"  (input guardrails apply here)
scope.output_agent  # -> "refund_agent"  (output guardrails apply here)
```

`tripwire_guardrails.py` owns the outcome vocabulary
(`ALLOW` / `REJECT_CONTENT` / `HALT`) and is **read-only** here — it was
not modified. The placement rule is not part of that module.

### What this module deliberately does not do

* **No LLM, no Runner.** A handoff books a decision; it does not run
  the next agent. The next agent's execution is the host's job.
* **No redaction.** The OpenAI invocation wrapper is not reimplemented.
* **No `nest_handoff_history`.** [OpenAI] marks it an opt-in beta that
  is off by default; this module does not implement it, and the default
  (off) is the behaviour here.
* **No dynamic destination selection.** [OpenAI] "`on_handoff` is side
  effects only" — the destination is fixed at registration.
* **No network, no timers, no wall clock.** Ordering is the caller's
  responsibility.

## Fail-closed inventory

Every one of these raises rather than degrading silently, and none of
them substitutes a different destination:

| input | error |
|---|---|
| `input_json` is not valid JSON | `HandoffValidationError` |
| unknown property in strict mode | `HandoffValidationError` |
| missing required property | `HandoffValidationError` |
| property type mismatch | `HandoffValidationError` |
| `input_json is None` while a schema is present | `HandoffValidationError` (after booking an error record) |
| destination never registered | `HandoffConfigError` |
| handoff disabled | `HandoffTargetError` |
| callback arity wrong | `HandoffConfigError` (at registration) |
| `input_filter` raised | `HandoffFilterError` |
| `on_handoff` raised | `HandoffCallbackError` |

## Three driven paths

The module's `main()` self-check drives the three headline paths, and
the test suite asserts each of them:

1. **triage → refund specialist.** `transfer_to_refund_agent` is
   registered with a filter that strips `card_number` / `ssn`. The
   destination stays `refund_agent` and the handed-on payload carries
   only the filtered fields.
2. **Strict input validation.** A payload missing a required field is
   refused; the refusal is booked as an error record and the calling
   agent stays active (the same handoff succeeds on the next call).
3. **A disabled handoff.** `is_enabled=False` keeps it out of
   `visible_handoffs()` and makes a direct invocation fail closed.

## Not confused with `hinted_handoff.py`

Both modules use the word "handoff"; they are different things, and
two tests pin the difference:

* `hinted_handoff.HintedHandoff` books a *write* for an unavailable
  owner (`store` / `deliver` / `expire`, a `target_node`, a `pending`
  status). It has no agent, no tool name and no destination.
* `agent_handoff.HandoffRegistry` books a *conversation transfer* to a
  named agent (`register` / `invoke` / `visible_handoffs`, a
  `transfer_to_<name>` tool, a fixed `target_name`). It has no hint
  ledger, no TTL and no delivery state.
