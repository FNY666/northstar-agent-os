# Typed tool-failure normalization

Status: implemented for B173 (slice `toolfail`).

One rule: **a tool failure is never an exception, a crash, or a bare string.**
Every failure path at the dispatch boundary produces a typed `tool_result` --
`is_error: true`, the content wrapped in a `<tool_use_error>...</tool_use_error>`
envelope, a plain-text summary, a denial kind when the failure *is* a denial,
and a structured remedy that says what to do next. Recovery is by
classification plus remedy: the model retries what the remedy tells it to
retry; the harness never silently re-executes a failed call.

This document records what was read in the Claude Code bundle, what Northstar
does, and where Northstar extends rather than transcribes. Nothing here is
guessed; the open questions are at the end.

## Where the code lives

| Module | Role |
| --- | --- |
| `components/northstar-agent-runtime/tool_failure.py` | The vocabulary and the failure record: denial kinds, remedy kinds, `ToolFailure`, `ToolResultRemedy`, and the constructors `from_tool_error`, `from_provider_fault`, `from_denial`. |
| `components/northstar-agent-runtime/tool_use.py` | The dispatch boundary: `ToolUse.invoke_result()` and `ToolUse.invoke_denial()` return typed results; `_check_arguments` tolerates extra keys; the failure audit row carries `error_code` and `denial_kind`. |
| `components/northstar-agent-runtime/provider_retry.py` | `fault_to_failure()` maps a `ProviderFault` onto the same typed vocabulary. The retry budget is untouched. |
| `components/northstar-agent-runtime/retry_contract.py` | Read-only. Its `FailureClass` / `FailurePhase` are the egress-side contract; this slice does not change them. |

`tool_failure.py` imports nothing from the rest of the runtime. It takes
provider faults by duck typing so that `tool_use` and `provider_retry` can both
import it without a cycle.

## The shape of a failure

`ToolFailure.to_tool_result()` produces:

| Field | Meaning |
| --- | --- |
| `is_error` | Always `True` on a failure. |
| `content` | `<tool_use_error>{summary}</tool_use_error>` -- the enveloped content. |
| `toolUseResult` | The plain-text summary. |
| `toolDenialKind` | One of the four denial kinds, or explicitly `None`. |
| `toolDenialEndsTurn` | `True` when the denial also ends the turn. |
| `toolResultRemedy` | The structured remedy, or `None`. |
| `errorCode` | The machine-readable code (e.g. `InputValidationError`). |
| `retryable` | `True` only for a transient provider fault. |
| `retryAfterMs` | The suggested wait, when the provider gave one. |
| `toolName` / `toolUseId` | Which call failed. |

`toolDenialKind` is present and explicitly `None` for a failure that is not a
denial: "we could not tell" must not read as "denied".

## The denial kinds (CC verbatim)

Transcribed from the Claude Code bundle (v2.1.322,
`@anthropic-ai/claude-code-linux-x64`), the `toolDenialKind` values are:

```
interrupted
user-rejected
permission-rule
cancelled
```

A denial may also carry `toolDenialEndsTurn: true`. "Denied" and "denied, stop
the turn" are two different states, and the boundary carries that difference
through unchanged: `ToolUse.invoke_denial(..., ends_turn=True)` produces a
result whose `toolDenialEndsTurn` is `True`, and a plain `permission-rule`
denial produces `False`.

A denial kind appears **only** when the failure is itself a denial. A
validation failure and a provider fault carry an `error_code` and (where one
applies) a remedy, with `denial_kind` explicitly `None`. No kind is ever
guessed.

## The remedy kinds

**CC verbatim** (transcribed from the bundle's `toolResultRemedy` kinds):

| Kind | Extra fields |
| --- | --- |
| `memory_paused` | -- |
| `staged_for_review` | `path` |
| `sandbox_violation` | -- |
| `auth_expired` | `provider` |
| `auth_overridden` | `provider`, `managed` |

**Northstar extension** (not Claude Code's words; kept in a separate tuple in
the code so a reader can see which is which):

| Kind | Why Northstar needs it |
| --- | --- |
| `invalid_input` | The call did not validate. Claude Code emits `toolUseResult: "InputValidationError: <message>"` but has no remedy word for it. |
| `unknown_tool` | The model named a tool that does not exist; the only way forward is to pick another one. |
| `compaction_required` | The request was too big for the provider; the answer is to shrink it, not to repeat it. |

`ToolResultRemedy.as_dict()` emits only the fields the kind actually carries,
so a `memory_paused` remedy never claims a `path` or a `provider`.

### A retryable fault is not a remedy kind

A throttled or 5xx provider fault is expressed on the failure record itself:
`retryable: true` plus `retryAfterMs` (the provider's wait, when it gave one).
It carries **no** remedy kind. A wait is not one of Claude Code's five remedy
words, and inventing a sixth ("try again later") would dress a Northstar
choice up as a transcribed one. The retry budget itself is unchanged by this
slice: `provider_retry.execute` still retries what its policy says, and the
harness still never silently re-executes a failed *tool* call -- the model
retries, following the remedy.

## The fault -> remedy mapping

| Fault / failure | `error_code` | `denial_kind` | Remedy | Retryable |
| --- | --- | --- | --- | -- |
| `UnknownToolError` | `unknown_tool` | `None` | `unknown_tool` (Northstar) | no |
| `BadArgumentsError` (missing / wrong type) | `InputValidationError` | `None` | `invalid_input` (Northstar) | no |
| `BadToolError`, `BadSchemaError`, `DuplicateToolError`, `SeqOrderError`, `AuditKindError` | the class name | `None` | none | no |
| provider fault `auth` | `auth` | `None` | `auth_expired` (CC, with `provider`) | no |
| provider fault `context_overflow` | `context_overflow` | `None` | `compaction_required` (Northstar) | no |
| provider fault `stream_interrupted` | `stream_interrupted` | `interrupted` (CC) | none | no |
| provider fault `rate_limited` / `overloaded` / `server_error` / `network` / `timeout` | the fault class | `None` | **none** | yes, with `retryAfterMs` |
| provider fault `client_error` / `unknown` | the fault class | `None` | none | no |
| a host refusal | `denied` | one of the four (CC) | optional | no |

The `error_code` for a validation failure is `InputValidationError` and the
`toolUseResult` reads `InputValidationError: <message>` -- the shape Claude
Code uses. The `error_code` for the other tool-use errors is the exception
class name, which is what the audit row already carried.

## The validation polarity

Before this slice, `tool_use._check_arguments` refused an argument key the
schema did not declare (`unknown argument: 'bogus'`). It now **tolerates**
extra keys and drops them from the booked record; a missing required key or a
wrong-typed value still fails.

That is the opposite polarity from the *schema* side, which stays fail-closed:
an unknown key in a schema is still a `BadSchemaError`. The reason is Claude
Code's zod `safeParse`: it filters `unrecognized_keys` issues out of the
failure list and fails only on the rest, so an extra key never fails a call.
A model that sends a superset of the fields it was told about must not have
its call turned into a failure.

Two consequences worth stating plainly:

* The booked `InvocationRecord.arguments` no longer contains the extra keys.
  The digest pin is over the *validated* arguments, so two calls that differ
  only in an ignored extra key produce the same pin. That is intended: the
  extra key had no effect on the call.
* The tool-use side is not the bash parser. `bash_parser` is fail-closed on
  unknown AST nodes, and it stays that way: an *input* is interpreted, a *tool
  call* is validated against a declared schema.

## What changed at the boundary

`ToolUse.invoke()` keeps its exception contract exactly as it was: a failed
invocation raises its `ToolUseError` subclass and still burns its seq. The
conversion to a typed result lives in a new method, so no existing caller's
contract changes silently:

* `ToolUse.invoke_result(tool_id, arguments, seq, *, tool_use_id="")` returns
  a `ToolResult`. On success it carries the booked `InvocationRecord`; on
  failure it carries a `ToolFailure` and never raises a `ToolUseError`.
* `ToolUse.invoke_denial(tool_id, denial_kind, seq, *, ends_turn=False, ...)`
  books a host refusal as a typed result with the denial kind and the
  ends-turn flag.
* `ToolResult.to_tool_result()` renders the result block: the plain booked
  result on success, the typed failure's shape on failure.

A failure that is *not* a tool-use error (a caller bug) still raises:
normalizing it would hide a bug behind a result block.

The seq accounting is unchanged: a failed call burns its seq, and the typed
result carries the same seq it was booked under.

## The audit boundary

A failed invocation now books an audit row of kind `failed` (a registration
failure still books `rejected`). The row carries:

```
{"error": "<class name>", "error_code": "...", "denial_kind": "..." or null, "tool_id": "..."}
```

The raw arguments still never cross this boundary -- only ids, codes and
digest pins, exactly as before. `tool_use_audit_event` still refuses the
banned detail keys.

The reason the row changed: a sealed ledger has to be able to tell a stranger
whether a missing result was a *refusal* (a policy decision, auditable) or a
*crash* (an infrastructure event). `denial_kind` is what makes the difference
legible; `error_code` says which failure it was.

## Telemetry

`ToolFailure.to_telemetry_event()` produces the failure event in the shape of
Claude Code's `tengu_tool_use_error` -- `messageId`, `toolUseID`, `toolName`,
`errorCode`, `isMcp`, plus the denial kind and the ends-turn flag. No new
telemetry sink is created: this is data an existing sink may carry.

## Relation to the rest of the runtime

* **The sealed ledger** (`forward_seal_ledger`, `sealed_audit_sink`) consumes
  the `audit.ndjson/1` rows unchanged; the new `failed` kind and the two new
  detail keys ride the same row shape.
* **The permission gate** (`permissions.py`) produces a `PermissionDecision`
  with a `deny_code`; the refusal becomes a typed failure through
  `invoke_denial`, which is where the denial kind and the ends-turn flag are
  attached. `permissions.py` itself is not changed by this slice.
* **The alert triggers** can now tell a `permission-rule` denial (a possible
  policy event) from an `interrupted` denial (noise), because the kind is on
  the record rather than in a message string.
* **The retry budget** (`provider_retry`) is unchanged: the same classes, the
  same schedule, the same stops. Only the *shape* of the failure that comes
  out of it changed.
* **`retry_contract.py`** is read-only here. Its `FailureClass` (retryable /
  non-retryable / unknown) is about *replaying an outbound call*, which is a
  different question from *what the model is told*. The two vocabularies are
  not merged: `retry_contract` decides whether a call may be repeated;
  `tool_failure` decides what the model is told about it.

## Mapping to Claude Code

| Claude Code (v2.1.322 bundle) | Northstar | Verbatim? |
| --- | --- | --- |
| `toolDenialKind` values `interrupted`, `user-rejected`, `permission-rule`, `cancelled` | `DENIAL_KINDS` | CC verbatim |
| `toolDenialEndsTurn` | `ToolFailure.ends_turn` | CC verbatim (the name) |
| `toolResultRemedy` kinds `memory_paused`, `staged_for_review`, `sandbox_violation`, `auth_expired`, `auth_overridden` | `CC_REMEDY_KINDS` | CC verbatim |
| `toolUseResult: "InputValidationError: <message>"` | `INPUT_VALIDATION_ERROR` + the summary prefix | CC verbatim |
| `<tool_use_error>...</tool_use_error>` envelope | `ENVELOPE_TAG` | CC verbatim |
| zod `safeParse` filtering `unrecognized_keys` | `_check_arguments` tolerating extra keys | the behaviour, not the library |
| `tengu_tool_use_error` event (messageID, toolUseID, toolName, errorCode, isMcp) | `to_telemetry_event()` | CC shape |
| remedies `invalid_input`, `unknown_tool`, `compaction_required` | `NORTHSTAR_REMEDY_KINDS` | **Northstar extension** |
| `errorCode`, `retryable`, `retryAfterMs` on the record | `ToolFailure` fields | **Northstar extension** |
| the `failed` audit kind and its `error_code` / `denial_kind` keys | `tool_use` audit row | **Northstar extension** |

The bundle contains no harness-level loop that re-runs a failed tool call;
recovery there is classification plus a remedy given to the model. Northstar
matches that posture: the model retries what the remedy says, and the harness
never silently re-executes.

## Open questions

These could not be settled from the bundle or from the code, and are recorded
rather than invented:

1. **Which denial kind a given permission refusal should carry.**
   `permission-rule` is the obvious fit for a policy refusal, but a host
   callback that the *user* declined and one that a rule refused are both
   `permission-rule` today. `user-rejected` exists for the user case; the
   mapping from `PermissionDecision` to a kind is left to the caller of
   `invoke_denial`, because only the caller knows whether a human or a rule
   said no.
2. **Whether `interrupted` should end the turn.** This slice ends the turn
   for a `stream_interrupted` provider fault and leaves it to the caller for
   an `interrupted` denial. The bundle shows the flag but not its default.
3. **How a `staged_for_review` remedy gets its `path`.** Nothing in the
   runtime stages a tool call for review today; the field is carried, not
   produced.
4. **Whether the `memory_paused` remedy should ever be emitted here.**
   Memory pausing is a Northstar concept; the word is transcribed, but this
   slice emits no `memory_paused` remedy.
