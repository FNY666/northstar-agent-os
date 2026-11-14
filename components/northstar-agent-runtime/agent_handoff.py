"""Agent handoff: ``transfer_to_<name>`` tool with a fixed destination.

Research motivation: Northstar had no way for one agent to hand a
conversation to another specialist. ``multi_agent.py`` only *mentions*
OpenAI Swarm handoffs in a comment (a documentation reference, not an
implementation); ``a2a_gates.py`` is a *gate* that runs before a handoff
is accepted (sabotage / turf-war detection); ``hinted_handoff.py`` is a
Dynamo-style *write buffer* for a temporarily unavailable owner -- a
different concept that happens to share the word "handoff". Before this
module the repository contained no ``transfer_to`` at all.

Source of the mechanism (OpenAI Agents SDK, official docs
https://openai.github.io/openai-agents-python/handoffs/ and API reference
https://openai.github.io/openai-agents-python/ref/handoffs/; the
``handoff()`` source was read in full on 2026-11-14). Verbatim rules
from that source are marked ``[OpenAI]`` below; everything else is a
Northstar extension and marked ``[Northstar]``.

- [OpenAI] A handoff is presented to the model as a *tool*. The default
  tool name is ``transfer_to_<agent_name>``
  (``Handoff.default_tool_name(agent)``); the description can be
  overridden (``tool_name_override`` / ``tool_description_override``).
- [OpenAI] ``handoff()`` captures exactly one agent and always returns
  that agent. ``on_handoff`` is a side-effect / bookkeeping callback and
  must never be used to pick a destination dynamically.
- [OpenAI] Construction-time validation (reported immediately, not at
  call time): giving ``input_type`` requires ``on_handoff``; with an
  ``input_type`` the callback must take exactly two arguments
  (``context, input``); without one it must take exactly one
  (``context``).
- [OpenAI] At call time the model's JSON is validated strictly against
  the input type (``partial=False, strict=True, contains_tool_data=True``).
  When the input type requires input but ``input_json`` is ``None``, the
  error is attached to the current span first and then
  ``ModelBehaviorError`` is raised. ``input_json_schema`` is always
  forced into strict mode.
- [OpenAI] ``is_enabled`` may be a bool or a callable
  ``(ctx, agent) -> bool``; a disabled handoff is hidden from the model
  at runtime. The internal ``_is_enabled`` asserts the target is an
  ``Agent`` ("Can't handoff to a non-Agent").
- [OpenAI] ``failure_error_function`` formats a failed invocation;
  ``None`` keeps the exception propagating. After a *handled* failure the
  calling agent stays active. Errors raised by the callback are handled
  and side effects that already happened are not rolled back, but
  cancellation, formatter errors, transfer-hook errors and input-filter
  errors keep propagating.
- [OpenAI] The invocation entry point is wrapped in a redaction layer
  (``on_invoke_handoff=partial(_invoke_handoff_with_redaction,
  _invoke_handoff_impl)``).
- [OpenAI] Identity and references: the default tool identity is only
  recorded when there is no ``tool_name_override``
  (``_default_tool_identity = (agent.name, tool_name)``), and the
  handoff holds the agent through ``weakref.ref(agent)`` -- it never
  owns the agent.
- [OpenAI] ``input_filter`` is opt-in: without it the full context
  (including tool-call history) is passed on unchanged.
- [OpenAI] ``nest_handoff_history`` is opt-in beta and off by default.
- [OpenAI] Handoffs stay inside a single run; input guardrails apply to
  the first agent of the chain and output guardrails to the agent that
  produced the final output.

Northstar extensions (NOT OpenAI content):

- [Northstar] No LLM and no Runner. This module is a pure data
  structure plus validation: a *registry* mapping agent names to
  handoff records. A "handoff" books a decision plus a summary of the
  filtered payload; it does not execute the next agent.
- [Northstar] ``input_filter`` is a pure function over the canonical
  record (a mapping), not a callback over an SDK context object.
- [Northstar] The registry keeps agent *names* only (strings) and never
  holds a reference to an agent object -- it owns nothing.
- [Northstar] Guardrail *placement* is recorded (first agent of the run
  for input guardrails, final agent for output guardrails) and handed to
  the caller. This module does not execute guardrails.
  ``tripwire_guardrails.py`` owns the three-valued outcome
  (ALLOW / REJECT_CONTENT / HALT); it is read-only here and unchanged.

Public API:

- ``HandoffRegistry()``
  - ``register_agent(name)`` -- declare an agent name (fail-closed on a
    non-string, so the registry can never take a strong reference to an
    agent object).
  - ``register(agent_name, target_name, tool_name=None,
    tool_description=None, input_schema=None, input_filter=None,
    on_handoff=None, is_enabled=True)`` -> frozen ``HandoffRecord``.
    Construction-time validation happens here, never later.
  - ``invoke(record, input_json, ctx=None)`` -> destination agent name
    (the fixed target captured at registration).
  - ``invoke_handled(record, input_json, ctx=None,
    failure_error_function=None)`` -> ``HandoffDecision``; applies the
    OpenAI failure semantics (a callback error may be formatted and
    handled, the caller then stays active).
  - ``visible_handoffs(agent_name, ctx=None)`` -- the handoffs an agent
    may currently offer (disabled ones are hidden).
  - ``begin_run(run_id, agent_name)`` / ``set_final_agent(run_id,
    agent_name)`` / ``guardrail_scope(run_id)`` -> ``GuardrailScope``
    (input guardrails -> first agent, output guardrails -> final agent).
  - Views: ``record(tool_name)``, ``records()``, ``agents()``,
    ``decisions()``, ``errors()`` -- pure reads.

Fail-closed everywhere: invalid JSON, a schema violation, an unknown or
disabled destination, and a callback whose arity does not match the
OpenAI rule all raise. Nothing degrades silently and no destination is
ever substituted automatically.

Version pin: ``agent-handoff.v1`` / schema pin
``northstar.agent-handoff.v1``.
"""

from __future__ import annotations

import inspect
import json
import threading
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple, Union

#: Version pin for this module's record shape.
AGENT_HANDOFF_VERSION = "agent-handoff.v1"

#: Schema pin carried by records and decisions.
AGENT_HANDOFF_SCHEMA = "northstar.agent-handoff.v1"

#: Default tool-name prefix used for a handoff tool.
DEFAULT_TOOL_PREFIX = "transfer_to_"

#: Fixed vocabulary for decision statuses.
STATUS_HANDOFF = "handoff"
STATUS_FAILED = "failed"
STATUS_REJECTED = "rejected"
_STATUSES = frozenset({STATUS_HANDOFF, STATUS_FAILED, STATUS_REJECTED})

#: Fixed vocabulary for booked error kinds.
KIND_CONFIG = "config"
KIND_MODEL_BEHAVIOR = "model_behavior"
KIND_TARGET = "target"
KIND_CALLBACK = "callback"
KIND_FILTER = "filter"
_KINDS = frozenset(
    {KIND_CONFIG, KIND_MODEL_BEHAVIOR, KIND_TARGET, KIND_CALLBACK, KIND_FILTER}
)


# ---------------------------------------------------------------------------
# Error taxonomy (fail-closed)
# ---------------------------------------------------------------------------


class HandoffError(Exception):
    """Base class for every agent-handoff error."""


class HandoffConfigError(HandoffError):
    """Construction-time misuse -- the OpenAI ``UserError`` analogue.

    Raised by ``register()`` for a bad arity, a missing callback, an
    unknown destination, or a malformed schema. Never raised at call
    time for a reason the caller could have caught earlier.
    """


class HandoffValidationError(HandoffError):
    """Call-time input problem -- the OpenAI ``ModelBehaviorError`` analogue.

    Raised when the model's JSON is not valid JSON, violates the strict
    schema, or is missing entirely while the schema requires input.
    """


class HandoffTargetError(HandoffError):
    """The destination is unknown, unregistered, or the handoff is disabled."""


class HandoffCallbackError(HandoffError):
    """The ``on_handoff`` callback raised.

    The error is *not* rolled back into the caller's side effects and
    the calling agent stays active; the exception carries
    ``caller_stays_active=True`` and the booked ``HandoffDecision``.
    """


class HandoffFilterError(HandoffError):
    """The ``input_filter`` raised.

    Input-filter errors always propagate; they are never swallowed and
    never degrade into "pass the context through unfiltered".
    """


class HandoffCancelled(HandoffError):
    """A cancellation happened during the handoff.

    Cancellation keeps propagating even when a failure formatter is
    configured.
    """


# ---------------------------------------------------------------------------
# Small validation helpers
# ---------------------------------------------------------------------------


def _check_agent_name(value: Any, what: str) -> str:
    """Validate an agent name: a non-empty string."""
    if not isinstance(value, str):
        raise HandoffConfigError(
            f"{what} must be a str (the registry stores names only, never "
            f"agent objects), got {type(value).__name__}"
        )
    if not value.strip():
        raise HandoffConfigError(f"{what} must be non-empty")
    if len(value) > 256:
        raise HandoffConfigError(f"{what} exceeds 256 chars")
    return value


def _check_tool_name(value: Any) -> str:
    if not isinstance(value, str):
        raise HandoffConfigError(
            f"tool_name must be a str, got {type(value).__name__}"
        )
    if not value.strip():
        raise HandoffConfigError("tool_name must be non-empty")
    if len(value) > 256:
        raise HandoffConfigError("tool_name exceeds 256 chars")
    return value


def _check_description(value: Any) -> str:
    if not isinstance(value, str):
        raise HandoffConfigError(
            f"tool_description must be a str, got {type(value).__name__}"
        )
    if len(value) > 4096:
        raise HandoffConfigError("tool_description exceeds 4096 chars")
    return value


def _canonical_json(value: Any) -> str:
    """Canonical JSON text for a mapping (stable key order)."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, default=str)


def _is_cancelled(exc: BaseException) -> bool:
    """True for cancellation errors (they always propagate)."""
    if isinstance(exc, HandoffCancelled):
        return True
    try:  # asyncio.CancelledError is a BaseException in 3.8+
        import asyncio

        return isinstance(exc, asyncio.CancelledError)
    except Exception:  # pragma: no cover - asyncio is stdlib, defensive only
        return False


# ---------------------------------------------------------------------------
# Strict schema validation (the OpenAI strict-mode rules, reimplemented)
# ---------------------------------------------------------------------------

#: JSON-schema type names this module understands.
_JSON_TYPES = frozenset(
    {"object", "array", "string", "integer", "number", "boolean", "null"}
)


def _check_schema(schema: Any) -> Mapping[str, Any]:
    """Validate the shape of an ``input_schema`` at construction time.

    Only the subset this module can enforce strictly is accepted:
    a JSON-schema ``object`` with ``properties`` / ``required`` and
    per-property ``type`` annotations.
    """
    if not isinstance(schema, Mapping):
        raise HandoffConfigError(
            f"input_schema must be a mapping, got {type(schema).__name__}"
        )
    declared = schema.get("type", "object")
    if declared != "object":
        raise HandoffConfigError(
            f"input_schema type must be 'object', got {declared!r}"
        )
    props = schema.get("properties", {})
    if not isinstance(props, Mapping):
        raise HandoffConfigError("input_schema properties must be a mapping")
    for key, spec in props.items():
        if not isinstance(key, str) or not key.strip():
            raise HandoffConfigError("input_schema property names must be str")
        if not isinstance(spec, Mapping):
            raise HandoffConfigError(
                f"input_schema property {key!r} must be a mapping"
            )
        ptype = spec.get("type")
        if ptype is not None and ptype not in _JSON_TYPES:
            raise HandoffConfigError(
                f"input_schema property {key!r} has unsupported type "
                f"{ptype!r}"
            )
    required = schema.get("required", [])
    if not isinstance(required, (list, tuple)):
        raise HandoffConfigError("input_schema required must be a sequence")
    for key in required:
        if not isinstance(key, str):
            raise HandoffConfigError(
                "input_schema required entries must be strings"
            )
        if key not in props:
            raise HandoffConfigError(
                f"input_schema requires undeclared property {key!r}"
            )
    return schema


def _type_ok(value: Any, declared: Optional[str]) -> bool:
    """Strict type check for a JSON value.

    ``bool`` is not an ``integer`` (the OpenAI strict-mode rule) and
    ``integer`` is not a ``number`` check either -- an ``integer``
    satisfies ``number`` but not the other way round.
    """
    if declared is None:
        return True
    if declared == "object":
        return isinstance(value, Mapping)
    if declared == "array":
        return isinstance(value, (list, tuple))
    if declared == "string":
        return isinstance(value, str)
    if declared == "boolean":
        return isinstance(value, bool)
    if declared == "null":
        return value is None
    if declared == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if declared == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    return False


def _validate_strict(payload: Any, schema: Mapping[str, Any]) -> None:
    """Validate ``payload`` against ``schema`` in strict mode.

    Strict means: unknown properties are refused, missing required
    properties are refused, and a property whose type does not match is
    refused. Raises ``HandoffValidationError`` on the first violation.
    """
    props: Mapping[str, Any] = schema.get("properties", {}) or {}
    required = list(schema.get("required", []) or [])

    if not isinstance(payload, Mapping):
        raise HandoffValidationError(
            f"input must be a JSON object, got {type(payload).__name__}"
        )
    unknown = sorted(k for k in payload if k not in props)
    if unknown:
        raise HandoffValidationError(
            f"unknown properties refused in strict mode: {unknown}"
        )
    missing = [k for k in required if k not in payload]
    if missing:
        raise HandoffValidationError(
            f"missing required properties: {missing}"
        )
    for key, spec in props.items():
        if key not in payload:
            continue
        declared = spec.get("type") if isinstance(spec, Mapping) else None
        if not _type_ok(payload[key], declared):
            raise HandoffValidationError(
                f"property {key!r} must be {declared}, got "
                f"{type(payload[key]).__name__}"
            )


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HandoffRecord:
    """One registered handoff tool.

    ``tool_name`` is the name the model sees. ``default_tool_identity``
    is ``(target_name, tool_name)`` when the tool name was *not*
    overridden and ``None`` when it was -- the OpenAI rule that the
    default identity is only recorded without a ``tool_name_override``.

    ``input_filter is None`` marks the handoff as **unfiltered**: the
    full context is passed on unchanged (the OpenAI opt-in default).
    """

    agent_name: str
    target_name: str
    tool_name: str
    tool_description: str
    input_schema: Optional[Mapping[str, Any]]
    input_filter: Optional[Callable[[Mapping[str, Any]], Mapping[str, Any]]]
    on_handoff: Optional[Callable[..., Any]]
    is_enabled: Union[bool, Callable[[Any, str], bool]]  # type: ignore[name-defined]
    default_tool_identity: Optional[Tuple[str, str]]
    schema_id: str

    @property
    def filtered(self) -> bool:
        """True when an input filter was supplied."""
        return self.input_filter is not None

    @property
    def enabled_by_default(self) -> bool:
        """True when ``is_enabled`` is a plain bool (not a predicate)."""
        return isinstance(self.is_enabled, bool)

    def identity(self) -> Tuple[str, str]:
        """The identity used for bookkeeping: ``(agent, tool)``."""
        return (self.agent_name, self.tool_name)


@dataclass(frozen=True)
class HandoffDecision:
    """The booked outcome of one handoff attempt.

    ``status`` is one of ``handoff`` / ``failed`` / ``rejected``.
    ``caller_stays_active`` records the OpenAI rule that after a
    handled failure the calling agent stays active. ``payload`` is the
    filtered payload that was handed on (the unfiltered context when no
    filter was configured).
    """

    run_id: str
    agent_name: str
    target_name: str
    tool_name: str
    status: str
    filtered: bool
    caller_stays_active: bool
    payload: Mapping[str, Any]
    error: Optional[str] = None
    error_kind: Optional[str] = None

    @property
    def handed_off(self) -> bool:
        return self.status == STATUS_HANDOFF


@dataclass(frozen=True)
class HandoffErrorRecord:
    """A booked error. Written *before* the matching exception is raised."""

    run_id: str
    agent_name: str
    target_name: str
    kind: str
    error: str
    caller_stays_active: bool


@dataclass(frozen=True)
class GuardrailScope:
    """Where guardrails apply within one run.

    ``input_agent`` is the first agent of the run (input guardrails
    apply to it); ``output_agent`` is the agent that produced the final
    output (output guardrails apply to it). This module only reports
    the placement -- it never executes a guardrail.
    """

    run_id: str
    input_agent: Optional[str]
    output_agent: Optional[str]


# ---------------------------------------------------------------------------
# The registry
# ---------------------------------------------------------------------------


class HandoffRegistry:
    """A registry of handoff tools, keyed by agent name.

    The registry stores agent *names* only. It never holds an agent
    object, so it owns nothing and cannot keep an agent alive (the
    OpenAI weak-reference rule, expressed without a weakref because no
    object is ever stored).

    Thread-safe: an ``RLock`` guards every mutation. All validation is
    fail-closed.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._agents: Dict[str, str] = {}
        self._records: Dict[str, HandoffRecord] = {}
        self._by_agent: Dict[str, List[str]] = {}
        self._decisions: List[HandoffDecision] = []
        self._errors: List[HandoffErrorRecord] = []
        self._runs: Dict[str, Dict[str, Optional[str]]] = {}

    # -- internal ------------------------------------------------------

    def _book_error(
        self,
        run_id: str,
        agent_name: str,
        target_name: str,
        kind: str,
        exc: BaseException,
        caller_stays_active: bool = True,
    ) -> HandoffErrorRecord:
        """Book an error record. Called *before* the exception is raised."""
        record = HandoffErrorRecord(
            run_id=run_id,
            agent_name=agent_name,
            target_name=target_name,
            kind=kind,
            error=f"{type(exc).__name__}: {exc}",
            caller_stays_active=caller_stays_active,
        )
        self._errors.append(record)
        return record

    def _book_decision(self, decision: HandoffDecision) -> HandoffDecision:
        self._decisions.append(decision)
        return decision

    @staticmethod
    def _callback_arity(callback: Callable[..., Any]) -> int:
        """Count the positional parameters a callback accepts.

        ``*args`` counts as unlimited and is accepted as a match for
        both arities (the OpenAI rule counts *required* parameters, and
        a variadic callback can satisfy either signature).
        """
        try:
            signature = inspect.signature(callback)
        except (TypeError, ValueError) as exc:
            raise HandoffConfigError(
                f"cannot inspect callback signature: {exc}"
            ) from exc
        count = 0
        for param in signature.parameters.values():
            if param.kind is inspect.Parameter.VAR_POSITIONAL:
                return -1  # variadic: matches any arity
            if param.kind in (
                inspect.Parameter.POSITIONAL_ONLY,
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
            ):
                count += 1
        return count

    # -- registration --------------------------------------------------

    def register_agent(self, name: str) -> str:
        """Declare an agent name. Fail-closed on anything but a string.

        Declaring the *destination* agent is what makes a handoff to it
        legal -- a handoff whose target was never declared is refused at
        registration time.
        """
        with self._lock:
            name = _check_agent_name(name, "agent name")
            self._agents[name] = name
            return name

    def register(
        self,
        agent_name: str,
        target_name: str,
        tool_name: Optional[str] = None,
        tool_description: Optional[str] = None,
        input_schema: Optional[Mapping[str, Any]] = None,
        input_filter: Optional[Callable[[Mapping[str, Any]], Mapping[str, Any]]] = None,
        on_handoff: Optional[Callable[..., Any]] = None,
        is_enabled: Union[bool, Callable[[Any, str], bool]] = True,
        run_id: str = "default",
    ) -> HandoffRecord:
        """Register one handoff tool and return its frozen record.

        Construction-time rules (all of them OpenAI's, all of them
        enforced *here* rather than at call time):

        - giving ``input_schema`` requires ``on_handoff``;
        - with ``input_schema`` the callback must take exactly two
          arguments (``context, input``);
        - without ``input_schema`` it must take exactly one
          (``context``);
        - the destination must already be a registered agent name.

        The default tool name is ``transfer_to_<target_name>``. An
        explicit ``tool_name`` overrides it, and then -- and only then
        -- no default tool identity is recorded.
        """
        with self._lock:
            agent_name = _check_agent_name(agent_name, "agent_name")
            target_name = _check_agent_name(target_name, "target_name")
            if not isinstance(run_id, str) or not run_id.strip():
                raise HandoffConfigError("run_id must be a non-empty str")

            # The destination must be a known agent (fail-closed).
            if target_name not in self._agents:
                raise HandoffConfigError(
                    f"target agent {target_name!r} is not registered; "
                    f"register_agent() it first"
                )

            # input_schema requires on_handoff (OpenAI).
            if input_schema is not None and on_handoff is None:
                raise HandoffConfigError(
                    "input_schema requires on_handoff (OpenAI rule: "
                    "giving an input type requires a handoff callback)"
                )

            # Arity check (OpenAI): 2 params with a schema, 1 without.
            if on_handoff is not None:
                if not callable(on_handoff):
                    raise HandoffConfigError("on_handoff must be callable")
                arity = self._callback_arity(on_handoff)
                expected = 2 if input_schema is not None else 1
                if arity != -1 and arity != expected:
                    raise HandoffConfigError(
                        f"on_handoff must take exactly {expected} "
                        f"argument(s) "
                        f"({'context, input' if expected == 2 else 'context'}), "
                        f"got {arity}"
                    )

            if input_schema is not None:
                _check_schema(input_schema)

            if input_filter is not None and not callable(input_filter):
                raise HandoffConfigError("input_filter must be callable")

            if not isinstance(is_enabled, bool) and not callable(is_enabled):
                raise HandoffConfigError(
                    "is_enabled must be a bool or a callable(ctx, target)"
                )

            overridden = tool_name is not None
            if overridden:
                resolved_tool = _check_tool_name(tool_name)
            else:
                resolved_tool = _check_tool_name(
                    f"{DEFAULT_TOOL_PREFIX}{target_name}"
                )
            description = _check_description(
                tool_description
                if tool_description is not None
                else f"Transfer the conversation to {target_name}."
            )

            if resolved_tool in self._records:
                raise HandoffConfigError(
                    f"tool name {resolved_tool!r} is already registered"
                )

            record = HandoffRecord(
                agent_name=agent_name,
                target_name=target_name,
                tool_name=resolved_tool,
                tool_description=description,
                input_schema=dict(input_schema) if input_schema is not None else None,
                input_filter=input_filter,
                on_handoff=on_handoff,
                is_enabled=is_enabled,
                default_tool_identity=(
                    None if overridden else (target_name, resolved_tool)
                ),
                schema_id=AGENT_HANDOFF_SCHEMA,
            )
            self._records[resolved_tool] = record
            self._by_agent.setdefault(agent_name, []).append(resolved_tool)
            self._agents.setdefault(agent_name, agent_name)
            return record

    # -- enablement ----------------------------------------------------

    def _is_enabled(self, record: HandoffRecord, ctx: Any = None) -> bool:
        """Evaluate ``is_enabled`` for one record.

        A disabled handoff is hidden from the caller (``visible_handoffs``)
        and refuses to be invoked. The target must be a registered agent
        -- asserted fail-closed rather than trusted.
        """
        if record.target_name not in self._agents:
            raise HandoffTargetError(
                f"target agent {record.target_name!r} is not registered"
            )
        enabled = record.is_enabled
        if isinstance(enabled, bool):
            return enabled
        result = enabled(ctx, record.target_name)
        if not isinstance(result, bool):
            raise HandoffConfigError(
                "is_enabled predicate must return a bool, got "
                f"{type(result).__name__}"
            )
        return result

    def visible_handoffs(
        self, agent_name: str, ctx: Any = None
    ) -> Tuple[HandoffRecord, ...]:
        """The handoffs ``agent_name`` may offer right now.

        A handoff whose ``is_enabled`` evaluates false is *not* in this
        tuple: it is hidden from the caller, exactly as the OpenAI
        runtime hides a disabled handoff from the model.
        """
        with self._lock:
            agent_name = _check_agent_name(agent_name, "agent_name")
            visible: List[HandoffRecord] = []
            for tool in self._by_agent.get(agent_name, []):
                record = self._records[tool]
                if self._is_enabled(record, ctx):
                    visible.append(record)
            return tuple(visible)

    # -- invocation ----------------------------------------------------

    def _parse_input(
        self,
        record: HandoffRecord,
        input_json: Any,
        run_id: str,
    ) -> Optional[Mapping[str, Any]]:
        """Validate the model's input against the record's schema.

        Returns the parsed mapping (or ``None`` when the record takes
        no input). Raises ``HandoffValidationError`` after booking an
        error record -- the booking happens *first*, matching the OpenAI
        rule that the error is attached to the span before the
        exception is raised.
        """
        schema = record.input_schema
        if schema is None:
            # No schema: the handoff takes no structured input.
            if input_json is not None:
                raise HandoffValidationError(
                    f"handoff {record.tool_name!r} takes no input, got "
                    f"{type(input_json).__name__}"
                )
            return None

        if input_json is None:
            exc = HandoffValidationError(
                f"handoff {record.tool_name!r} requires input but "
                f"input_json is None"
            )
            self._book_error(
                run_id, record.agent_name, record.target_name,
                KIND_MODEL_BEHAVIOR, exc,
            )
            raise exc

        if isinstance(input_json, str):
            try:
                payload = json.loads(input_json)
            except (ValueError, TypeError) as exc:
                err = HandoffValidationError(
                    f"input_json is not valid JSON: {exc}"
                )
                self._book_error(
                    run_id, record.agent_name, record.target_name,
                    KIND_MODEL_BEHAVIOR, err,
                )
                raise err from exc
        elif isinstance(input_json, Mapping):
            payload = dict(input_json)
        else:
            err = HandoffValidationError(
                f"input_json must be a JSON object or JSON text, got "
                f"{type(input_json).__name__}"
            )
            self._book_error(
                run_id, record.agent_name, record.target_name,
                KIND_MODEL_BEHAVIOR, err,
            )
            raise err

        try:
            _validate_strict(payload, schema)
        except HandoffValidationError as exc:
            self._book_error(
                run_id, record.agent_name, record.target_name,
                KIND_MODEL_BEHAVIOR, exc,
            )
            raise
        return payload

    def invoke(
        self,
        record: HandoffRecord,
        input_json: Any = None,
        ctx: Any = None,
        run_id: str = "default",
        context: Optional[Mapping[str, Any]] = None,
    ) -> str:
        """Invoke a handoff and return the destination agent name.

        The destination is *fixed*: it is the target captured at
        registration, and no callback can change it. ``on_handoff`` is a
        side-effect / bookkeeping callback only -- its return value is
        ignored.

        Failure semantics (OpenAI):

        - a validation failure raises and books an error record; the
          calling agent stays active;
        - a callback error propagates as ``HandoffCallbackError``; the
          side effects that already happened are *not* rolled back and
          the calling agent stays active;
        - cancellation and input-filter errors always propagate and are
          never swallowed.

        The full context handed to the next agent is
        ``context`` (defaulting to the validated input); with no
        ``input_filter`` it passes through unchanged, and the decision
        records ``filtered=False`` so the caller can see that.
        """
        with self._lock:
            if not isinstance(record, HandoffRecord):
                raise HandoffConfigError(
                    f"record must be a HandoffRecord, got "
                    f"{type(record).__name__}"
                )
            if record.tool_name not in self._records:
                raise HandoffConfigError(
                    f"record {record.tool_name!r} is not registered here"
                )
            if not self._is_enabled(record, ctx):
                raise HandoffTargetError(
                    f"handoff {record.tool_name!r} is disabled and cannot "
                    f"be invoked"
                )

            payload = self._parse_input(record, input_json, run_id)

            # The context handed on: the caller's context, or the
            # validated input when the caller supplied none.
            base_context: Mapping[str, Any] = (
                context if context is not None
                else (payload if payload is not None else {})
            )

            # input_filter is opt-in; without it the full context passes
            # through unchanged. A filter error propagates and is never
            # degraded into "unfiltered".
            if record.input_filter is not None:
                try:
                    filtered_ctx = record.input_filter(base_context)
                except HandoffCancelled:
                    raise
                except Exception as exc:
                    err = HandoffFilterError(
                        f"input_filter for {record.tool_name!r} raised: "
                        f"{type(exc).__name__}: {exc}"
                    )
                    self._book_error(
                        run_id, record.agent_name, record.target_name,
                        KIND_FILTER, err,
                    )
                    raise err from exc
                if not isinstance(filtered_ctx, Mapping):
                    err = HandoffFilterError(
                        f"input_filter for {record.tool_name!r} must return "
                        f"a mapping, got {type(filtered_ctx).__name__}"
                    )
                    self._book_error(
                        run_id, record.agent_name, record.target_name,
                        KIND_FILTER, err,
                    )
                    raise err
                handed_context: Mapping[str, Any] = filtered_ctx
                was_filtered = True
            else:
                handed_context = base_context
                was_filtered = False

            # on_handoff: side effects only. The destination is fixed.
            if record.on_handoff is not None:
                try:
                    if record.input_schema is not None:
                        record.on_handoff(ctx, payload)
                    else:
                        record.on_handoff(ctx)
                except HandoffCancelled:
                    raise
                except Exception as exc:
                    err = HandoffCallbackError(
                        f"on_handoff for {record.tool_name!r} raised: "
                        f"{type(exc).__name__}: {exc}"
                    )
                    self._book_error(
                        run_id, record.agent_name, record.target_name,
                        KIND_CALLBACK, err, caller_stays_active=True,
                    )
                    raise err from exc

            decision = HandoffDecision(
                run_id=run_id,
                agent_name=record.agent_name,
                target_name=record.target_name,
                tool_name=record.tool_name,
                status=STATUS_HANDOFF,
                filtered=was_filtered,
                caller_stays_active=False,
                payload=handed_context,
            )
            self._book_decision(decision)
            # The destination is the captured target, always.
            return record.target_name

    def invoke_handled(
        self,
        record: HandoffRecord,
        input_json: Any = None,
        ctx: Any = None,
        run_id: str = "default",
        context: Optional[Mapping[str, Any]] = None,
        failure_error_function: Optional[Callable[[BaseException], str]] = None,
    ) -> HandoffDecision:
        """Invoke a handoff, applying the OpenAI failure semantics.

        With ``failure_error_function=None`` the exception propagates
        (the OpenAI default: ``None`` keeps the exception). With a
        formatter, a *handled* failure books a ``failed`` decision whose
        ``caller_stays_active`` is True -- the calling agent stays
        active after a handled failure, and the side effects that
        already happened are not rolled back.

        Cancellation, formatter errors and input-filter errors keep
        propagating even when a formatter is configured.
        """
        with self._lock:
            try:
                target = self.invoke(
                    record, input_json, ctx, run_id, context
                )
            except HandoffCancelled:
                raise
            except HandoffFilterError:
                raise
            except (HandoffValidationError, HandoffTargetError,
                    HandoffCallbackError, HandoffConfigError) as exc:
                if failure_error_function is None:
                    raise
                try:
                    message = failure_error_function(exc)
                except Exception as fmt_exc:
                    # A formatter error keeps propagating.
                    raise fmt_exc from exc
                decision = HandoffDecision(
                    run_id=run_id,
                    agent_name=record.agent_name,
                    target_name=record.target_name,
                    tool_name=record.tool_name,
                    status=STATUS_FAILED,
                    filtered=record.input_filter is not None,
                    caller_stays_active=True,
                    payload={},
                    error=str(message),
                    error_kind=type(exc).__name__,
                )
                self._book_decision(decision)
                return decision
            else:
                return self._decisions[-1]

    # -- guardrail placement -------------------------------------------

    def begin_run(self, run_id: str, agent_name: str) -> str:
        """Record the first agent of a run.

        The first agent is the one input guardrails apply to (the
        OpenAI rule: input guardrails apply to the first agent of the
        chain). This module records the placement; it does not execute
        any guardrail.
        """
        with self._lock:
            if not isinstance(run_id, str) or not run_id.strip():
                raise HandoffConfigError("run_id must be a non-empty str")
            agent_name = _check_agent_name(agent_name, "agent_name")
            state = self._runs.setdefault(
                run_id, {"first": None, "final": None}
            )
            if state["first"] is None:
                state["first"] = agent_name
            return agent_name

    def set_final_agent(self, run_id: str, agent_name: str) -> str:
        """Record the agent that produced the final output of a run.

        Output guardrails apply to that agent (the OpenAI rule: output
        guardrails apply to the agent that produced the final output).
        """
        with self._lock:
            if not isinstance(run_id, str) or not run_id.strip():
                raise HandoffConfigError("run_id must be a non-empty str")
            agent_name = _check_agent_name(agent_name, "agent_name")
            state = self._runs.setdefault(
                run_id, {"first": None, "final": None}
            )
            state["final"] = agent_name
            return agent_name

    def guardrail_scope(self, run_id: str) -> GuardrailScope:
        """Return the guardrail placement for one run.

        ``input_agent`` is the run's first agent; ``output_agent`` is the
        run's final agent. The caller executes the guardrails; this
        module only says *where* they apply.
        """
        with self._lock:
            if not isinstance(run_id, str) or not run_id.strip():
                raise HandoffConfigError("run_id must be a non-empty str")
            state = self._runs.get(run_id) or {}
            return GuardrailScope(
                run_id=run_id,
                input_agent=state.get("first"),
                output_agent=state.get("final"),
            )

    # -- views (pure reads) --------------------------------------------

    def record(self, tool_name: str) -> Optional[HandoffRecord]:
        """The record for a tool name, or None."""
        with self._lock:
            return self._records.get(tool_name)

    def records(self) -> Tuple[HandoffRecord, ...]:
        """All registered records, sorted by tool name."""
        with self._lock:
            return tuple(
                self._records[name] for name in sorted(self._records)
            )

    def agents(self) -> Tuple[str, ...]:
        """All declared agent names, sorted."""
        with self._lock:
            return tuple(sorted(self._agents))

    def decisions(self) -> Tuple[HandoffDecision, ...]:
        """All booked decisions, oldest first."""
        with self._lock:
            return tuple(self._decisions)

    def errors(self) -> Tuple[HandoffErrorRecord, ...]:
        """All booked error records, oldest first."""
        with self._lock:
            return tuple(self._errors)


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------


def main() -> None:
    """Deterministic self-check of the three headline paths."""
    registry = HandoffRegistry()
    registry.register_agent("triage_agent")
    registry.register_agent("refund_agent")

    # (a) triage -> refund specialist, with a field-stripping filter.
    def strip_secrets(context: Mapping[str, Any]) -> Mapping[str, Any]:
        return {
            k: v for k, v in context.items()
            if k not in ("card_number", "ssn")
        }

    seen: List[Any] = []

    def on_handoff(context: Any, payload: Any) -> None:
        seen.append(payload)

    record = registry.register(
        "triage_agent",
        "refund_agent",
        input_schema={
            "type": "object",
            "properties": {
                "order_id": {"type": "string"},
                "amount": {"type": "number"},
            },
            "required": ["order_id"],
        },
        input_filter=strip_secrets,
        on_handoff=on_handoff,
    )
    assert record.tool_name == "transfer_to_refund_agent"
    assert record.default_tool_identity == (
        "refund_agent", "transfer_to_refund_agent"
    )
    target = registry.invoke(
        record,
        {"order_id": "o-1", "amount": 12.5},
        ctx=None,
        context={"order_id": "o-1", "card_number": "4111"},
    )
    assert target == "refund_agent"
    assert seen == [{"order_id": "o-1", "amount": 12.5}]

    # (b) strict validation refuses a missing required field.
    try:
        registry.invoke(record, {"amount": 3.0}, ctx=None)
        raise AssertionError("missing required field must be refused")
    except HandoffValidationError:
        pass
    assert registry.errors(), "the refusal must be booked as an error record"

    # (c) a disabled handoff is hidden and refuses to be invoked.
    disabled = registry.register(
        "triage_agent", "refund_agent", tool_name="transfer_to_refund_later",
        is_enabled=False,
    )
    names = [r.tool_name for r in registry.visible_handoffs("triage_agent")]
    assert disabled.tool_name not in names
    try:
        registry.invoke(disabled, None, ctx=None)
        raise AssertionError("a disabled handoff must refuse to be invoked")
    except HandoffTargetError:
        pass

    # Guardrail placement: input -> first agent, output -> final agent.
    registry.begin_run("run-1", "triage_agent")
    registry.set_final_agent("run-1", "refund_agent")
    scope = registry.guardrail_scope("run-1")
    assert scope.input_agent == "triage_agent"
    assert scope.output_agent == "refund_agent"

    print(
        "agent-handoff OK: transfer_to_<name>, strict input, "
        "input_filter, is_enabled, guardrail placement"
    )


if __name__ == "__main__":
    main()
