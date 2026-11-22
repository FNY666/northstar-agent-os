"""Tests for agent_handoff (transfer_to_<name> tool with a fixed destination)."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

import agent_handoff
from agent_handoff import (
    AGENT_HANDOFF_SCHEMA,
    AGENT_HANDOFF_VERSION,
    DEFAULT_TOOL_PREFIX,
    GuardrailScope,
    HandoffCallbackError,
    HandoffCancelled,
    HandoffConfigError,
    HandoffDecision,
    HandoffError,
    HandoffErrorRecord,
    HandoffFilterError,
    HandoffRecord,
    HandoffRegistry,
    HandoffTargetError,
    HandoffValidationError,
    KIND_CALLBACK,
    KIND_FILTER,
    KIND_MODEL_BEHAVIOR,
    STATUS_FAILED,
    STATUS_HANDOFF,
)

MODULE_PATH = Path(__file__).resolve().parent.parent / "agent_handoff.py"


def _registry_with_agents(*names):
    registry = HandoffRegistry()
    for name in names:
        registry.register_agent(name)
    return registry


def _order_schema():
    return {
        "type": "object",
        "properties": {
            "order_id": {"type": "string"},
            "amount": {"type": "number"},
        },
        "required": ["order_id"],
    }


# ---------------------------------------------------------------------------
# Pins
# ---------------------------------------------------------------------------


def test_version_and_schema_pins():
    assert AGENT_HANDOFF_VERSION == "agent-handoff.v1"
    assert AGENT_HANDOFF_SCHEMA == "northstar.agent-handoff.v1"
    assert DEFAULT_TOOL_PREFIX == "transfer_to_"


def test_stdlib_only():
    """The module must not import third-party packages."""
    src = MODULE_PATH.read_text(encoding="utf-8")
    tree = __import__("ast").parse(src)
    imported = set()
    for node in __import__("ast").walk(tree):
        if isinstance(node, __import__("ast").Import):
            for alias in node.names:
                imported.add(alias.name.split(".")[0])
        elif isinstance(node, __import__("ast").ImportFrom):
            if node.module:
                imported.add(node.module.split(".")[0])
    allowed = {
        "inspect", "json", "threading", "dataclasses", "typing",
        "__future__", "asyncio",
    }
    assert imported <= allowed, f"non-stdlib import: {imported - allowed}"


def test_module_self_check_runs():
    """The module's own self-check must pass."""
    proc = subprocess.run(
        [sys.executable, str(MODULE_PATH)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=60,
    )
    assert proc.returncode == 0, proc.stdout
    assert "agent-handoff OK" in proc.stdout


# ---------------------------------------------------------------------------
# Default tool name and override
# ---------------------------------------------------------------------------


def test_default_tool_name_is_transfer_to_target():
    """OpenAI: the default tool name is transfer_to_<agent_name>."""
    registry = _registry_with_agents("triage_agent", "refund_agent")
    record = registry.register("triage_agent", "refund_agent")
    assert record.tool_name == "transfer_to_refund_agent"
    assert record.default_tool_identity == (
        "refund_agent", "transfer_to_refund_agent"
    )


def test_tool_name_override_wins_and_drops_default_identity():
    """OpenAI: with a tool_name_override no default identity is recorded."""
    registry = _registry_with_agents("triage_agent", "refund_agent")
    record = registry.register(
        "triage_agent", "refund_agent", tool_name="escalate_to_refund"
    )
    assert record.tool_name == "escalate_to_refund"
    assert record.default_tool_identity is None


def test_tool_name_collision_is_refused():
    registry = _registry_with_agents("triage_agent", "refund_agent")
    registry.register("triage_agent", "refund_agent")
    with pytest.raises(HandoffConfigError):
        registry.register("triage_agent", "refund_agent")


# ---------------------------------------------------------------------------
# Construction-time arity validation
# ---------------------------------------------------------------------------


def test_schema_requires_two_arg_callback_accepted():
    """OpenAI: with an input type the callback takes (context, input)."""
    registry = _registry_with_agents("triage_agent", "refund_agent")
    record = registry.register(
        "triage_agent", "refund_agent",
        input_schema=_order_schema(),
        on_handoff=lambda context, payload: None,
    )
    assert record.input_schema is not None


def test_schema_with_one_arg_callback_is_refused_at_registration():
    """OpenAI: one-argument callback is wrong when a schema is given."""
    registry = _registry_with_agents("triage_agent", "refund_agent")
    with pytest.raises(HandoffConfigError) as excinfo:
        registry.register(
            "triage_agent", "refund_agent",
            input_schema=_order_schema(),
            on_handoff=lambda context: None,
        )
    assert "exactly 2" in str(excinfo.value)


def test_no_schema_with_two_arg_callback_is_refused_at_registration():
    """OpenAI: without an input type the callback takes (context) only."""
    registry = _registry_with_agents("triage_agent", "refund_agent")
    with pytest.raises(HandoffConfigError) as excinfo:
        registry.register(
            "triage_agent", "refund_agent",
            on_handoff=lambda context, payload: None,
        )
    assert "exactly 1" in str(excinfo.value)


def test_no_schema_with_one_arg_callback_accepted():
    registry = _registry_with_agents("triage_agent", "refund_agent")
    record = registry.register(
        "triage_agent", "refund_agent", on_handoff=lambda context: None
    )
    assert record.input_schema is None


def test_schema_without_callback_is_refused_at_registration():
    """OpenAI: giving an input type requires a handoff callback."""
    registry = _registry_with_agents("triage_agent", "refund_agent")
    with pytest.raises(HandoffConfigError) as excinfo:
        registry.register(
            "triage_agent", "refund_agent", input_schema=_order_schema()
        )
    assert "requires on_handoff" in str(excinfo.value)


def test_unregistered_target_is_refused_at_registration():
    """Fail-closed: the destination must be a registered agent."""
    registry = _registry_with_agents("triage_agent")
    with pytest.raises(HandoffConfigError) as excinfo:
        registry.register("triage_agent", "refund_agent")
    assert "not registered" in str(excinfo.value)


def test_register_agent_refuses_non_string():
    """The registry stores names only -- never an agent object."""
    registry = HandoffRegistry()
    with pytest.raises(HandoffConfigError):
        registry.register_agent(object())


# ---------------------------------------------------------------------------
# Strict call-time validation
# ---------------------------------------------------------------------------


def _schema_registry():
    registry = _registry_with_agents("triage_agent", "refund_agent")
    record = registry.register(
        "triage_agent", "refund_agent",
        input_schema=_order_schema(),
        on_handoff=lambda context, payload: None,
    )
    return registry, record


def test_strict_validation_refuses_unknown_property():
    """OpenAI strict mode: unknown fields are refused."""
    registry, record = _schema_registry()
    with pytest.raises(HandoffValidationError) as excinfo:
        registry.invoke(record, {"order_id": "o-1", "surprise": 1})
    assert "unknown" in str(excinfo.value)
    assert registry.errors(), "the refusal must be booked"


def test_strict_validation_refuses_missing_required_property():
    """OpenAI strict mode: a missing required field is refused."""
    registry, record = _schema_registry()
    with pytest.raises(HandoffValidationError) as excinfo:
        registry.invoke(record, {"amount": 3.0})
    assert "missing required" in str(excinfo.value)


def test_strict_validation_refuses_type_mismatch():
    """OpenAI strict mode: a wrong type is refused."""
    registry, record = _schema_registry()
    with pytest.raises(HandoffValidationError) as excinfo:
        registry.invoke(record, {"order_id": 42})
    assert "must be string" in str(excinfo.value)


def test_strict_validation_refuses_invalid_json():
    """Fail-closed: input_json must be valid JSON."""
    registry, record = _schema_registry()
    with pytest.raises(HandoffValidationError) as excinfo:
        registry.invoke(record, "{not json")
    assert "not valid JSON" in str(excinfo.value)


def test_missing_input_with_schema_books_error_before_raising():
    """OpenAI: the error is recorded before ModelBehaviorError is raised."""
    registry, record = _schema_registry()
    with pytest.raises(HandoffValidationError):
        registry.invoke(record, None)
    errors = registry.errors()
    assert len(errors) == 1
    booked = errors[0]
    assert booked.kind == KIND_MODEL_BEHAVIOR
    assert booked.run_id == "default"
    assert booked.target_name == "refund_agent"


def test_validation_failure_keeps_caller_active():
    """A refused input does not end the calling agent's turn."""
    registry, record = _schema_registry()
    with pytest.raises(HandoffValidationError):
        registry.invoke(record, {"amount": 1.0})
    # The handoff is still usable afterwards -- the caller is still active.
    assert registry.invoke(record, {"order_id": "o-2"}) == "refund_agent"


# ---------------------------------------------------------------------------
# Fixed destination
# ---------------------------------------------------------------------------


def test_callback_cannot_change_the_destination():
    """OpenAI: on_handoff is side effects only; the target is fixed."""
    registry = _registry_with_agents("triage_agent", "refund_agent")
    registry.register_agent("other_agent")

    def sneaky(context, payload):
        return "other_agent"

    record = registry.register(
        "triage_agent", "refund_agent",
        input_schema=_order_schema(),
        on_handoff=sneaky,
    )
    assert registry.invoke(record, {"order_id": "o-1"}) == "refund_agent"
    decision = registry.decisions()[-1]
    assert decision.target_name == "refund_agent"


def test_destination_is_the_registered_target():
    registry = _registry_with_agents("triage_agent", "refund_agent")
    record = registry.register("triage_agent", "refund_agent")
    assert registry.invoke(record) == "refund_agent"


# ---------------------------------------------------------------------------
# input_filter (opt-in)
# ---------------------------------------------------------------------------


def test_input_filter_strips_sensitive_fields():
    """Path (a): the filter runs and the payload handed on is filtered."""
    registry = _registry_with_agents("triage_agent", "refund_agent")
    seen = []

    def strip_secrets(context):
        return {
            k: v for k, v in context.items()
            if k not in ("card_number", "ssn")
        }

    record = registry.register(
        "triage_agent", "refund_agent",
        input_schema=_order_schema(),
        input_filter=strip_secrets,
        on_handoff=lambda context, payload: seen.append(payload),
    )
    target = registry.invoke(
        record,
        {"order_id": "o-1", "amount": 12.5},
        context={"order_id": "o-1", "card_number": "4111"},
    )
    assert target == "refund_agent"
    assert seen == [{"order_id": "o-1", "amount": 12.5}]
    decision = registry.decisions()[-1]
    assert decision.filtered is True
    assert "card_number" not in decision.payload


def test_without_filter_the_context_passes_through_unchanged():
    """OpenAI: input_filter is opt-in; without it the full context passes."""
    registry = _registry_with_agents("triage_agent", "refund_agent")
    record = registry.register("triage_agent", "refund_agent")
    assert record.input_filter is None
    assert record.filtered is False
    context = {"order_id": "o-1", "card_number": "4111"}
    registry.invoke(record, context=context)
    decision = registry.decisions()[-1]
    assert decision.filtered is False
    assert decision.payload == context


def test_filter_error_propagates_and_does_not_fall_back_to_unfiltered():
    """A filter error must not degrade into 'pass the context through'."""
    registry = _registry_with_agents("triage_agent", "refund_agent")

    def broken(context):
        raise ValueError("filter exploded")

    record = registry.register(
        "triage_agent", "refund_agent", input_filter=broken
    )
    with pytest.raises(HandoffFilterError) as excinfo:
        registry.invoke(record, context={"secret": 1})
    assert "filter exploded" in str(excinfo.value)
    errors = registry.errors()
    assert errors and errors[-1].kind == KIND_FILTER
    # No decision was booked: the handoff did not happen.
    assert registry.decisions() == ()


# ---------------------------------------------------------------------------
# is_enabled
# ---------------------------------------------------------------------------


def test_disabled_handoff_is_hidden_from_visible_handoffs():
    """OpenAI: a disabled handoff is hidden from the model."""
    registry = _registry_with_agents("triage_agent", "refund_agent")
    registry.register("triage_agent", "refund_agent", tool_name="live_one")
    registry.register(
        "triage_agent", "refund_agent", tool_name="dead_one", is_enabled=False
    )
    names = [r.tool_name for r in registry.visible_handoffs("triage_agent")]
    assert names == ["live_one"]


def test_disabled_handoff_refuses_to_be_invoked():
    """Fail-closed: a disabled handoff cannot be called directly."""
    registry = _registry_with_agents("triage_agent", "refund_agent")
    record = registry.register(
        "triage_agent", "refund_agent", is_enabled=False
    )
    with pytest.raises(HandoffTargetError):
        registry.invoke(record)


def test_is_enabled_predicate_is_evaluated_per_call():
    """OpenAI: is_enabled may be a callable(ctx, agent) -> bool."""
    registry = _registry_with_agents("triage_agent", "refund_agent")
    state = {"on": True}
    record = registry.register(
        "triage_agent", "refund_agent",
        is_enabled=lambda ctx, target: state["on"] and target == "refund_agent",
    )
    assert [r.tool_name for r in registry.visible_handoffs("triage_agent")] == [
        "transfer_to_refund_agent"
    ]
    state["on"] = False
    assert registry.visible_handoffs("triage_agent") == ()
    with pytest.raises(HandoffTargetError):
        registry.invoke(record)
    state["on"] = True
    assert registry.invoke(record) == "refund_agent"


def test_enabled_handoff_is_visible_and_invokable():
    registry = _registry_with_agents("triage_agent", "refund_agent")
    record = registry.register("triage_agent", "refund_agent")
    assert registry.visible_handoffs("triage_agent") == (record,)
    assert registry.invoke(record) == "refund_agent"


# ---------------------------------------------------------------------------
# Failure semantics
# ---------------------------------------------------------------------------


def test_callback_error_keeps_side_effects_and_caller_active():
    """OpenAI: a callback error does not roll back side effects."""
    registry = _registry_with_agents("triage_agent", "refund_agent")
    effects = []

    def half_failing(context):
        effects.append("side-effect-happened")
        raise RuntimeError("callback exploded")

    record = registry.register(
        "triage_agent", "refund_agent", on_handoff=half_failing
    )
    with pytest.raises(HandoffCallbackError) as excinfo:
        registry.invoke(record)
    assert "callback exploded" in str(excinfo.value)
    # The side effect that already happened is NOT rolled back.
    assert effects == ["side-effect-happened"]
    errors = registry.errors()
    assert errors and errors[-1].kind == KIND_CALLBACK
    assert errors[-1].caller_stays_active is True
    # The error was not disguised as a successful handoff.
    assert all(d.status != STATUS_HANDOFF for d in registry.decisions())


def test_handled_failure_keeps_caller_active():
    """OpenAI: after a handled failure the calling agent stays active."""
    registry = _registry_with_agents("triage_agent", "refund_agent")

    def failing(context):
        raise RuntimeError("nope")

    record = registry.register(
        "triage_agent", "refund_agent", on_handoff=failing
    )
    decision = registry.invoke_handled(
        record, failure_error_function=lambda exc: f"handled: {exc}"
    )
    assert decision.status == STATUS_FAILED
    assert decision.caller_stays_active is True
    assert "handled" in decision.error


def test_formatter_none_keeps_the_exception_propagating():
    """OpenAI: failure_error_function=None keeps the exception."""
    registry = _registry_with_agents("triage_agent", "refund_agent")
    record = registry.register(
        "triage_agent", "refund_agent",
        on_handoff=lambda context: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    with pytest.raises(HandoffCallbackError):
        registry.invoke_handled(record, failure_error_function=None)


def test_formatter_error_propagates():
    """OpenAI: an error in the formatter itself keeps propagating."""
    registry = _registry_with_agents("triage_agent", "refund_agent")
    record = registry.register(
        "triage_agent", "refund_agent",
        on_handoff=lambda context: (_ for _ in ()).throw(RuntimeError("boom")),
    )

    def broken_formatter(exc):
        raise ValueError("formatter exploded")

    with pytest.raises(ValueError) as excinfo:
        registry.invoke_handled(record, failure_error_function=broken_formatter)
    assert "formatter exploded" in str(excinfo.value)


def test_cancellation_keeps_propagating_even_with_a_formatter():
    """OpenAI: cancellation always propagates."""
    registry = _registry_with_agents("triage_agent", "refund_agent")
    record = registry.register(
        "triage_agent", "refund_agent",
        on_handoff=lambda context: (_ for _ in ()).throw(
            HandoffCancelled("cancelled")
        ),
    )
    with pytest.raises(HandoffCancelled):
        registry.invoke_handled(
            record, failure_error_function=lambda exc: "should not be used"
        )


def test_filter_error_keeps_propagating_even_with_a_formatter():
    """OpenAI: input-filter errors always propagate."""
    registry = _registry_with_agents("triage_agent", "refund_agent")
    record = registry.register(
        "triage_agent", "refund_agent",
        input_filter=lambda context: (_ for _ in ()).throw(
            ValueError("filter exploded")
        ),
    )
    with pytest.raises(HandoffFilterError):
        registry.invoke_handled(
            record, failure_error_function=lambda exc: "should not be used"
        )


# ---------------------------------------------------------------------------
# Guardrail placement
# ---------------------------------------------------------------------------


def test_guardrail_scope_places_input_on_first_and_output_on_final():
    """OpenAI: input guardrails -> first agent, output -> final agent."""
    registry = _registry_with_agents("triage_agent", "refund_agent")
    registry.begin_run("run-1", "triage_agent")
    registry.set_final_agent("run-1", "refund_agent")
    scope = registry.guardrail_scope("run-1")
    assert isinstance(scope, GuardrailScope)
    assert scope.input_agent == "triage_agent"
    assert scope.output_agent == "refund_agent"


def test_guardrail_scope_for_an_unknown_run_is_empty():
    registry = HandoffRegistry()
    scope = registry.guardrail_scope("run-never-started")
    assert scope.input_agent is None
    assert scope.output_agent is None


def test_guardrail_scope_records_the_first_agent_only_once():
    """The first agent of the chain stays the first agent."""
    registry = _registry_with_agents("triage_agent", "refund_agent")
    registry.begin_run("run-2", "triage_agent")
    registry.begin_run("run-2", "refund_agent")
    assert registry.guardrail_scope("run-2").input_agent == "triage_agent"


# ---------------------------------------------------------------------------
# Not confused with hinted_handoff (Dynamo write buffering)
# ---------------------------------------------------------------------------


def test_hinted_handoff_is_a_write_buffer_not_an_agent_handoff():
    """The two 'handoff' modules have different APIs and different jobs."""
    import hinted_handoff

    # hinted_handoff buffers a write for an unavailable owner and never
    # talks about agents, tools or destinations.
    ledger = hinted_handoff.HintedHandoff()
    hint = ledger.store("h-1", "orders/42", "payload", "node-b", 1)
    assert hint.status == hinted_handoff.STATUS_PENDING
    assert hint.target_node == "node-b"
    assert not hasattr(ledger, "invoke")
    assert not hasattr(ledger, "visible_handoffs")
    assert not hasattr(ledger, "guardrail_scope")

    # agent_handoff is about a tool, a fixed destination and a caller.
    registry = _registry_with_agents("triage_agent", "refund_agent")
    record = registry.register("triage_agent", "refund_agent")
    assert record.tool_name == "transfer_to_refund_agent"
    assert registry.invoke(record) == "refund_agent"
    assert not hasattr(record, "target_node")
    assert not hasattr(record, "status")


def test_agent_handoff_does_not_expose_a_hint_ledger():
    """The agent handoff module has no hint/write-buffer API at all."""
    registry = HandoffRegistry()
    for forbidden in ("store", "deliver", "expire", "pending", "audit_log"):
        assert not hasattr(registry, forbidden)
    assert hasattr(registry, "invoke")
    assert hasattr(registry, "visible_handoffs")
    assert hasattr(registry, "guardrail_scope")


# ---------------------------------------------------------------------------
# Views
# ---------------------------------------------------------------------------


def test_views_are_pure_reads():
    registry = _registry_with_agents("triage_agent", "refund_agent")
    record = registry.register("triage_agent", "refund_agent")
    assert registry.record(record.tool_name) is record
    assert registry.records() == (record,)
    assert registry.agents() == ("refund_agent", "triage_agent")
    assert registry.decisions() == ()
    assert registry.errors() == ()


# ---------------------------------------------------------------------------
# Mutant evidence: the three length bounds
#
# The mutant probe rewrites `>` to `>=` on these three lines, so the
# original and the mutant differ at EXACTLY ONE value: the limit
# itself.  A test that only feeds an over-limit value cannot see the
# difference -- both refuse it.
#
# The three constructs:
#   gt@214  agent name    `len(value) > 256`
#   gt@226  tool name     `len(value) > 256`
#   gt@236  description   `len(value) > 4096`
#
# So each test feeds the limit itself (where the original ACCEPTS and the
# mutant REFUSES), the limit + 1 (where both refuse), and the limit - 1
# (where both accept, the control that stops the test from being
# satisfied by a function that refuses everything).
# ---------------------------------------------------------------------------

#: The limit, read off the module so the test follows the code if the
#: constant moves.
_AGENT_NAME_LIMIT = 256
_TOOL_NAME_LIMIT = 256
_DESCRIPTION_LIMIT = 4096


def test_gt_at_214_agent_name_of_exactly_the_limit_is_accepted():
    """gt@214: `len(value) > 256` -- the limit itself must be ACCEPTED.

    Under the mutant (`>=`) a name of exactly 256 characters is refused.
    This is the only input that separates the original from the mutant.
    """
    registry = HandoffRegistry()
    name = "a" * _AGENT_NAME_LIMIT
    assert len(name) == _AGENT_NAME_LIMIT
    assert registry.register_agent(name) == name
    assert registry.agents() == (name,)


def test_gt_at_214_agent_name_over_the_limit_is_refused():
    """gt@214: the bound itself is still pinned -- 257 characters refuse."""
    registry = HandoffRegistry()
    with pytest.raises(HandoffConfigError):
        registry.register_agent("a" * (_AGENT_NAME_LIMIT + 1))


def test_gt_at_214_agent_name_under_the_limit_is_accepted():
    """gt@214: the control -- one below the limit accepts."""
    registry = HandoffRegistry()
    name = "a" * (_AGENT_NAME_LIMIT - 1)
    assert registry.register_agent(name) == name


def test_gt_at_226_tool_name_of_exactly_the_limit_is_accepted():
    """gt@226: `len(value) > 256` -- the limit itself must be ACCEPTED."""
    registry = _registry_with_agents("triage_agent")
    tool_name = "t" * _TOOL_NAME_LIMIT
    record = registry.register(
        "triage_agent",
        "triage_agent",
        tool_name=tool_name,
    )
    assert record.tool_name == tool_name


def test_gt_at_226_tool_name_over_the_limit_is_refused():
    """gt@226: the bound itself is still pinned -- 257 characters refuse."""
    registry = _registry_with_agents("triage_agent")
    with pytest.raises(HandoffConfigError):
        registry.register(
            "triage_agent",
            "triage_agent",
            tool_name="t" * (_TOOL_NAME_LIMIT + 1),
        )


def test_gt_at_226_tool_name_under_the_limit_is_accepted():
    """gt@226: the control -- one below the limit accepts."""
    registry = _registry_with_agents("triage_agent")
    tool_name = "t" * (_TOOL_NAME_LIMIT - 1)
    record = registry.register(
        "triage_agent",
        "triage_agent",
        tool_name=tool_name,
    )
    assert record.tool_name == tool_name


def test_gt_at_236_description_of_exactly_the_limit_is_accepted():
    """gt@236: `len(value) > 4096` -- the limit itself must be ACCEPTED."""
    registry = _registry_with_agents("triage_agent")
    description = "d" * _DESCRIPTION_LIMIT
    record = registry.register(
        "triage_agent",
        "triage_agent",
        tool_description=description,
    )
    assert record.tool_description == description


def test_gt_at_236_description_over_the_limit_is_refused():
    """gt@236: the bound itself is still pinned -- 4097 characters refuse."""
    registry = _registry_with_agents("triage_agent")
    with pytest.raises(HandoffConfigError):
        registry.register(
            "triage_agent",
            "triage_agent",
            tool_description="d" * (_DESCRIPTION_LIMIT + 1),
        )


def test_gt_at_236_description_under_the_limit_is_accepted():
    """gt@236: the control -- one below the limit accepts."""
    registry = _registry_with_agents("triage_agent")
    description = "d" * (_DESCRIPTION_LIMIT - 1)
    record = registry.register(
        "triage_agent",
        "triage_agent",
        tool_description=description,
    )
    assert record.tool_description == description
