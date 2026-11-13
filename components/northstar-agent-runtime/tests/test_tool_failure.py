"""Tests for tool_failure: typed tool-failure normalization.

The contract under test: a tool failure is never an exception, a crash, or a
bare string. It is a typed result -- ``is_error``, a ``<tool_use_error>``
envelope, a plain-text summary, an optional denial kind, an optional remedy --
and the vocabularies are closed: Claude Code's five denial kinds and five
remedy kinds are transcribed, and Northstar's own extensions are marked as
such.
"""

import pytest

import support  # noqa: F401  (bootstraps sys.path)

import tool_failure as tf
from provider_retry import ProviderFault, classify, fault_to_failure
from tool_use import ToolUse, tool_use_audit_event


def _schema(**overrides):
    base = {
        "type": "object",
        "properties": {
            "query": {"type": "string"},
            "limit": {"type": "integer"},
        },
        "required": ["query"],
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# the closed vocabularies
# ---------------------------------------------------------------------------


def test_the_vocabularies_are_closed_and_the_cc_words_are_marked():
    # Claude Code's four denial kinds, transcribed verbatim.
    assert tf.DENIAL_KINDS == ("interrupted", "user-rejected",
                                "permission-rule", "cancelled")
    # Claude Code's five remedy kinds, transcribed verbatim.
    assert tf.CC_REMEDY_KINDS == ("memory_paused", "staged_for_review",
                                  "sandbox_violation", "auth_expired",
                                  "auth_overridden")
    # Northstar's own extensions live in their own tuple: a reader can see
    # which words are borrowed and which are ours.
    assert set(tf.NORTHSTAR_REMEDY_KINDS) & set(tf.CC_REMEDY_KINDS) == set()
    assert tf.REMEDY_KINDS == tf.CC_REMEDY_KINDS + tf.NORTHSTAR_REMEDY_KINDS
    with pytest.raises(tf.ToolFailureError):
        tf.ToolResultRemedy(kind="try-again-later")
    with pytest.raises(tf.ToolFailureError):
        tf.ToolFailure(error_code="x", summary="x", denial_kind="nope")
    with pytest.raises(tf.ToolFailureError):
        tf.from_denial("denied-by-vibes")


def test_a_remedy_carries_only_the_fields_its_kind_carries():
    staged = tf.ToolResultRemedy(kind="staged_for_review", path="/tmp/out")
    assert staged.as_dict() == {"kind": "staged_for_review", "path": "/tmp/out"}
    auth = tf.ToolResultRemedy(kind="auth_expired", provider="anthropic")
    assert auth.as_dict() == {"kind": "auth_expired", "provider": "anthropic"}
    overridden = tf.ToolResultRemedy(kind="auth_overridden",
                                     provider="anthropic", managed=True)
    assert overridden.as_dict() == {"kind": "auth_overridden",
                                    "provider": "anthropic", "managed": True}
    assert overridden.is_cc_verbatim
    assert not tf.ToolResultRemedy(kind="invalid_input").is_cc_verbatim


# ---------------------------------------------------------------------------
# the shape of a failure
# ---------------------------------------------------------------------------


def test_a_failure_is_an_enveloped_typed_result():
    failure = tf.from_denial("permission-rule", summary="denied by rule",
                              ends_turn=True)
    result = failure.to_tool_result()
    assert result["is_error"] is True
    assert result["content"] == "<tool_use_error>denied by rule</tool_use_error>"
    assert result["toolUseResult"] == "denied by rule"
    assert result["toolDenialKind"] == "permission-rule"
    assert result["toolDenialEndsTurn"] is True
    assert result["toolResultRemedy"] is None
    assert failure.is_error is True


def test_a_non_denial_leaves_the_denial_kind_explicitly_null():
    failure = tf.from_tool_error(
        _raise_bad_arguments("missing required argument: 'query'"))
    result = failure.to_tool_result()
    assert result["toolDenialKind"] is None
    assert result["toolDenialEndsTurn"] is False
    assert result["toolUseResult"].startswith("InputValidationError: ")
    assert result["errorCode"] == "InputValidationError"
    assert result["toolResultRemedy"] == {"kind": "invalid_input"}


def _raise_bad_arguments(message):
    import tool_use

    return tool_use.BadArgumentsError(message)


# ---------------------------------------------------------------------------
# the dispatch boundary: a real path through invoke
# ---------------------------------------------------------------------------


def test_the_boundary_turns_an_unknown_tool_into_a_typed_result():
    ledger = ToolUse()
    ledger.register("search", _schema(), 1)
    result = ledger.invoke_result("nope", {"query": "x"}, 2)
    assert result.ok is False
    assert result.is_error is True
    assert result.record is None
    payload = result.to_tool_result()
    assert payload["is_error"] is True
    assert payload["errorCode"] == "unknown_tool"
    assert payload["content"].startswith("<tool_use_error>")
    assert payload["content"].endswith("</tool_use_error>")
    assert payload["toolDenialKind"] is None


def test_the_boundary_reports_a_missing_required_key_as_input_validation():
    ledger = ToolUse()
    ledger.register("search", _schema(), 1)
    result = ledger.invoke_result("search", {"limit": 5}, 2)
    payload = result.to_tool_result()
    assert payload["errorCode"] == "InputValidationError"
    assert payload["toolUseResult"].startswith("InputValidationError: ")
    assert payload["toolResultRemedy"] == {"kind": "invalid_input"}


def test_the_boundary_reports_a_wrong_typed_required_key():
    ledger = ToolUse()
    ledger.register("search", _schema(), 1)
    result = ledger.invoke_result("search", {"query": 123}, 2)
    payload = result.to_tool_result()
    assert payload["errorCode"] == "InputValidationError"
    assert "expected string" in payload["toolUseResult"]


def test_an_extra_unknown_key_is_tolerated_and_dropped():
    ledger = ToolUse()
    ledger.register("search", _schema(), 1)
    result = ledger.invoke_result("search", {"query": "x", "bogus": 1,
                                             "another": "extra"}, 2)
    assert result.ok is True
    assert result.record.arguments == {"query": "x"}
    assert "bogus" not in result.record.arguments


def test_the_extra_key_polarity_is_the_opposite_of_the_schema_side():
    # The schema side stays fail-closed: an unknown key in a *schema* is
    # refused. The argument side is tolerant: an unknown key in a *call* is
    # dropped. Both halves are pinned here so neither drifts into the other.
    import tool_use as tu

    ledger = ToolUse()
    with pytest.raises(tu.BadSchemaError):
        ledger.register("bad", {"type": "object", "bogus": 1}, 1)
    ledger.register("good", _schema(), 2)
    assert ledger.invoke_result("good", {"query": "x", "bogus": 1}, 3).ok


def test_each_of_the_four_denial_kinds_renders_itself():
    for kind in ("interrupted", "user-rejected", "permission-rule",
                 "cancelled"):
        failure = tf.from_denial(kind, summary=f"denied: {kind}")
        payload = failure.to_tool_result()
        assert payload["toolDenialKind"] == kind
        assert payload["toolDenialEndsTurn"] is False
        assert payload["is_error"] is True
        assert payload["content"] == f"<tool_use_error>denied: {kind}</tool_use_error>"


def test_denied_and_denied_and_stop_the_turn_are_two_states():
    plain = tf.from_denial("permission-rule", summary="denied")
    stopping = tf.from_denial("permission-rule", summary="denied",
                               ends_turn=True)
    assert plain.to_tool_result()["toolDenialEndsTurn"] is False
    assert stopping.to_tool_result()["toolDenialEndsTurn"] is True
    assert plain.to_tool_result()["toolDenialKind"] == \
        stopping.to_tool_result()["toolDenialKind"]
    # The boundary carries the difference through unchanged.
    ledger = ToolUse()
    ledger.register("search", _schema(), 1)
    result = ledger.invoke_denial("search", "permission-rule", 2,
                                   ends_turn=True, summary="denied by rule")
    assert result.to_tool_result()["toolDenialEndsTurn"] is True
    assert result.to_tool_result()["toolDenialKind"] == "permission-rule"


def test_an_auth_fault_becomes_the_auth_expired_remedy_with_the_provider():
    fault = ProviderFault("auth", detail="401 invalid api key",
                          status_code=401)
    failure = fault_to_failure(fault, provider="anthropic")
    payload = failure.to_tool_result()
    assert payload["toolResultRemedy"] == {"kind": "auth_expired",
                                           "provider": "anthropic"}
    assert payload["errorCode"] == "auth"
    assert payload["toolDenialKind"] is None
    assert payload["retryable"] is False


def test_a_throttled_fault_is_retryable_and_invents_no_remedy_kind():
    fault = ProviderFault("rate_limited", retry_after_ms=1500,
                          detail="429", status_code=429)
    failure = fault_to_failure(fault, provider="anthropic")
    payload = failure.to_tool_result()
    assert payload["retryable"] is True
    assert payload["retryAfterMs"] == 1500
    # No invented sixth remedy kind: a wait is not a remedy word.
    assert payload["toolResultRemedy"] is None
    assert payload["toolDenialKind"] is None
    server = fault_to_failure(ProviderFault("server_error", status_code=500),
                               provider="anthropic")
    assert server.to_tool_result()["retryable"] is True
    assert server.to_tool_result()["toolResultRemedy"] is None


def test_a_failed_invoke_still_burns_its_seq():
    ledger = ToolUse()
    ledger.register("search", _schema(), 1)
    ledger.invoke_result("nope", {}, 2)          # burns seq 2
    with pytest.raises(Exception):
        ledger.invoke("search", {"query": "x"}, 2)  # rewind refused
    result = ledger.invoke_result("search", {"query": "x"}, 3)
    assert result.ok is True
    assert result.seq == 3
    assert result.record.invocation_id == "invoke-1"


def test_the_failure_audit_row_carries_the_error_code_and_the_denial_kind():
    ledger = ToolUse()
    ledger.register("search", _schema(), 1)
    ledger.invoke_result("search", {"limit": 5}, 2)
    ledger.invoke_denial("search", "permission-rule", 3, ends_turn=True)
    rows = [row for row in ledger.audit_log() if row["kind"] == "failed"]
    assert len(rows) == 2
    assert rows[0]["detail"]["error_code"] == "InputValidationError"
    assert rows[0]["detail"]["denial_kind"] is None
    assert rows[1]["detail"]["error_code"] == "denied"
    assert rows[1]["detail"]["denial_kind"] == "permission-rule"
    # The audit boundary still carries no raw arguments.
    assert "secret" not in str(ledger.audit_log())


def test_no_failure_leaves_the_boundary_as_a_bare_exception_or_string():
    ledger = ToolUse()
    ledger.register("search", _schema(), 1)
    cases = [
        ("nope", {"query": "x"}),      # unknown tool
        ("search", {"limit": 5}),      # missing required
        ("search", {"query": 1}),      # wrong type
        ("search", ["not-a-dict"]),    # arguments not a dict
        ("", {"query": "x"}),          # malformed tool id
    ]
    for tool_id, arguments in cases:
        result = ledger.invoke_result(tool_id, arguments, 1)
        payload = result.to_tool_result()
        assert payload["is_error"] is True
        assert payload["content"].startswith("<tool_use_error>")
        assert payload["content"].endswith("</tool_use_error>")
        assert isinstance(payload["toolUseResult"], str)
        assert payload["errorCode"]
        assert payload["toolDenialKind"] is None


def test_the_telemetry_event_names_the_tool_the_code_and_the_denial_kind():
    failure = tf.from_denial("user-rejected", summary="the user said no",
                              tool_name="search", tool_use_id="toolu_1")
    event = failure.to_telemetry_event(message_id="msg_1")
    assert event["event"] == "tengu_tool_use_error"
    assert event["messageId"] == "msg_1"
    assert event["toolUseID"] == "toolu_1"
    assert event["toolName"] == "search"
    assert event["errorCode"] == "denied"
    assert event["toolDenialKind"] == "user-rejected"
    assert event["isMcp"] is False


def test_the_boundary_is_the_only_way_a_tool_failure_leaves_the_ledger():
    # Two ways to book a call, one way for a caller to get a result:
    # ``invoke`` still raises (its contract is unchanged), ``invoke_result``
    # never raises a tool-use error. A caller that wants typed results must
    # not have to catch anything to get them.
    import tool_use as tu

    ledger = ToolUse()
    ledger.register("search", _schema(), 1)
    with pytest.raises(tu.UnknownToolError):
        ledger.invoke("nope", {}, 2)
    result = ledger.invoke_result("nope", {}, 3)
    assert result.is_error is True
    assert isinstance(result.to_tool_result()["content"], str)


def test_a_provider_fault_classifies_and_normalizes_end_to_end():
    class Boom(Exception):
        status_code = 401

    fault = classify(Boom("invalid api key"))
    assert fault.kind == "auth"
    failure = fault_to_failure(fault, provider="anthropic")
    payload = failure.to_tool_result()
    assert payload["toolResultRemedy"]["kind"] == "auth_expired"
    assert payload["toolResultRemedy"]["provider"] == "anthropic"
    assert payload["content"].startswith("<tool_use_error>auth")
