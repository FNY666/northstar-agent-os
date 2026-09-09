"""Elicitation-as-approval: decoding a modern server's embedded input requests, the
policy that decides what may be answered, and the MRTR round trip through the client.

The invariant under test is a single sentence: **a remote server may ask, and the run
may refuse, but nothing may answer on the operator's behalf without the operator having
said so.**
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

from mcp_client import McpStdioClient
from mcp_elicitation import (
    ACCEPT,
    CANCEL,
    DECLINE,
    MAX_ANSWER_CHARS,
    MAX_DESCRIPTION_CHARS,
    MAX_MESSAGE_CHARS,
    MAX_PROPERTIES,
    SENSITIVE_NAME_RE,
    ElicitationError,
    ElicitationRequest,
    decode_input_requests,
    decode_request,
    make_answers_elicitor,
    make_terminal_elicitor,
    resolve_requests,
    summarize_verdicts,
)
from mcp_negotiate import ELICITATION_METHOD, ROOTS_METHOD, SAMPLING_METHOD

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "mcp_mrtr_server.py"


def elicit_form(**overrides: object) -> dict:
    params: dict = {
        "mode": "form",
        "message": "Delete /tmp/x?",
        "requestedSchema": {
            "type": "object",
            "properties": {"approved": {"type": "boolean", "description": "really?"}},
            "required": ["approved"],
        },
    }
    params.update(overrides)
    return {"method": ELICITATION_METHOD, "params": params}


def decode(entry: dict, **kwargs: object) -> ElicitationRequest:
    kwargs.setdefault("server", "srv")
    kwargs.setdefault("tool", "tool")
    return decode_request("k", entry, **kwargs)  # type: ignore[arg-type]


class DecodeTests(unittest.TestCase):
    def test_an_elicitation_becomes_a_typed_field_list(self):
        request = decode(elicit_form())
        self.assertEqual((request.server, request.tool, request.key, request.method), ("srv", "tool", "k", ELICITATION_METHOD))
        self.assertTrue(request.answerable)
        self.assertEqual(len(request.fields), 1)
        field = request.fields[0]
        self.assertEqual((field.name, field.type, field.required), ("approved", "boolean", True))
        self.assertIn("Delete /tmp/x?", request.message)
        self.assertIn("approved (boolean)", request.prompt())

    def test_sampling_is_declined_and_the_reason_names_the_method(self):
        request = decode({"method": SAMPLING_METHOD, "params": {"messages": []}})
        self.assertFalse(request.answerable)
        self.assertIn("sampling/createMessage", request.refuse_reason)
        self.assertIn("does not lend its model", request.refuse_reason)

    def test_roots_need_both_an_opt_in_and_a_workspace(self):
        # The opt-in lives in the batch entry point, which is what the client calls: a
        # root is only ever handed down when ``allow_roots`` was set, so "no root" and
        # "not allowed" refuse for the same reason and neither is answerable.
        entry = {"r": {"method": ROOTS_METHOD, "params": {}}}
        (denied,) = decode_input_requests(entry, server="s", tool="t", workspace_root="/work")
        self.assertFalse(denied.answerable)
        self.assertIn("no workspace root", denied.refuse_reason)
        (allowed,) = decode_input_requests(entry, server="s", tool="t", workspace_root="/work", allow_roots=True)
        self.assertTrue(allowed.answerable)
        self.assertEqual(allowed.workspace_root, "/work")

    def test_an_unrecognised_method_is_described_not_dropped(self):
        request = decode({"method": "notification/ask", "params": {}})
        self.assertFalse(request.answerable)
        self.assertIn("unsupported input request method", request.refuse_reason)

    def test_a_missing_params_object_is_a_hard_error(self):
        with self.assertRaises(ElicitationError):
            decode({"method": ELICITATION_METHOD})
        with self.assertRaises(ElicitationError):
            decode({"method": ELICITATION_METHOD, "params": {"mode": "form", "requestedSchema": "nope"}})

    def test_the_schema_is_bounded_in_width_depth_and_size(self):
        wide = {"type": "object", "properties": {f"f{i}": {"type": "string"} for i in range(MAX_PROPERTIES + 1)}}
        with self.assertRaises(ElicitationError):
            decode(elicit_form(requestedSchema=wide))
        deep: dict = {"type": "string"}
        for _ in range(6):
            deep = {"type": "object", "properties": {"n": deep}}
        with self.assertRaises(ElicitationError):
            decode(elicit_form(requestedSchema=deep))
        huge = {"type": "object", "properties": {"a": {"type": "string", "description": "x" * 9_000}}}
        with self.assertRaises(ElicitationError):
            decode(elicit_form(requestedSchema=huge))

    def test_long_strings_are_truncated_rather_than_refused(self):
        request = decode(
            elicit_form(
                message="q" * (MAX_MESSAGE_CHARS + 500),
                requestedSchema={
                    "type": "object",
                    "properties": {"a": {"type": "string", "description": "d" * (MAX_DESCRIPTION_CHARS + 50)}},
                },
            )
        )
        self.assertEqual(len(request.message), MAX_MESSAGE_CHARS)
        self.assertEqual(len(request.fields[0].description), MAX_DESCRIPTION_CHARS)

    def test_credential_shaped_names_are_refused_before_any_human_is_asked(self):
        for name in ("password", "api_key", "accessKey", "otp", "private_key", "session_id"):
            request = decode(elicit_form(requestedSchema={"type": "object", "properties": {name: {"type": "string"}}}))
            self.assertFalse(request.answerable, name)
            self.assertIn("credential", request.refuse_reason)
            self.assertTrue(SENSITIVE_NAME_RE.search(name), name)
        for name in ("approved", "target_path", "note", "reason"):
            request = decode(elicit_form(requestedSchema={"type": "object", "properties": {name: {"type": "string"}}}))
            self.assertTrue(request.answerable, name)

    def test_a_host_may_opt_into_one_sensitive_field(self):
        entry = elicit_form(requestedSchema={"type": "object", "properties": {"password": {"type": "string"}}})
        self.assertTrue(decode(entry, allow_sensitive=True).answerable)


class ResolveTests(unittest.TestCase):
    def request(self, **kwargs: object) -> ElicitationRequest:
        return decode(elicit_form(), **kwargs)  # type: ignore[arg-type]

    def test_no_approver_means_decline_not_default(self):
        responses, verdicts = resolve_requests([self.request()], elicitor=None)
        self.assertEqual(responses["k"], {"action": DECLINE})
        self.assertEqual(verdicts[0].action, DECLINE)
        self.assertIn("no approver attached", verdicts[0].reason)

    def test_an_approver_answer_becomes_content(self):
        responses, verdicts = resolve_requests([self.request()], elicitor=lambda request: {"approved": True})
        self.assertEqual(responses["k"], {"action": ACCEPT, "content": {"approved": True}})
        self.assertEqual(verdicts[0].action, ACCEPT)
        self.assertEqual(verdicts[0].answered_fields, ("approved",))

    def test_boolean_true_is_an_accept_when_nothing_is_required(self):
        requests = decode_input_requests(
            {"k": elicit_form(requestedSchema={"type": "object", "properties": {"note": {"type": "string"}}})},
            server="s",
            tool="t",
        )
        responses, verdicts = resolve_requests(requests, elicitor=lambda request: True)
        self.assertEqual(responses["k"], {"action": ACCEPT, "content": {}})
        self.assertEqual(verdicts[0].action, ACCEPT)

    def test_answering_a_field_the_server_never_asked_for_is_rejected(self):
        # Volunteering data is how a client leaks; the request must be answerable only
        # in the shape the server declared.
        responses, verdicts = resolve_requests(
            [self.request()], elicitor=lambda request: {"approved": True, "ssh_private_key": "abc"}
        )
        self.assertEqual(responses["k"], {"action": DECLINE})
        self.assertIn("never asked for", verdicts[0].reason)

    def test_a_missing_required_field_is_a_refusal_not_a_blank(self):
        responses, verdicts = resolve_requests([self.request()], elicitor=lambda request: {})
        self.assertEqual(responses["k"], {"action": DECLINE})
        self.assertIn("required field 'approved'", verdicts[0].reason)

    def test_an_over_long_answer_is_refused(self):
        responses, verdicts = resolve_requests(
            [self.request()], elicitor=lambda request: {"approved": "x" * (MAX_ANSWER_CHARS + 1)}
        )
        self.assertEqual(responses["k"], {"action": DECLINE})
        self.assertIn("chars (cap", verdicts[0].reason)

    def test_a_faulty_approver_declines_and_says_which(self):
        def explode(request: ElicitationRequest) -> dict:
            raise RuntimeError("prompt unavailable")

        responses, verdicts = resolve_requests([self.request()], elicitor=explode)
        self.assertEqual(responses["k"], {"action": DECLINE})
        self.assertIn("RuntimeError", verdicts[0].reason)
        self.assertIn("prompt unavailable", verdicts[0].reason)

    def test_cancel_is_its_own_action(self):
        responses, verdicts = resolve_requests([self.request()], elicitor=lambda request: CANCEL)
        self.assertEqual(responses["k"], {"action": CANCEL})
        self.assertEqual(verdicts[0].action, CANCEL)

    def test_refused_methods_never_reach_the_approver(self):
        seen: list[str] = []
        requests = decode_input_requests(
            {"a": elicit_form(), "b": {"method": SAMPLING_METHOD, "params": {"messages": []}}}, server="s", tool="t"
        )
        responses, verdicts = resolve_requests(requests, elicitor=lambda request: seen.append(request.key) or {"approved": True})
        self.assertEqual(seen, ["a"], "an unanswerable request must not be offered for approval")
        self.assertEqual(responses["b"], {"action": DECLINE})
        self.assertEqual(responses["a"], {"action": ACCEPT, "content": {"approved": True}})

    def test_roots_answer_with_exactly_the_workspace(self):
        requests = decode_input_requests(
            {"r": {"method": ROOTS_METHOD, "params": {}}},
            server="s",
            tool="t",
            workspace_root="/work",
            allow_roots=True,
        )
        responses, verdicts = resolve_requests(requests, elicitor=lambda request: {"approved": True})
        self.assertEqual(
            responses["r"], {"action": ACCEPT, "roots": [{"uri": "file:///work", "name": "workspace"}]}
        )
        self.assertIn("single workspace root", verdicts[0].reason)

    def test_values_never_appear_in_the_audit_record(self):
        secret = "hunter2-do-not-log-me"
        requests = decode_input_requests(
            {"k": elicit_form(requestedSchema={"type": "object", "properties": {"note": {"type": "string"}}, "required": ["note"]})},
            server="s",
            tool="t",
        )
        _, verdicts = resolve_requests(requests, elicitor=lambda request: {"note": secret})
        blob = json.dumps(summarize_verdicts(verdicts))
        self.assertIn("note", blob)
        self.assertNotIn(secret, blob)
        self.assertEqual(summarize_verdicts(verdicts)["accepted"], 1)

    def test_declining_requests_are_counted_separately_from_cancels(self):
        requests = decode_input_requests({"a": elicit_form(), "b": {"method": SAMPLING_METHOD, "params": {}}}, server="s", tool="t")
        _, verdicts = resolve_requests(requests, elicitor=lambda request: CANCEL if request.key == "a" else {"approved": True})
        summary = summarize_verdicts(verdicts)
        self.assertEqual((summary["count"], summary["cancelled"], summary["declined"]), (2, 1, 1))


class ElicitorFactoryTests(unittest.TestCase):
    def request(self) -> ElicitationRequest:
        return decode(elicit_form())

    def test_pre_approved_answers_are_applied_field_by_field(self):
        elicitor = make_answers_elicitor({"approved": True, "unused": 1})
        self.assertEqual(dict(elicitor(self.request())), {"approved": True})

    def test_a_gap_in_the_pre_approved_set_is_a_refusal(self):
        elicitor = make_answers_elicitor({"other": 1})
        with self.assertRaises(ElicitationError) as caught:
            elicitor(self.request())
        self.assertIn("does not cover approved", str(caught.exception))

    def test_the_terminal_elicitor_asks_per_field_and_coerces(self):
        answers = iter(["y", "12"])
        elicitor = make_terminal_elicitor(read_line=lambda prompt: next(answers), echo=lambda text: None)
        request = decode(
            elicit_form(
                requestedSchema={
                    "type": "object",
                    "properties": {"approved": {"type": "boolean"}, "count": {"type": "integer"}},
                    "required": ["approved"],
                }
            )
        )
        self.assertEqual(dict(elicitor(request)), {"approved": True, "count": 12})

    def test_a_blank_boolean_is_no_and_a_blank_required_field_is_a_refusal(self):
        self.assertEqual(dict(make_terminal_elicitor(read_line=lambda p: "", echo=lambda t: None)(self.request())), {})
        with self.assertRaises(ElicitationError):
            make_terminal_elicitor(read_line=lambda p: "maybe", echo=lambda t: None)(self.request())
        with self.assertRaises(ElicitationError):
            make_terminal_elicitor(read_line=lambda p: "", echo=lambda t: None)(
                decode(elicit_form(requestedSchema={"type": "object", "properties": {"note": {"type": "string"}}, "required": ["note"]}))
            )

    def test_cancel_from_a_terminal_abandons_the_whole_call(self):
        elicitor = make_terminal_elicitor(read_line=lambda p: CANCEL, echo=lambda t: None)
        _, verdicts = resolve_requests([self.request()], elicitor=elicitor)
        self.assertEqual(verdicts[0].action, CANCEL)

    def test_the_prompt_is_shown_and_never_includes_the_answers(self):
        shown: list[str] = []
        elicitor = make_terminal_elicitor(read_line=lambda p: "yes", echo=shown.append)
        elicitor(self.request())
        self.assertIn("Delete /tmp/x?", shown[0])
        self.assertNotIn("yes", "\n".join(shown))


class MrtrRoundTripTests(unittest.TestCase):
    """The same policy, driven through a real subprocess and a real retry."""

    def connect(self, *, mode: str = "discover", **kwargs: object) -> McpStdioClient:
        wire = Path(tempfile.mkdtemp(prefix="nsar-mrtr-")) / "wire.jsonl"
        # The fixture's instructions arrive through the client, the only door left open to it: a
        # server child sees what it is given, never what the test process happens to hold.
        client = McpStdioClient(
            "demo",
            [sys.executable, str(FIXTURE)],
            timeout_ms=8_000,
            env={"MRTR_SERVER_MODE": mode, "MRTR_SERVER_WIRE": str(wire)},
            **kwargs,  # type: ignore[arg-type]
        )
        client.connect()
        client._wire_path = str(wire)  # noqa: SLF001 - test-local bookkeeping
        return client

    def wire(self, client: McpStdioClient) -> list[dict]:
        return [json.loads(line) for line in Path(client._wire_path).read_text(encoding="utf-8").splitlines() if line]

    def test_unattended_run_refuses_the_request_and_cancels_the_call(self):
        client = self.connect()
        try:
            result = client.call_tool("needs_input", {})
            self.assertTrue(result.is_error)
            self.assertIn("declined without calling the tool", result.text())
            self.assertIn("no approver attached", result.text())
            calls = [entry for entry in self.wire(client) if entry["method"] == "tools/call"]
            self.assertEqual(len(calls), 1, "a refusal is final: no retry loop until the round cap")
            self.assertIn("notifications/cancelled", [entry["method"] for entry in self.wire(client)])
        finally:
            client.close()

    def test_an_approved_request_is_carried_by_a_genuinely_new_request(self):
        client = self.connect(elicitor=make_answers_elicitor({"approved": True}))
        try:
            result = client.call_tool("needs_input", {})
            self.assertFalse(result.is_error, result.text())
            self.assertIn("answered after 1 ask(s)", result.text())
            self.assertIn("governance", result.text(), "the model must see that a remote server tried to ask")
            calls = [entry for entry in self.wire(client) if entry["method"] == "tools/call"]
            self.assertEqual(len(calls), 2)
            self.assertNotEqual(calls[0]["id"], calls[1]["id"], "the retry is a new JSON-RPC request")
            self.assertEqual(calls[1]["params"]["requestState"], "state-1", "the opaque state is echoed verbatim")
            self.assertEqual(
                calls[1]["params"]["inputResponses"],
                {"ask_model": {"action": "decline"}, "confirm": {"action": "accept", "content": {"approved": True}}},
            )
            self.assertIsNone(calls[0]["params"].get("requestState"))
        finally:
            client.close()

    def test_sampling_and_password_requests_are_refused_even_with_an_approver(self):
        client = self.connect(elicitor=make_answers_elicitor({"approved": True, "password": "hunter2"}))
        try:
            secret = client.call_tool("needs_password", {})
            self.assertTrue(secret.is_error)
            self.assertIn("credential", secret.text())
            self.assertNotIn("hunter2", json.dumps(client.elicitation_log))
            self.assertNotIn("hunter2", secret.text())
            self.assertEqual([verdict["action"] for verdict in client.elicitation_log], ["decline"])
        finally:
            client.close()

    def test_a_host_that_allows_sensitive_input_still_has_to_answer_it(self):
        client = self.connect(
            allow_sensitive_input=True,
            elicitor=make_answers_elicitor({"password": "hunter2"}),
        )
        try:
            # Answering is now permitted, and the server accepts it: the point is that
            # the *value* is what the server asked for, and it never reaches the audit.
            result = client.call_tool("needs_password", {})
            self.assertFalse(result.is_error, result.text())
            verdict = client.elicitation_log[-1]
            self.assertEqual((verdict["action"], verdict["answered_fields"]), ("accept", ["password"]))
            self.assertNotIn("hunter2", json.dumps(client.elicitation_log))
        finally:
            client.close()

    def test_a_server_that_never_stops_asking_is_stopped(self):
        client = self.connect(mode="loop", elicitor=make_answers_elicitor({"approved": True}), max_input_rounds=2)
        try:
            result = client.call_tool("needs_input", {})
            self.assertTrue(result.is_error)
            self.assertIn("stopped after 2 round(s)", result.text())
            calls = [entry for entry in self.wire(client) if entry["method"] == "tools/call"]
            self.assertEqual(len(calls), 3, "max rounds + the original request, never more")
            self.assertEqual(len(client.elicitation_log), 4, "two rounds of two requests each")
        finally:
            client.close()

    def test_an_approver_can_cancel_the_call(self):
        client = self.connect(elicitor=lambda request: CANCEL if request.key == "confirm" else None)
        try:
            result = client.call_tool("needs_input", {})
            self.assertTrue(result.is_error)
            self.assertIn("cancelled this call", result.text())
        finally:
            client.close()

    def test_the_audit_callback_sees_every_verdict(self):
        seen: list[dict] = []
        client = self.connect(audit=seen.append)
        try:
            client.call_tool("needs_input", {})
            self.assertEqual([record["method"] for record in seen], [SAMPLING_METHOD, ELICITATION_METHOD])
            self.assertTrue(all(record["kind"] == "mcp-elicitation" for record in seen))
            self.assertTrue(all(record["action"] == DECLINE for record in seen))
            self.assertEqual(client.elicitation_log, seen, "the log and the audit sink are the same records")
        finally:
            client.close()

    def test_a_tool_that_never_asks_is_unaffected_by_the_new_path(self):
        client = self.connect()
        try:
            result = client.call_tool("echo", {"text": "boring"})
            self.assertFalse(result.is_error)
            self.assertIn("rounds", result.text())
            self.assertNotIn("governance", result.text())
            self.assertEqual(client.elicitation_log, [])
        finally:
            client.close()

    def test_an_input_required_result_with_nothing_to_answer_is_an_error(self):
        # The spec allows "no inputRequests" only together with a state to echo; a
        # result with neither is a server that cannot say what it wants.
        client = self.connect(mode="bare")
        try:
            result = client.call_tool("needs_input", {})
            self.assertTrue(result.is_error)
            self.assertIn("neither inputRequests nor requestState", result.text())
            calls = [entry for entry in self.wire(client) if entry["method"] == "tools/call"]
            self.assertEqual(len(calls), 1, "no question means no retry")
        finally:
            client.close()

    def test_a_bare_retry_is_allowed_once_per_round_and_then_capped(self):
        client = self.connect(mode="bare-state", max_input_rounds=2)
        try:
            result = client.call_tool("needs_input", {})
            self.assertTrue(result.is_error)
            self.assertIn("stopped after 2 round(s)", result.text())
            calls = [entry for entry in self.wire(client) if entry["method"] == "tools/call"]
            self.assertEqual(len(calls), 3)
            self.assertEqual(calls[1]["params"]["requestState"], "bare-0", "the state is echoed even with no question")
        finally:
            client.close()


if __name__ == "__main__":
    unittest.main()
