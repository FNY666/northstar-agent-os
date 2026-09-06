"""Sidecar client: the local half of the delegation contract.

Nothing here touches a real Codex. The transport seam stands in for the socket so
the framing, validation, and failure taxonomy can be asserted offline; the socket
itself is exercised in ``test_integration_sidecar.py``.
"""
from __future__ import annotations

import json
import os
import socket
import tempfile
import unittest
from pathlib import Path

import support  # noqa: F401

from sidecar_client import (
    FALLBACK_STATUSES,
    MAX_REQUEST_BYTES,
    SIDECAR_MAX_PROMPT_CHARS,
    SIDECAR_MAX_TIMEOUT_MS,
    SIDECAR_MIN_TIMEOUT_MS,
    SOCKET_FILENAME,
    SidecarClient,
    SidecarProtocolError,
    SidecarResult,
    fallback_allowed,
    known_statuses,
    socket_path_text,
    validate_request,
    validate_socket_path,
)
from tools import ToolContext, ToolResult, build_default_registry, codex_tool_spec


def client_with(payload: object, *, error: Exception | None = None, **kwargs) -> tuple[SidecarClient, list[bytes]]:
    """A client whose transport returns `payload` and records the request bytes."""
    sent: list[bytes] = []

    def transport(request_bytes: bytes) -> tuple[str, int, bool]:
        sent.append(request_bytes)
        if error is not None:
            raise error
        if isinstance(payload, bytes):
            text = payload.decode("utf-8")
        elif isinstance(payload, str):
            text = payload
        else:
            text = json.dumps(payload, ensure_ascii=False)
        encoded = text.encode("utf-8")
        return text, len(encoded) + 1, False

    client = SidecarClient(kwargs.pop("socket_path", "/run/northstar-codex/sidecar.sock"), transport=transport, **kwargs)
    return client, sent


class ValidationTests(unittest.TestCase):
    def test_a_well_formed_request_is_accepted(self):
        checked = validate_request({"request_id": "r1", "prompt": "look at this", "timeout_ms": 5000})
        self.assertTrue(checked.ok, checked.errors)

    def test_the_request_surface_is_exactly_three_fields(self):
        checked = validate_request({"request_id": "r1", "prompt": "x", "timeout_ms": 5000, "sandbox": "read-only"})
        self.assertFalse(checked.ok)
        self.assertEqual(checked.errors, ("unknown request fields: sandbox",))

    def test_the_sidecar_limits_are_mirrored_exactly(self):
        # If the sidecar moves a bound and this copy does not, the runtime sends a
        # request the sidecar rejects, and the error text blames the wrong component.
        sidecar = support.load_sidecar("sidecar")

        self.assertEqual(SIDECAR_MAX_PROMPT_CHARS, sidecar.MAX_PROMPT_CHARS)
        self.assertEqual(SIDECAR_MIN_TIMEOUT_MS, sidecar.MIN_TIMEOUT_MS)
        self.assertEqual(SIDECAR_MAX_TIMEOUT_MS, sidecar.MAX_TIMEOUT_MS)
        self.assertEqual(SOCKET_FILENAME, "sidecar.sock")

    def test_prompt_size_is_checked_at_the_boundary(self):
        self.assertTrue(validate_request({"request_id": "r", "prompt": "x" * SIDECAR_MAX_PROMPT_CHARS, "timeout_ms": 1000}).ok)
        checked = validate_request({"request_id": "r", "prompt": "x" * (SIDECAR_MAX_PROMPT_CHARS + 1), "timeout_ms": 1000})
        self.assertEqual(checked.errors, ("prompt exceeds maximum size",))

    def test_timeout_range_is_inclusive(self):
        for timeout in (SIDECAR_MIN_TIMEOUT_MS, SIDECAR_MAX_TIMEOUT_MS):
            self.assertTrue(validate_request({"request_id": "r", "prompt": "x", "timeout_ms": timeout}).ok, timeout)
        for timeout in (SIDECAR_MIN_TIMEOUT_MS - 1, SIDECAR_MAX_TIMEOUT_MS + 1, True, "1000", None):
            with self.subTest(timeout=timeout):
                self.assertFalse(validate_request({"request_id": "r", "prompt": "x", "timeout_ms": timeout}).ok)

    def test_empty_and_whitespace_prompts_are_refused(self):
        for prompt in ("", "   ", "\n", 5, None):
            with self.subTest(prompt=prompt):
                self.assertFalse(validate_request({"request_id": "r", "prompt": prompt, "timeout_ms": 1000}).ok)

    def test_a_non_mapping_is_described(self):
        self.assertEqual(validate_request("prompt").errors, ("request must be an object",))

    def test_request_id_bounds(self):
        self.assertFalse(validate_request({"request_id": " ", "prompt": "x", "timeout_ms": 1000}).ok)
        self.assertFalse(validate_request({"request_id": "r" * 129, "prompt": "x", "timeout_ms": 1000}).ok)

    def test_socket_path_rules(self):
        self.assertTrue(validate_socket_path("/run/northstar-codex/sidecar.sock").ok)
        self.assertTrue(validate_socket_path("/tmp/whatever/sidecar.sock/").ok)
        self.assertEqual(validate_socket_path("relative/sidecar.sock").errors, ("sidecar socket path must be absolute",))
        self.assertEqual(validate_socket_path("").errors, ("sidecar socket path must be a non-empty string",))
        self.assertEqual(validate_socket_path("/tmp/sidecarOther.sock").errors, (f"sidecar socket filename must be {SOCKET_FILENAME}",))
        self.assertTrue(validate_socket_path("/tmp/sidecarOther.sock", require_canonical_name=False).ok)
        self.assertEqual(socket_path_text(Path("/tmp/a.sock")), "/tmp/a.sock")

    def test_status_taxonomies(self):
        self.assertEqual(fallback_allowed("transport_unavailable"), True)
        self.assertEqual(fallback_allowed("timeout"), True)
        self.assertEqual(fallback_allowed("rejected"), False)
        self.assertEqual(FALLBACK_STATUSES, frozenset({"transport_unavailable", "timeout"}))
        statuses = set(known_statuses())
        self.assertTrue({"ok", "rejected", "timeout", "internal_error", "codex_error", "protocol_error"} <= statuses)


class ConstructionTests(unittest.TestCase):
    def test_an_illegal_socket_path_is_refused_before_any_connect(self):
        for bad in ("relative/sidecar.sock", "/tmp/nope.sock", ""):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError) as caught:
                    SidecarClient(bad)
                self.assertIn("refusing to build a sidecar client", str(caught.exception))

    def test_an_illegal_default_timeout_is_refused(self):
        with self.assertRaises(ValueError):
            SidecarClient("/tmp/x/sidecar.sock", timeout_ms=500)

    def test_request_ids_are_prefixed_and_unique(self):
        client, _ = client_with({"status": "ok"})
        first, second = client.new_request_id(), client.new_request_id()
        self.assertTrue(first.startswith("nsar-"))
        self.assertNotEqual(first, second)
        self.assertLessEqual(len(first), 128)


class RoundTripTests(unittest.TestCase):
    def test_the_wire_request_is_one_json_line_with_exactly_three_fields(self):
        client, sent = client_with({"request_id": "r", "status": "ok", "text": "hello"}, )
        result = client.execute("do the thing", request_id="r")
        self.assertEqual(len(sent), 1)
        self.assertTrue(sent[0].endswith(b"\n"))
        self.assertEqual(sent[0].count(b"\n"), 1)
        payload = json.loads(sent[0])
        self.assertEqual(sorted(payload), ["prompt", "request_id", "timeout_ms"])
        self.assertEqual(payload["prompt"], "do the thing")
        self.assertEqual(payload["timeout_ms"], 30_000)
        self.assertTrue(result.ok)
        self.assertEqual(result.text, "hello")

    def test_unicode_travels_as_utf8_not_escapes(self):
        client, sent = client_with({"status": "ok", "text": "中文"})
        client.execute("读取 文件")
        self.assertIn("读取 文件".encode("utf-8"), sent[0])
        self.assertNotIn(b"\\u", sent[0])

    def test_a_per_call_timeout_overrides_the_default(self):
        client, sent = client_with({"status": "ok", "text": "x"})
        client.execute("go", timeout_ms=4000)
        self.assertEqual(json.loads(sent[0])["timeout_ms"], 4000)

    def test_an_out_of_contract_prompt_is_refused_locally_without_a_round_trip(self):
        client, sent = client_with({"status": "ok", "text": "x"})
        result = client.execute("y" * (SIDECAR_MAX_PROMPT_CHARS + 1))
        self.assertEqual(sent, [], "the request never leaves the process")
        self.assertEqual(result.status, "rejected")
        self.assertEqual(result.errors, ("prompt exceeds maximum size",))
        self.assertIn("prompt exceeds maximum size", result.report)

    def test_the_request_is_capped_before_it_is_sent(self):
        client, sent = client_with({"status": "ok", "text": "x"})
        with self.assertRaises(SidecarProtocolError):
            client._round_trip({"request_id": "r", "prompt": "x" * SIDECAR_MAX_PROMPT_CHARS, "timeout_ms": SIDECAR_MAX_TIMEOUT_MS, "extra": "y" * (MAX_REQUEST_BYTES)})
        self.assertEqual(sent, [])

    def test_an_absent_socket_is_transport_unavailable_not_an_exception(self):
        missing = os.path.join(tempfile.mkdtemp(prefix="nsar-nosuch-"), SOCKET_FILENAME)
        client = SidecarClient(missing)
        result = client.execute("go")
        self.assertEqual(result.status, "transport_unavailable")
        self.assertTrue(result.may_fall_back, "a host may decide to proceed another way")
        self.assertIn("socket is not present", result.error)

    def test_a_stalled_peer_becomes_a_timeout_result(self):
        client, _ = client_with(None, error=TimeoutError("read deadline exceeded"))
        result = client.execute("go")
        self.assertEqual(result.status, "transport_unavailable")
        self.assertIn("did not answer within the read deadline", result.error)

    def test_a_refused_connection_is_reported_not_raised(self):
        path = os.path.join(tempfile.mkdtemp(prefix="nsar-sock-"), SOCKET_FILENAME)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(path)
        listener.listen(0)
        listener.close()  # inode exists, nobody accepts
        client = SidecarClient(path)
        result = client.execute("go")
        self.assertEqual(result.status, "transport_unavailable")
        self.assertIn("transport failed", result.error)

    def test_a_closed_connection_is_a_protocol_error(self):
        client, _ = client_with("\n")
        result = client.execute("go")
        self.assertEqual(result.status, "protocol_error")
        self.assertIn("non-JSON", result.error)

    def test_response_fields_are_validated(self):
        cases = {
            "not a mapping": ([{"status": "ok"}], "sidecar response is not a JSON object"),
            "no status": ({"text": "hi"}, "no status field"),
            "ok without text": ({"status": "ok", "text": ""}, "ok without an agent message"),
            "non-string text": ({"status": "ok", "text": 5}, "text field is not a string"),
        }
        for label, (payload, expected) in cases.items():
            with self.subTest(case=label):
                client, _ = client_with(payload)
                result = client.execute("go")
                self.assertEqual(result.status, "protocol_error", result.error)
                self.assertIn(expected, result.error)

    def test_a_mismatched_request_id_is_refused(self):
        client, _ = client_with({"request_id": "someone-else", "status": "ok", "text": "x"})
        result = client.execute("go", request_id="mine")
        self.assertEqual(result.status, "protocol_error")
        self.assertIn("someone-else", result.error)
        self.assertIn("mine", result.error)

    def test_a_missing_request_id_in_the_response_is_tolerated(self):
        client, _ = client_with({"status": "ok", "text": "x"})
        result = client.execute("go", request_id="given-id")
        self.assertEqual(result.request_id, "given-id")
        self.assertTrue(result.ok)

    def test_error_statuses_keep_their_text_out_of_the_result_text(self):
        client, _ = client_with({"request_id": "r", "status": "timeout"})
        result = client.execute("go", request_id="r")
        self.assertEqual(result.status, "timeout")
        self.assertEqual(result.text, "")
        self.assertTrue(result.may_fall_back)
        self.assertIn("status=timeout", result.report)

    def test_rejected_responses_carry_the_sidecar_errors(self):
        client, _ = client_with({"status": "rejected", "errors": ["prompt must be a non-empty string"]})
        result = client.execute("go")
        self.assertEqual(result.status, "rejected")
        self.assertEqual(result.errors, ("prompt must be a non-empty string",))
        self.assertFalse(result.may_fall_back)

    def test_latency_and_bytes_are_measured(self):
        client, _ = client_with({"status": "ok", "text": "hello"})
        result = client.execute("go")
        self.assertGreaterEqual(result.latency_ms, 0)
        self.assertGreater(result.bytes_read, 10)

    def test_an_oversized_response_is_cut_down_rather_than_consumed(self):
        def transport(request_bytes: bytes) -> tuple[str, int, bool]:
            return json.dumps({"status": "ok", "text": "z" * 5000}), 5000, True

        client = SidecarClient("/run/northstar-codex/sidecar.sock", transport=transport, max_response_bytes=1000)
        result = client.execute("go")
        self.assertTrue(result.truncated)
        self.assertIn("truncated", json.dumps(result.as_dict()))

    def test_probe_uses_a_short_bounded_deadline(self):
        client, sent = client_with({"status": "ok", "text": "OK"})
        result = client.probe()
        self.assertTrue(result.ok)
        timeout = json.loads(sent[0])["timeout_ms"]
        self.assertLessEqual(timeout, 10_000)
        self.assertGreaterEqual(timeout, SIDECAR_MIN_TIMEOUT_MS)


class ResultShapeTests(unittest.TestCase):
    def test_as_dict_reports_only_what_a_host_needs(self):
        result = SidecarResult(request_id="r", status="ok", text="answer", latency_ms=4, bytes_read=20)
        payload = result.as_dict()
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["text"], "answer")
        self.assertEqual(payload["chars"], 6)
        self.assertFalse(payload["fallback_allowed"])
        self.assertNotIn("truncated", payload)
        failure = SidecarResult(request_id="r", status="transport_unavailable", error="gone")
        self.assertNotIn("text", failure.as_dict())
        self.assertTrue(failure.as_dict()["fallback_allowed"])
        self.assertEqual(failure.as_dict()["error"], "gone")

    def test_report_reads_like_a_log_line(self):
        result = SidecarResult(status="internal_error", error="codex binary missing", errors=["a", "b"])
        self.assertEqual(result.report, "sidecar status=internal_error | a; b | codex binary missing")


class ToolAdapterTests(unittest.TestCase):
    def test_execute_tool_wraps_success_for_the_model(self):
        client, _ = client_with({"status": "ok", "text": "the file is fine"})
        result = client.execute_tool(prompt="check the file")
        self.assertIsInstance(result, ToolResult)
        self.assertFalse(result.is_error)
        self.assertEqual(result.content["status"], "ok")
        self.assertEqual(result.content["text"], "the file is fine")
        self.assertEqual(result.data["chars"], len("the file is fine"))

    def test_execute_tool_surfaces_failure_as_an_error_result(self):
        client, _ = client_with({"status": "codex_error", "error": "exit 1"})
        result = client.execute_tool(prompt="go")
        self.assertTrue(result.is_error)
        self.assertIn("status=codex_error", result.content["report"])
        self.assertEqual(result.data["status"], "codex_error")
        self.assertEqual(result.data["chars"], 0)

    def test_execute_tool_validates_before_the_socket(self):
        client, sent = client_with({"status": "ok", "text": "x"})
        for prompt in (None, 5, ["a"], {"a": 1}):
            with self.subTest(prompt=prompt):
                result = client.execute_tool(prompt=prompt)
                self.assertTrue(result.is_error)
                self.assertIn("prompt must be a string", result.text())
        for timeout in (True, "1000", 1.5):
            with self.subTest(timeout=timeout):
                result = client.execute_tool(prompt="go", timeout_ms=timeout)
                self.assertTrue(result.is_error)
                self.assertIn("timeout_ms must be an integer", result.text())
        self.assertEqual(sent, [])

    def test_the_tool_is_registered_only_when_a_socket_is_configured(self):
        spec = codex_tool_spec()
        self.assertEqual(spec.name, "CodexReadOnly")
        self.assertFalse(spec.is_mutating)
        self.assertEqual(spec.kind, "read")
        self.assertEqual(spec.input_schema["required"], ["prompt"])
        self.assertNotIn("CodexReadOnly", build_default_registry().names())

    def test_the_handler_needs_a_client_in_the_context(self):
        spec = codex_tool_spec()
        bare = spec.handler({"prompt": "go"}, ToolContext())
        self.assertTrue(bare.is_error)
        self.assertIn("no sidecar client", bare.text())
        client, _ = client_with({"status": "ok", "text": "answered"})
        attached = ToolContext(services={"sidecar": client})
        answered = spec.handler({"prompt": "go"}, attached)
        self.assertFalse(answered.is_error)
        self.assertEqual(answered.content["text"], "answered")


if __name__ == "__main__":
    unittest.main()
