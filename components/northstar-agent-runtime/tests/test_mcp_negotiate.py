"""Protocol-generation handling: the ``server/discover`` probe, version selection,
per-request ``_meta``, and the fallback rules that decide when a server is legacy.

The pure half is arithmetic on spec text; the subprocess half is the part that
actually matters, because an era determination is only worth anything if the bytes on
the wire change with it.
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

from cli import main
from mcp_client import McpError, McpStdioClient
from mcp_negotiate import (
    DISCOVER_METHOD,
    ELICITATION_METHOD,
    LEGACY_VERSIONS,
    META_CLIENT_CAPABILITIES,
    META_CLIENT_INFO,
    META_PROTOCOL_VERSION,
    MODERN_VERSION,
    RESULT_COMPLETE,
    RESULT_INPUT_REQUIRED,
    EraDecision,
    client_capabilities,
    decide_era,
    input_requests,
    request_meta,
    request_state,
    result_type,
    retry_params,
    select_version,
)

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "mcp_mrtr_server.py"
LEGACY_FIXTURE = Path(__file__).resolve().parent / "fixtures" / "mcp_echo_server.py"


class SelectVersionTests(unittest.TestCase):
    def test_the_newest_mutual_version_wins_in_our_order(self):
        self.assertEqual(select_version([LEGACY_VERSIONS[1], MODERN_VERSION, LEGACY_VERSIONS[0]]), MODERN_VERSION)
        self.assertEqual(select_version(["2024-11-05", "2025-11-25"]), "2025-11-25")

    def test_nothing_in_common_is_none_rather_than_a_favourite_date(self):
        # A client that "tries its newest anyway" turns an incompatibility into a
        # confusing second-round failure; None keeps the failure where it started.
        self.assertIsNone(select_version(["2099-01-01"]))
        self.assertIsNone(select_version([]))
        self.assertIsNone(select_version(None))
        self.assertIsNone(select_version([None, {"nope": 1}, 3.5]))  # junk is not a version
        self.assertEqual(select_version([MODERN_VERSION, "2099-01-01"]), MODERN_VERSION)

    def test_the_preference_is_overridable_for_an_embedder_that_pins_a_version(self):
        self.assertEqual(select_version(["2024-11-05", "2025-11-25"], prefer=("2024-11-05",)), "2024-11-05")


class CapabilitiesTests(unittest.TestCase):
    def test_elicitation_is_advertised_only_with_an_approver(self):
        # This is the whole governance trick: a server MUST NOT send an input request
        # the client did not declare, so an unattended run never receives the question.
        self.assertNotIn("elicitation", client_capabilities(can_elicit=False))
        self.assertEqual(client_capabilities(can_elicit=True)["elicitation"], {})

    def test_roots_are_a_separate_opt_in(self):
        self.assertNotIn("roots", client_capabilities(can_elicit=True))
        self.assertIn("roots", client_capabilities(can_elicit=True, can_list_roots=True))

    def test_request_meta_uses_the_namespaced_keys(self):
        meta = request_meta(
            protocol_version=MODERN_VERSION,
            client_info={"name": "x", "version": "1"},
            capabilities={"tools": {}},
        )
        self.assertEqual(
            set(meta),
            {META_PROTOCOL_VERSION, META_CLIENT_INFO, META_CLIENT_CAPABILITIES},
        )
        self.assertEqual(meta[META_PROTOCOL_VERSION], MODERN_VERSION)
        self.assertEqual(meta[META_CLIENT_INFO], {"name": "x", "version": "1"})


class DecideEraTests(unittest.TestCase):
    def test_a_discover_answer_means_modern(self):
        decision = decide_era({"supportedVersions": [MODERN_VERSION, LEGACY_VERSIONS[0]]}, None)
        self.assertEqual((decision.era, decision.version), ("modern", MODERN_VERSION))
        self.assertTrue(decision.modern)
        self.assertIn(DISCOVER_METHOD, decision.reason)

    def test_a_modern_error_with_a_named_version_adopts_it(self):
        decision = decide_era(
            None,
            {"code": -32022, "message": "unsupported", "data": {"supported": [LEGACY_VERSIONS[0]]}},
        )
        self.assertTrue(decision.modern, "only a modern server can produce -32022")
        self.assertEqual(decision.version, LEGACY_VERSIONS[0])

    def test_a_modern_error_without_one_we_share_stays_modern_and_says_so(self):
        decision = decide_era(None, {"code": -32022, "data": {"supported": ["2099-01-01"]}})
        self.assertTrue(decision.modern)
        self.assertEqual(decision.version, MODERN_VERSION)
        self.assertIn("no version we support", decision.reason)

    def test_method_not_found_is_the_legacy_signal(self):
        decision = decide_era(None, {"code": -32601, "message": "method not found"})
        self.assertEqual(decision.era, "legacy")
        self.assertEqual(decision.version, LEGACY_VERSIONS[0])
        self.assertIn("legacy server", decision.reason)

    def test_an_unknown_error_code_is_not_evidence_of_modernity(self):
        # "Some error" is not "a modern error": guessing modern here would send a
        # 2024-era server a request shape it cannot parse, and the operator would see
        # a handshake failure instead of the server's own message.
        self.assertEqual(decide_era(None, {"code": -32603, "message": "internal"}).era, "legacy")

    def test_timeout_and_silence_fall_back_to_the_handshake(self):
        self.assertEqual(decide_era(None, None, timed_out=True).era, "legacy")
        self.assertEqual(decide_era(None, None).era, "legacy")
        self.assertIn("no usable response", decide_era(None, None).reason)

    def test_a_modern_server_that_offers_nothing_we_speak_is_reported_not_retried(self):
        decision = decide_era({"supportedVersions": ["2099-01-01"]}, None)
        self.assertEqual(decision.era, "modern")
        self.assertIn("2099-01-01", decision.reason)

    def test_the_reason_always_names_the_evidence(self):
        for decision in (
            decide_era({"supportedVersions": [MODERN_VERSION]}, None),
            decide_era(None, {"code": -32601, "message": "no"}),
            decide_era(None, None, timed_out=True),
        ):
            self.assertIsInstance(decision, EraDecision)
            self.assertTrue(decision.reason.strip(), "an era call with no reason is a guess")


class MrtrPlanningTests(unittest.TestCase):
    def test_a_missing_result_type_is_complete(self):
        self.assertEqual(result_type({}), RESULT_COMPLETE)
        self.assertEqual(result_type(None), RESULT_COMPLETE)
        self.assertEqual(result_type({"resultType": "nonsense"}), RESULT_COMPLETE)
        self.assertEqual(result_type({"resultType": RESULT_INPUT_REQUIRED}), RESULT_INPUT_REQUIRED)

    def test_only_well_formed_requests_survive(self):
        result = {
            "resultType": RESULT_INPUT_REQUIRED,
            "inputRequests": {
                "ok": {"method": ELICITATION_METHOD, "params": {"mode": "form"}},
                "": {"method": ELICITATION_METHOD, "params": {}},
                "no_params": {"method": ELICITATION_METHOD},
                7: {"method": ELICITATION_METHOD, "params": {}},
            },
        }
        self.assertEqual(list(input_requests(result)), ["ok"])
        self.assertEqual(input_requests({"resultType": RESULT_COMPLETE, "inputRequests": result["inputRequests"]}), {})

    def test_retry_params_echo_state_only_when_there_was_one(self):
        # An empty-string state invented by the client fails the server's integrity
        # check in a way that looks like a server bug.
        plain = retry_params(tool_name="t", arguments={"a": 1}, input_responses={}, state=None)
        self.assertNotIn("requestState", plain)
        self.assertEqual(plain["arguments"], {"a": 1})
        echoed = retry_params(tool_name="t", arguments={"a": 1}, input_responses={"k": {"action": "accept"}}, state="s2")
        self.assertEqual(echoed["requestState"], "s2")
        self.assertEqual(echoed["inputResponses"], {"k": {"action": "accept"}})

    def test_state_is_only_a_string_and_arguments_are_copied(self):
        self.assertEqual(request_state({"requestState": {"no": 1}}), None)
        self.assertEqual(request_state({"requestState": "opaque"}), "opaque")
        arguments = {"a": 1}
        params = retry_params(tool_name="t", arguments=arguments, input_responses={}, state=None)
        params["arguments"]["a"] = 2
        self.assertEqual(arguments["a"], 1, "a retry must not alias the caller's arguments")


class NegotiationSubprocessTests(unittest.TestCase):
    """What the client actually puts on the wire, read back from the fixture."""

    def connect(self, *, mode: str, fixture: Path = FIXTURE, **kwargs: object) -> McpStdioClient:
        wire = Path(tempfile.mkdtemp(prefix="nsar-mcpwire-")) / "wire.jsonl"
        saved = dict(os.environ)
        os.environ.update({"MRTR_SERVER_MODE": mode, "MRTR_SERVER_WIRE": str(wire)})
        try:
            client = McpStdioClient("demo", [sys.executable, str(fixture)], timeout_ms=8_000, **kwargs)  # type: ignore[arg-type]
            client.connect()
        finally:
            os.environ.clear()
            os.environ.update(saved)
        client._wire_path = str(wire)  # noqa: SLF001 - test-local bookkeeping
        return client

    def wire(self, client: McpStdioClient) -> list[dict]:
        return [json.loads(line) for line in Path(client._wire_path).read_text(encoding="utf-8").splitlines() if line]

    def test_probe_is_the_first_request_and_declares_the_version(self):
        client = self.connect(mode="discover")
        try:
            first = self.wire(client)[0]
            self.assertEqual(first["method"], DISCOVER_METHOD)
            self.assertEqual(first["meta"][META_PROTOCOL_VERSION], MODERN_VERSION)
            self.assertEqual(first["meta"][META_CLIENT_INFO]["name"], "northstar-agent-runtime")
            self.assertEqual(client.era, "modern")
            self.assertEqual(client.protocol_version, MODERN_VERSION)
            self.assertIn("mutually supported version", client.negotiation)
        finally:
            client.close()

    def test_every_request_after_the_probe_carries_the_same_meta(self):
        client = self.connect(mode="discover")
        try:
            client.call_tool("echo", {"text": "x"})
            entries = self.wire(client)
            self.assertGreater(len(entries), 1)
            for entry in entries:
                self.assertEqual(entry["meta"][META_PROTOCOL_VERSION], MODERN_VERSION)
                self.assertEqual(entry["meta"][META_CLIENT_CAPABILITIES], {"tools": {}})
        finally:
            client.close()

    def test_a_refused_version_is_adopted_instead_of_retried(self):
        client = self.connect(mode="reject-then-discover")
        try:
            self.assertEqual(client.era, "modern")
            self.assertEqual(client.protocol_version, LEGACY_VERSIONS[0])
            self.assertIn("modern error", client.negotiation)
            # The correction applies to the work, not to the probe: every later request
            # names the version the server said it speaks.
            for entry in self.wire(client)[1:]:
                self.assertEqual(entry["meta"][META_PROTOCOL_VERSION], LEGACY_VERSIONS[0])
        finally:
            client.close()

    def test_an_unanswered_probe_falls_back_to_the_handshake(self):
        client = self.connect(mode="legacy-only")
        try:
            self.assertEqual(client.era, "legacy")
            self.assertEqual(client.protocol_version, LEGACY_VERSIONS[0])
            self.assertIn("legacy server", client.negotiation)
            methods = [entry["method"] for entry in self.wire(client)]
            # The probe still happens - that is what "fallback" means - and it is the
            # only request that declares a version before the era is known.
            self.assertEqual(methods[0], DISCOVER_METHOD)
            self.assertEqual(methods[1], "initialize")
            self.assertIn("notifications/initialized", methods)
            self.assertEqual(client.tool_names(), ("echo", "needs_input", "needs_password"))
        finally:
            client.close()

    def test_the_legacy_generation_sends_no_per_request_meta(self):
        # Attaching _meta to a 2024/2025 payload is a sure way to be rejected by a
        # strict server, and the handshake already declared everything.
        client = self.connect(mode="legacy-only")
        try:
            client.call_tool("echo", {"text": "x"})
            for entry in self.wire(client):
                if entry["method"] == DISCOVER_METHOD:
                    continue
                self.assertEqual(entry["meta"], {}, f"{entry['method']} carried per-request metadata on the legacy era")
                self.assertNotIn("_meta", entry["params"])
        finally:
            client.close()

    def test_the_older_echo_server_still_works_unchanged(self):
        # Backward compatibility is the point of the fallback, so it is asserted
        # against the fixture that predates this whole generation.
        saved = dict(os.environ)
        os.environ.pop("MRTR_SERVER_MODE", None)
        os.environ.pop("MRTR_SERVER_WIRE", None)
        try:
            client = McpStdioClient("old", [sys.executable, str(LEGACY_FIXTURE)], timeout_ms=8_000)
            client.connect()
        finally:
            os.environ.clear()
            os.environ.update(saved)
        try:
            self.assertEqual(client.era, "legacy")
            result = client.call_tool("echo", {"text": "still fine"})
            self.assertFalse(result.is_error)
            self.assertEqual(result.text(), "echo:still fine")
            self.assertTrue(client.call_tool("needs_input", {}).is_error, "that tool belongs to the other fixture")
        finally:
            client.close()

    def test_a_modern_only_server_on_the_legacy_fallback_fails_loudly(self):
        # ``no-discover`` refuses the probe *and* the handshake: the client must report
        # the server's own error, not a timeout the operator would debug for an hour.
        saved = dict(os.environ)
        os.environ["MRTR_SERVER_MODE"] = "no-discover"
        try:
            client = McpStdioClient("demo", [sys.executable, str(FIXTURE)], timeout_ms=8_000)
            with self.assertRaises(McpError) as caught:
                client.connect()
        finally:
            os.environ.clear()
            os.environ.update(saved)
        self.assertIn("modern-only", str(caught.exception))
        self.assertEqual(client._proc, None, "a failed connection leaves no child process behind")

    def test_pinning_protocol_skips_the_probe_entirely(self):
        # Pinning is for the operator who already knows: no probe, no guessing, and no
        # chance of a modern server being handed a handshake it must refuse.
        pinned = self.connect(mode="legacy-only", protocol="legacy")
        try:
            self.assertEqual([entry["method"] for entry in self.wire(pinned)][0], "initialize")
            self.assertIn("--mcp-protocol legacy", pinned.negotiation)
        finally:
            pinned.close()
        modern = self.connect(mode="discover", protocol="modern")
        try:
            methods = [entry["method"] for entry in self.wire(modern)]
            self.assertEqual(methods[0], "tools/list")
            self.assertNotIn("initialize", methods)
            self.assertNotIn(DISCOVER_METHOD, methods)
            self.assertIn("--mcp-protocol modern", modern.negotiation)
        finally:
            modern.close()

    def test_an_unknown_protocol_name_is_a_configuration_error(self):
        with self.assertRaises(ValueError):
            McpStdioClient("demo", ["true"], protocol="guess")

    def test_round_cap_is_bounded_rather_than_zero_or_infinite(self):
        for bad in (0, -1, 9):
            with self.assertRaises(ValueError):
                McpStdioClient("demo", ["true"], max_input_rounds=bad)
        self.assertEqual(McpStdioClient("demo", ["true"], max_input_rounds=8).max_input_rounds, 8)

    def test_workspace_root_is_normalised_to_an_absolute_path(self):
        client = McpStdioClient("demo", ["true"], workspace_root=".")
        self.assertTrue(client.workspace_root.startswith("/") or ":" in client.workspace_root)
        self.assertEqual(McpStdioClient("demo", ["true"]).workspace_root, "")


class DryRunDoesNotTalkToTheServerTests(unittest.TestCase):
    """The era is only ever decided by a live peer, so a dry run must not spawn one."""

    def test_dry_run_reports_servers_without_probing_them(self):
        wire = Path(tempfile.mkdtemp(prefix="nsar-mcpdry-")) / "wire.jsonl"
        saved = dict(os.environ)
        os.environ.update({"MRTR_SERVER_MODE": "discover", "MRTR_SERVER_WIRE": str(wire)})
        out, err = io.StringIO(), io.StringIO()
        saved_stdin, sys.stdin = sys.stdin, io.StringIO("")
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = main(
                    [
                        "run",
                        "--workspace",
                        tempfile.gettempdir(),
                        "--prompt",
                        "hi",
                        "--scripted-text",
                        "x",
                        "--mcp-server",
                        f"demo={sys.executable} {FIXTURE}",
                        "--dry-run",
                    ]
                )
        finally:
            sys.stdin = saved_stdin
            os.environ.clear()
            os.environ.update(saved)
        self.assertEqual(code, 0, err.getvalue())
        self.assertIn("not connected in dry-run", out.getvalue())
        self.assertFalse(wire.exists(), "a dry run must not speak to the server")


if __name__ == "__main__":
    unittest.main()
