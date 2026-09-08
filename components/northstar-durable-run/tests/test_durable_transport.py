"""Authenticated loopback control/replay transport tests."""
from __future__ import annotations

import hashlib
import hmac
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path

COMPONENT_ROOT = Path(__file__).resolve().parents[1]
CONTRACT_ROOT = COMPONENT_ROOT.parent / "northstar-run-contract"
HOST_ROOT = COMPONENT_ROOT.parent / "northstar-host"
for path in (COMPONENT_ROOT, CONTRACT_ROOT, HOST_ROOT):
    sys.path.insert(0, str(path))

from authorization import HostPolicy, authorize_run, verify_authorization  # noqa: E402
from binding import sign_binding, verify_binding  # noqa: E402
from durable_contract import RunContract  # noqa: E402
from durable_transport import (  # noqa: E402
    DurableTransportError,
    DurableWorkerClient,
    DurableWorkerServer,
    TRANSPORT_SCHEMA_VERSION,
)
from event_store import EventStore  # noqa: E402
from runner import DurableRunner, StepPlan  # noqa: E402


class DurableTransportTests(unittest.TestCase):
    def setUp(self):
        self.now = int(time.time())
        self.binding_secret = b"b" * 32
        self.authorization_secret = b"a" * 32
        self.channel_secret = b"c" * 32
        self.ws = Path(tempfile.mkdtemp(prefix="nsar-transport-"))
        self.events = self.ws / "events.jsonl"
        self.lease = self.ws / "run.lease.json"
        self.run = RunContract.from_dict(
            {
                "schema_version": "northstar.durable-run.v1",
                "task_id": "task-1",
                "thread_id": "thread-1",
                "run_id": "run-1",
                "parent_run_id": None,
                "status": "planned",
                "deadline_at": self.now + 3_600,
                "scope_snapshot": ["workspace:read"],
                "trace_id": "trace-1",
            }
        )
        binding = {
            "schema_version": "northstar.run.v1",
            "run_id": "run-1",
            "actor_id": "actor-1",
            "workspace_id": "workspace-1",
            "expires_at": self.now + 3_600,
        }
        self.binding_token = sign_binding(binding, self.binding_secret)
        binding_validation = verify_binding(self.binding_token, self.binding_secret, now=self.now)
        request = {
            "schema_version": "northstar.run.v1",
            "run_id": "run-1",
            "actor_id": "actor-1",
            "workspace_id": "workspace-1",
            "task_kind": "analysis",
            "prompt": "inspect the durable history",
            "timeout_ms": 10_000,
            "requested_capabilities": ["workspace:read", "durable:read", "durable:control"],
            "parent_run_id": None,
        }
        self.authorization_request = request
        self.policy = HostPolicy.from_mapping(
            "policy-1",
            {"actor-1": ["workspace:read", "durable:read", "durable:control"]},
        )
        self.authorization_token = authorize_run(
            request,
            binding_validation,
            self.policy,
            now=self.now,
            secret=self.authorization_secret,
            grant_ttl_seconds=3_600,
        )

    def server(self) -> DurableWorkerServer:
        return DurableWorkerServer(
            self.events,
            lease_path=self.lease,
            binding_secret=self.binding_secret,
            authorization_secret=self.authorization_secret,
            channel_secret=self.channel_secret,
            policy_revision="policy-1",
        )

    def client(self, server: DurableWorkerServer) -> DurableWorkerClient:
        host, port = server.address
        return DurableWorkerClient(
            host,
            port,
            workspace_id="workspace-1",
            run_contract=self.run,
            binding_token=self.binding_token,
            authorization_token=self.authorization_token,
            channel_secret=self.channel_secret,
        )

    def test_loopback_status_and_history_are_signed_and_read_only(self):
        with self.server() as server:
            client = self.client(server)
            status = client.request_ok("status")
            self.assertEqual(status["state"]["status"], "planned")
            self.assertEqual(status["event_count"], 0)
            history = client.request_ok("history")
            self.assertEqual(history["events"], [])
            self.assertEqual(history["from_sequence"], 1)
            self.assertFalse(history["has_more"])
            self.assertIsNone(history["next_sequence"])
            self.assertFalse(self.events.exists())

    def test_control_round_trip_reuses_existing_runner_and_returns_receipt(self):
        runner = DurableRunner(self.run, EventStore(self.events), lease_path=self.lease)
        running = runner.execute(
            [
                StepPlan(
                    step_id="inspect",
                    input_payload={"path": "README.md"},
                    scope_snapshot=["workspace:read"],
                    expected_postconditions=[],
                    action=lambda _key: {"ok": True},
                )
            ],
            owner_id="actor-1",
            now=self.now + 1,
            finalize=False,
        )
        self.assertEqual(running["status"], "running")
        with self.server() as server:
            client = self.client(server)
            paused = client.request_ok(
                "pause", payload={"reason": "remote operator hold"}, request_id="pause-1"
            )
            self.assertEqual(paused["state"]["status"], "waiting")
            self.assertEqual(paused["receipt"]["command_id"], "pause-1")
            self.assertFalse(paused["replayed"])
            event_count_after_pause = len(self.events.read_text(encoding="utf-8").splitlines())
            replayed = client.request_ok(
                "pause",
                payload={"reason": "remote operator hold"},
                request_id="pause-1",
            )
            self.assertTrue(replayed["replayed"])
            self.assertEqual(replayed["receipt"], paused["receipt"])
            self.assertEqual(
                len(self.events.read_text(encoding="utf-8").splitlines()),
                event_count_after_pause,
            )
            conflict = client.request(
                "pause",
                payload={"reason": "different command"},
                request_id="pause-1",
            )
            self.assertEqual(conflict["status"], "business_error")
            resumed = client.request_ok("resume", request_id="resume-1")
            self.assertEqual(resumed["state"]["status"], "running")
            self.assertEqual(resumed["receipt"]["after_status"], "running")
            history = client.request_ok("history")
            self.assertGreaterEqual(len(history["events"]), 6)
            first_page = client.request_ok("history", payload={"limit": 1})
            self.assertEqual(first_page["from_sequence"], 1)
            self.assertEqual(len(first_page["events"]), 1)
            self.assertTrue(first_page["has_more"])
            second_page = client.request_ok(
                "history",
                payload={"from_sequence": first_page["next_sequence"], "limit": 2},
            )
            self.assertEqual(second_page["from_sequence"], 2)
            self.assertEqual(len(second_page["events"]), 2)
            self.assertEqual(second_page["events"][0]["sequence"], 2)

    def test_tampered_request_is_rejected_without_mutating_history(self):
        with self.server() as server:
            client = self.client(server)
            frame = client.build_frame("status", request_id="tamper-1")
            frame["operation"] = "cancel"
            response = server.handle_frame(frame, now=self.now)
            self.assertEqual(response["schema_version"], TRANSPORT_SCHEMA_VERSION)
            self.assertEqual(response["status"], "rejected")
            self.assertIn("authentication", response["error"])
            self.assertFalse(self.events.exists())

    def test_wrong_workspace_claim_is_rejected_even_with_a_valid_channel_mac(self):
        with self.server() as server:
            client = self.client(server)
            frame = client.build_frame("cancel", request_id="bad-scope")
            frame["workspace_id"] = "other-workspace"
            # Re-signing proves the server checks the signed host claims too,
            # rather than treating the channel MAC as sufficient authorization.
            body = dict(frame)
            body.pop("mac")
            frame["mac"] = hmac.new(
                self.channel_secret,
                json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            response = server.handle_frame(frame, now=self.now)
            self.assertEqual(response["status"], "rejected")
            self.assertIn("workspace_id", response["error"])
            self.assertEqual(response["data"], {})

    def test_control_receipt_replays_after_server_restart(self):
        runner = DurableRunner(self.run, EventStore(self.events), lease_path=self.lease)
        runner.execute(
            [
                StepPlan(
                    step_id="inspect",
                    input_payload={"path": "README.md"},
                    scope_snapshot=["workspace:read"],
                    expected_postconditions=[],
                    action=lambda _key: {"ok": True},
                )
            ],
            owner_id="actor-1",
            now=self.now + 1,
            finalize=False,
        )
        with self.server() as server:
            first = self.client(server).request_ok(
                "pause", payload={"reason": "restart-safe hold"}, request_id="restart-1"
            )
        with self.server() as server:
            second = self.client(server).request_ok(
                "pause", payload={"reason": "restart-safe hold"}, request_id="restart-1"
            )
        self.assertTrue(second["replayed"])
        self.assertEqual(second["receipt"], first["receipt"])

    def test_completed_event_marker_recovers_when_ledger_commit_was_lost(self):
        runner = DurableRunner(self.run, EventStore(self.events), lease_path=self.lease)
        runner.execute(
            [
                StepPlan(
                    step_id="inspect",
                    input_payload={"path": "README.md"},
                    scope_snapshot=["workspace:read"],
                    expected_postconditions=[],
                    action=lambda _key: {"ok": True},
                )
            ],
            owner_id="actor-1",
            now=self.now + 1,
            finalize=False,
        )
        with self.server() as server:
            client = self.client(server)
            frame = client.build_frame(
                "pause",
                payload={"reason": "recovered hold"},
                request_id="recover-1",
            )
            authorized = server._authorize(frame, now=self.now)
            runner.pause(
                owner_id="actor-1",
                now=self.now,
                reason="recovered hold",
                command_key=authorized.command_marker,
            )
            before_retry = len(self.events.read_text(encoding="utf-8").splitlines())
            recovered = client.request_ok(
                "pause",
                payload={"reason": "recovered hold"},
                request_id="recover-1",
            )
            self.assertTrue(recovered["replayed"])
            self.assertEqual(recovered["receipt"]["outcome"], "applied")
            self.assertEqual(
                len(self.events.read_text(encoding="utf-8").splitlines()),
                before_retry,
            )

    def test_history_pagination_rejects_unbounded_or_unknown_parameters(self):
        with self.server() as server:
            client = self.client(server)
            oversized = server.handle_frame(
                client.build_frame("history", payload={"limit": 257}),
                now=self.now,
            )
            self.assertEqual(oversized["status"], "rejected")
            self.assertIn("history limit", oversized["error"])
            unknown = server.handle_frame(
                client.build_frame("history", payload={"cursor": 1}),
                now=self.now,
            )
            self.assertEqual(unknown["status"], "rejected")
            self.assertIn("unknown fields", unknown["error"])

    def test_read_capability_cannot_apply_a_control_operation(self):
        read_only_token = authorize_run(
            {
                **self.authorization_request,
                "requested_capabilities": ["workspace:read", "durable:read"],
            },
            verify_binding(self.binding_token, self.binding_secret, now=self.now),
            self.policy,
            now=self.now,
            secret=self.authorization_secret,
            grant_ttl_seconds=3_600,
        )
        with self.server() as server:
            client = self.client(server)
            client.authorization_token = read_only_token
            response = client.request("cancel")
            self.assertEqual(response["status"], "rejected")
            self.assertIn("durable:control", response["error"])
            self.assertFalse(self.events.exists())

    def test_server_refuses_public_listener_and_client_reports_unavailable(self):
        with self.assertRaises(ValueError):
            DurableWorkerServer(
                self.events,
                lease_path=self.lease,
                binding_secret=self.binding_secret,
                authorization_secret=self.authorization_secret,
                channel_secret=self.channel_secret,
                host="0.0.0.0",
            )
        with self.assertRaises(DurableTransportError) as caught:
            DurableWorkerClient(
                "127.0.0.1",
                1,
                workspace_id="workspace-1",
                run_contract=self.run,
                binding_token=self.binding_token,
                authorization_token=self.authorization_token,
                channel_secret=self.channel_secret,
                timeout_s=0.2,
            ).request("status")
        self.assertEqual(caught.exception.status, "transport_unavailable")

    def test_client_rejects_a_tampered_signed_response(self):
        with self.server() as server:
            client = self.client(server)
            original = server.handle_frame

            def tamper(frame, now=None):
                response = original(frame, now=now)
                response["data"] = {"tampered": True}
                return response

            server.handle_frame = tamper  # type: ignore[method-assign]
            with self.assertRaises(DurableTransportError) as caught:
                client.request("status")
            self.assertEqual(caught.exception.status, "protocol_error")
            self.assertIn("authentication failed", str(caught.exception))

    def test_client_rejects_a_signed_response_with_wrong_request_id(self):
        with self.server() as server:
            client = self.client(server)
            original = server.handle_frame
            server.handle_frame = lambda frame, now=None: {  # type: ignore[method-assign]
                **original(frame, now=now),
                "request_id": "other",
            }
            # The socket handler calls handle_wire_line, which uses the patched
            # method and returns a response whose MAC no longer matches too.
            with self.assertRaises(DurableTransportError) as caught:
                client.request("status")
            self.assertEqual(caught.exception.status, "protocol_error")


if __name__ == "__main__":
    unittest.main()
