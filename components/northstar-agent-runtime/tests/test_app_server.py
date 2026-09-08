"""T25 local app-server: host-owned async runs, auth, idempotency and bounds."""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path

import support  # noqa: F401
from support import RuntimeTestCase

from app_server import (
    APP_CAPABILITY_SCHEMA,
    APP_PROTOCOL,
    MAX_WAIT_MS,
    AppClient,
    AppServer,
    AppServerError,
    RunContext,
    RunManager,
    _mac,
    validate_capabilities,
)
from loop import AgentRuntime, RuntimeConfig
from providers.base import Generation, Provider, TextBlock
from providers.scripted import ScriptedProvider


class BlockingProvider(Provider):
    name = "blocking-test"

    def __init__(self) -> None:
        self.started = threading.Event()
        self.release = threading.Event()

    def generate(self, request):
        self.started.set()
        if not self.release.wait(timeout=5):
            raise TimeoutError("test provider was not released")
        return Generation(content=(TextBlock(text="finished"),), model=self.name)


class RunManagerTests(RuntimeTestCase):
    def factory(self, workspace: str):
        def build():
            return AgentRuntime(
                provider=ScriptedProvider([{"text": "done"}]),
                config=RuntimeConfig(workspace=workspace),
            )

        return build

    def test_context_aware_factory_receives_host_run_context(self):
        seen: dict[str, object] = {}
        workspace = str(self.workspace())

        def factory(context: RunContext):
            seen.update(
                run_id=context.run_id,
                request_id=context.request_id,
                actor_id=context.actor_id,
                prompt=context.prompt,
            )
            return AgentRuntime(
                provider=ScriptedProvider([{"text": "context received"}]),
                config=RuntimeConfig(workspace=workspace),
            )

        manager = RunManager(factory)
        started = manager.start(request_id="request-context", actor_id="actor-context", prompt="hello context")
        final = manager.wait(run_id=started["run_id"], actor_id="actor-context")
        self.assertEqual(final["status"], "success")
        self.assertEqual(seen, {
            "run_id": started["run_id"],
            "request_id": "request-context",
            "actor_id": "actor-context",
            "prompt": "hello context",
        })

    def test_factory_failures_do_not_echo_host_exception_text(self):
        secret = "provider-secret-token:/srv/private/workspace"

        def factory():
            raise RuntimeError(secret)

        manager = RunManager(factory)
        started = manager.start(request_id="request-failure", actor_id="owner", prompt="hello")
        final = manager.wait(run_id=started["run_id"], actor_id="owner")
        self.assertEqual(final["status"], "failed")
        self.assertEqual(final["result"]["errors"], ["background runtime failure: RuntimeError"])
        self.assertNotIn(secret, final["result"]["errors"][0])

    def test_start_is_idempotent_and_events_are_bounded(self):
        workspace = str(self.workspace())
        manager = RunManager(self.factory(workspace), max_event_retention=32)
        first = manager.start(request_id="request-1", actor_id="actor-1", prompt="hello")
        second = manager.start(request_id="request-1", actor_id="actor-1", prompt="hello")
        self.assertEqual(first["run_id"], second["run_id"])
        self.assertTrue(second["replayed"])
        final = manager.wait(run_id=first["run_id"], actor_id="actor-1")
        self.assertEqual(final["status"], "success")
        page = manager.events(run_id=first["run_id"], actor_id="actor-1")
        self.assertFalse(page["has_more"])
        self.assertEqual([entry["event"]["type"] for entry in page["events"]], ["system", "assistant", "result"])
        with self.assertRaises(AppServerError) as conflict:
            manager.start(request_id="request-1", actor_id="actor-1", prompt="changed")
        self.assertEqual(conflict.exception.code, "idempotency_conflict")

    def test_actor_binding_is_fail_closed(self):
        manager = RunManager(self.factory(str(self.workspace())))
        started = manager.start(request_id="request-2", actor_id="owner", prompt="hello")
        with self.assertRaises(AppServerError) as denied:
            manager.status(run_id=started["run_id"], actor_id="other")
        self.assertEqual(denied.exception.code, "authorization_denied")

    def test_old_event_cursor_is_rejected_after_bounded_retention(self):
        manager = RunManager(self.factory(str(self.workspace())), max_event_retention=2)
        started = manager.start(request_id="request-3", actor_id="owner", prompt="hello")
        manager.wait(run_id=started["run_id"], actor_id="owner")
        status = manager.status(run_id=started["run_id"], actor_id="owner")
        self.assertGreater(status["first_sequence"], 0)
        with self.assertRaises(AppServerError) as expired:
            manager.events(run_id=started["run_id"], actor_id="owner", from_sequence=0)
        self.assertEqual(expired.exception.code, "cursor_expired")

    def test_cancel_is_cooperative_and_never_kills_the_provider_thread(self):
        provider = BlockingProvider()

        def factory():
            return AgentRuntime(
                provider=provider,
                config=RuntimeConfig(workspace=str(self.workspace())),
            )

        manager = RunManager(factory)
        started = manager.start(request_id="request-4", actor_id="owner", prompt="wait")
        self.assertTrue(provider.started.wait(timeout=2))
        pending = manager.cancel(run_id=started["run_id"], actor_id="owner")
        self.assertTrue(pending["cancel_requested"])
        provider.release.set()
        final = manager.wait(run_id=started["run_id"], actor_id="owner")
        self.assertEqual(final["status"], "cancelled")
        self.assertEqual(final["result"]["subtype"], "error_cancelled")

    def test_shutdown_requests_cancellation_but_does_not_force_kill(self):
        provider = BlockingProvider()

        def factory():
            return AgentRuntime(
                provider=provider,
                config=RuntimeConfig(workspace=str(self.workspace())),
            )

        manager = RunManager(factory)
        started = manager.start(request_id="request-5", actor_id="owner", prompt="wait")
        self.assertTrue(provider.started.wait(timeout=2))
        pending = manager.shutdown(timeout=0)
        self.assertEqual(pending[0]["status"], "running")
        self.assertTrue(pending[0]["cancel_requested"])
        provider.release.set()
        final = manager.wait(run_id=started["run_id"], actor_id="owner")
        self.assertEqual(final["status"], "cancelled")


class AppWireTests(RuntimeTestCase):
    SECRET = b"app-server-test-channel-secret"

    def manager(self):
        workspace = str(self.workspace())

        def factory():
            return AgentRuntime(
                provider=ScriptedProvider([{"text": "done"}]),
                config=RuntimeConfig(workspace=workspace),
            )

        return RunManager(factory)

    def test_authenticated_unix_socket_round_trip(self):
        manager = self.manager()
        with tempfile.TemporaryDirectory() as directory:
            socket_path = Path(directory) / "app.sock"
            server = AppServer(manager, channel_secret=self.SECRET, socket_path=socket_path)
            thread = server.start()
            server.wait_ready(timeout=2)
            self.assertTrue(socket_path.exists())
            client = AppClient(socket_path, channel_secret=self.SECRET)
            description = client.describe(request_id="wire-describe", actor_id="owner")
            self.assertEqual(description["capabilities"]["schema"], APP_CAPABILITY_SCHEMA)
            self.assertIn("run.wait", description["capabilities"]["operations"])
            self.assertEqual(description["capabilities"]["cancellation"], "cooperative")
            self.assertNotIn("provider", description["capabilities"])
            self.assertNotIn("workspace", description["capabilities"])
            started = client.start(request_id="wire-start", actor_id="owner", prompt="hello")
            final = client.wait(request_id="wire-wait", actor_id="owner", run_id=started["run_id"], timeout_ms=2000)
            status = client.status(request_id="wire-status", actor_id="owner", run_id=started["run_id"])
            page = client.events(request_id="wire-events", actor_id="owner", run_id=started["run_id"])
            server.close()
            thread.join(timeout=2)
        self.assertEqual(final["status"], "success")
        self.assertEqual(status["status"], "success")
        self.assertEqual(page["events"][-1]["event"]["subtype"], "success")

    def test_completed_wire_requests_replay_and_conflicting_ids_fail_closed(self):
        server = AppServer(self.manager(), channel_secret=self.SECRET)
        request = {
            "protocol": APP_PROTOCOL,
            "op": "app.describe",
            "request_id": "wire-replay",
            "actor_id": "owner",
        }
        request["auth"] = _mac(request, self.SECRET)
        first = server.handle_wire_line(json.dumps(request))
        second = server.handle_wire_line(json.dumps(request))
        self.assertEqual(second, first)
        self.assertEqual(first["capabilities"]["request_replay"], "completed_response")

        conflict = dict(request, actor_id="other")
        conflict["auth"] = _mac({key: value for key, value in conflict.items() if key != "auth"}, self.SECRET)
        response = server.handle_wire_line(json.dumps(conflict))
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["code"], "idempotency_conflict")

        operation_conflict = dict(request, op="run.start", prompt="hello")
        operation_conflict["auth"] = _mac(
            {key: value for key, value in operation_conflict.items() if key != "auth"},
            self.SECRET,
        )
        response = server.handle_wire_line(json.dumps(operation_conflict))
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["code"], "idempotency_conflict")

        start_request = {
            "protocol": APP_PROTOCOL,
            "op": "run.start",
            "request_id": "wire-start-marker",
            "actor_id": "owner",
            "prompt": "hello",
        }
        start_request["auth"] = _mac(start_request, self.SECRET)
        started = server.handle_wire_line(json.dumps(start_request))
        status_conflict = {
            "protocol": APP_PROTOCOL,
            "op": "run.status",
            "request_id": "wire-start-marker",
            "actor_id": "owner",
            "run_id": started["run_id"],
        }
        status_conflict["auth"] = _mac(status_conflict, self.SECRET)
        response = server.handle_wire_line(json.dumps(status_conflict))
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["code"], "idempotency_conflict")

    def test_capability_validation_rejects_incompatible_or_sensitive_projection(self):
        with self.assertRaises(AppServerError) as unsupported:
            validate_capabilities({"schema": "other.capabilities.v1"})
        self.assertEqual(unsupported.exception.code, "invalid_response")

        with self.assertRaises(AppServerError) as sensitive:
            validate_capabilities({
                "schema": APP_CAPABILITY_SCHEMA,
                "operations": ["app.describe", "run.start"],
                "max_frame_bytes": 1024,
                "max_prompt_chars": 1,
                "max_event_page": 1,
                "max_wait_ms": 1,
                "event_retention": 1,
                "request_replay": "completed_response",
                "request_replay_retention": 1,
                "cancellation": "cooperative",
                "manager_registry": "in_memory",
                "remote_execution": False,
                "workspace": "/secret/workspace",
            })
        self.assertEqual(sensitive.exception.code, "invalid_response")

    def test_node_consumer_verifies_hmac_and_uses_bounded_wait(self):
        repository = Path(__file__).resolve().parents[3]
        smoke = repository / "examples" / "app-server" / "node_client_smoke.mjs"
        if shutil.which("node") is None or not smoke.is_file():
            self.skipTest("Node.js consumer example is unavailable in this component copy")
        workspace = str(self.workspace())

        def factory():
            return AgentRuntime(
                provider=ScriptedProvider(
                    [{"text": "done"}],
                    default_usage={"input_tokens": 1, "output_tokens": 1},
                ),
                config=RuntimeConfig(workspace=workspace),
            )

        with tempfile.TemporaryDirectory() as directory:
            socket_path = Path(directory) / "app.sock"
            server = AppServer(RunManager(factory), channel_secret=self.SECRET, socket_path=socket_path)
            thread = server.start()
            server.wait_ready(timeout=2)
            try:
                completed = subprocess.run(
                    ["node", str(smoke), str(socket_path), self.SECRET.hex()],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
            finally:
                server.close()
                thread.join(timeout=2)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(json.loads(completed.stdout), {"status": "success", "eventCount": 3})

    def test_server_shutdown_closes_transport_and_requests_cooperative_drain(self):
        provider = BlockingProvider()

        def factory():
            return AgentRuntime(
                provider=provider,
                config=RuntimeConfig(workspace=str(self.workspace())),
            )

        manager = RunManager(factory)
        with tempfile.TemporaryDirectory() as directory:
            socket_path = Path(directory) / "app.sock"
            server = AppServer(manager, channel_secret=self.SECRET, socket_path=socket_path)
            thread = server.start()
            server.wait_ready(timeout=2)
            started = manager.start(request_id="server-shutdown", actor_id="owner", prompt="wait")
            self.assertTrue(provider.started.wait(timeout=2))
            pending = server.shutdown(timeout=0)
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
            self.assertFalse(socket_path.exists())
        self.assertEqual(pending[0]["run_id"], started["run_id"])
        self.assertEqual(pending[0]["status"], "running")
        self.assertTrue(pending[0]["cancel_requested"])
        provider.release.set()
        final = manager.wait(run_id=started["run_id"], actor_id="owner")
        self.assertEqual(final["status"], "cancelled")

    def test_startup_failure_is_reported_by_wait_ready(self):
        with tempfile.TemporaryDirectory() as directory:
            socket_path = Path(directory) / "app.sock"
            socket_path.write_text("do not replace", encoding="utf-8")
            server = AppServer(self.manager(), channel_secret=self.SECRET, socket_path=socket_path)
            thread = server.start()
            with self.assertRaises(AppServerError) as failure:
                server.wait_ready(timeout=2)
            self.assertEqual(failure.exception.code, "socket_exists")
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
            self.assertEqual(socket_path.read_text(encoding="utf-8"), "do not replace")

    def test_tampered_and_unknown_wire_fields_are_rejected(self):
        server = AppServer(self.manager(), channel_secret=self.SECRET)
        duplicate = '{"protocol":"%s","protocol":"%s"}' % (APP_PROTOCOL, APP_PROTOCOL)
        duplicate_response = server.handle_wire_line(duplicate)
        self.assertFalse(duplicate_response["ok"])
        self.assertEqual(duplicate_response["error"]["code"], "invalid_request")

        tampered = {
            "protocol": APP_PROTOCOL,
            "op": "run.start",
            "request_id": "wire-bad",
            "actor_id": "owner",
            "prompt": "hello",
            "auth": "hmac-sha256:" + "0" * 64,
        }
        response = server.handle_wire_line(json.dumps(tampered))
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["code"], "authentication_failed")

        valid = dict(tampered)
        valid["unexpected"] = True
        unsigned = {key: value for key, value in valid.items() if key != "auth"}
        valid["auth"] = _mac(unsigned, self.SECRET)
        response = server.handle_wire_line(json.dumps(valid))
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["code"], "invalid_request")

        wait = {
            "protocol": APP_PROTOCOL,
            "op": "run.wait",
            "request_id": "wire-wait-invalid",
            "actor_id": "owner",
            "run_id": "missing",
            "timeout_ms": MAX_WAIT_MS + 1,
        }
        wait["auth"] = _mac(wait, self.SECRET)
        response = server.handle_wire_line(json.dumps(wait))
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["code"], "invalid_request")

    def test_client_cannot_override_authenticated_request_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            client = AppClient(Path(directory) / "app.sock", channel_secret=self.SECRET)
            with self.assertRaises(ValueError):
                client.call(
                    "run.start",
                    request_id="wire-reserved",
                    actor_id="owner",
                    op="run.status",
                )

    def test_server_never_accepts_wire_selected_provider_or_workspace(self):
        server = AppServer(self.manager(), channel_secret=self.SECRET)
        request = {
            "protocol": APP_PROTOCOL,
            "op": "run.start",
            "request_id": "wire-policy",
            "actor_id": "owner",
            "prompt": "hello",
            "provider": "arbitrary-provider",
        }
        request["auth"] = _mac(request, self.SECRET)
        response = server.handle_wire_line(json.dumps(request))
        self.assertFalse(response["ok"])
        self.assertEqual(response["error"]["code"], "invalid_request")


if __name__ == "__main__":
    unittest.main()
