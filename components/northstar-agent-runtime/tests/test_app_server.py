"""T25 local app-server: host-owned async runs, auth, idempotency and bounds."""
from __future__ import annotations

import json
import tempfile
import threading
import unittest
from pathlib import Path

import support  # noqa: F401
from support import RuntimeTestCase

from app_server import (
    APP_PROTOCOL,
    AppClient,
    AppServer,
    AppServerError,
    RunManager,
    _mac,
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
            started = client.start(request_id="wire-start", actor_id="owner", prompt="hello")
            final = manager.wait(run_id=started["run_id"], actor_id="owner")
            status = client.status(request_id="wire-status", actor_id="owner", run_id=started["run_id"])
            page = client.events(request_id="wire-events", actor_id="owner", run_id=started["run_id"])
            server.close()
            thread.join(timeout=2)
        self.assertEqual(final["status"], "success")
        self.assertEqual(status["status"], "success")
        self.assertEqual(page["events"][-1]["event"]["subtype"], "success")

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
