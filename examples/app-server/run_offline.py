#!/usr/bin/env python3
"""Exercise the experimental local app-server without a model or network.

The host owns the runtime factory, workspace and scripted provider. The client
only sees the bounded prompt/status/events surface and uses a separate request
id for every wire call.
"""
from __future__ import annotations

import sys
import tempfile
import time
from pathlib import Path

RUNTIME_DIR = Path(__file__).resolve().parents[2] / "components" / "northstar-agent-runtime"
sys.path.insert(0, str(RUNTIME_DIR))

from app_server import AppClient, AppServer, RunManager  # noqa: E402
from loop import AgentRuntime, RuntimeConfig  # noqa: E402
from providers.scripted import ScriptedProvider  # noqa: E402

CHANNEL_SECRET = b"northstar-local-app-example-secret"


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="northstar-app-example-") as directory:
        root = Path(directory)
        workspace = root / "workspace"
        workspace.mkdir()
        socket_path = root / "app.sock"

        def runtime_factory() -> AgentRuntime:
            # This seam is host-owned. A wire client cannot replace this
            # provider, workspace, policy or session configuration.
            return AgentRuntime(
                provider=ScriptedProvider([{"text": "offline app-server run complete"}]),
                config=RuntimeConfig(workspace=str(workspace)),
            )

        manager = RunManager(runtime_factory)
        server = AppServer(
            manager,
            channel_secret=CHANNEL_SECRET,
            socket_path=socket_path,
        )
        server_thread = server.start()
        try:
            deadline = time.monotonic() + 2
            while not socket_path.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            if not socket_path.exists():
                raise RuntimeError("local app-server did not create its socket")

            client = AppClient(socket_path, channel_secret=CHANNEL_SECRET)
            started = client.start(request_id="example-start", actor_id="demo", prompt="say hello")
            run_id = started["run_id"]
            status = started
            poll = 0
            while status["status"] not in {"success", "failed", "cancelled"}:
                time.sleep(0.01)
                poll += 1
                status = client.status(
                    request_id=f"example-status-{poll}",
                    actor_id="demo",
                    run_id=run_id,
                )
            events = client.events(
                request_id="example-events",
                actor_id="demo",
                run_id=run_id,
            )
            replay = client.start(
                request_id="example-start",
                actor_id="demo",
                prompt="say hello",
            )

            assert status["status"] == "success"
            assert events["events"][-1]["event"]["subtype"] == "success"
            assert replay["run_id"] == run_id
            assert replay["replayed"] is True
            print(f"status       {status['status']}")
            print(f"run_id       {run_id}")
            print(f"events       {len(events['events'])} retained")
            print("idempotency  replay returned the original run")
            return 0
        finally:
            server.close()
            server_thread.join(timeout=2)


if __name__ == "__main__":
    raise SystemExit(main())
