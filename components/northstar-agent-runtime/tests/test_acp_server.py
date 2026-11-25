"""Tests for the thin Agent Client Protocol (ACP v1) stdio adapter."""
from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import Any

RUNTIME_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = RUNTIME_ROOT.parents[1]
if str(RUNTIME_ROOT) not in sys.path:
    sys.path.insert(0, str(RUNTIME_ROOT))

from _version import __version__
from acp_server import (
    ACP_NOT_INITIALIZED,
    ACP_PROTOCOL_VERSION,
    JSONRPC_INVALID_PARAMS,
    JSONRPC_INVALID_REQUEST,
    JSONRPC_METHOD_NOT_FOUND,
    JSONRPC_PARSE_ERROR,
    MAX_LINE_BYTES,
    AcpServer,
    AcpServerConfig,
    serve_stdio,
)
from providers.base import (
    Generation,
    GenerationRequest,
    Provider,
    TextBlock,
    Usage,
)
from providers.scripted import ScriptedTurn


class _SlowCancelProvider(Provider):
    """Provider that blocks on turn 1 until released, so session/cancel can interrupt."""

    name = "slow-cancel"
    streams = False

    def __init__(self, entered: threading.Event, gate: threading.Event) -> None:
        self.model = "claude-sonnet-4-5"
        self.entered = entered
        self.gate = gate
        self.calls = 0

    def generate(self, request: GenerationRequest) -> Generation:
        self.calls += 1
        self.entered.set()
        self.gate.wait(timeout=5.0)
        return Generation(
            content=(TextBlock("turn completed after gate"),),
            stop_reason="end_turn",
            usage=Usage(input_tokens=10, output_tokens=5),
        )


def _offline_config(workspace: Path, **overrides: Any) -> AcpServerConfig:
    defaults: dict[str, Any] = {
        "workspace": str(workspace),
        "provider": "scripted",
        "permission_mode": "default",
        "shell_backend": "process",
        "shell_seccomp": "off",
        "shell_capdrop": "off",
        "workspace_agents": False,
    }
    defaults.update(overrides)
    return AcpServerConfig(**defaults)


class AcpProtocolAndGovernanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        self.ws = self.root / "repo"
        self.ws.mkdir()
        (self.ws / "notes.txt").write_text("alpha\nbeta\n", encoding="utf-8")
        self.outside = self.root / "outside"
        self.outside.mkdir()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_requires_initialize_and_returns_acp_v1_capabilities(self) -> None:
        emitted: list[dict[str, Any]] = []
        server = AcpServer(_offline_config(self.ws), emit=emitted.append)

        # Calling session/new before initialize must fail closed.
        pre = server.handle_message(
            {"jsonrpc": "2.0", "id": 1, "method": "session/new", "params": {"cwd": str(self.ws)}}
        )
        assert pre is not None
        self.assertEqual(pre["error"]["code"], ACP_NOT_INITIALIZED)

        # Invalid protocolVersion rejected.
        bad_init = server.handle_message(
            {"jsonrpc": "2.0", "id": 2, "method": "initialize", "params": {"protocolVersion": "1"}}
        )
        assert bad_init is not None
        self.assertEqual(bad_init["error"]["code"], JSONRPC_INVALID_PARAMS)

        # Valid ACP v1 initialize.
        init = server.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "initialize",
                "params": {
                    "protocolVersion": 1,
                    "clientInfo": {"name": "zed", "version": "0.200.0"},
                    "clientCapabilities": {},
                },
            }
        )
        assert init is not None
        result = init["result"]
        self.assertEqual(result["protocolVersion"], ACP_PROTOCOL_VERSION)
        self.assertEqual(result["agentInfo"]["name"], "northstar")
        self.assertEqual(result["agentInfo"]["version"], __version__)
        self.assertTrue(result["agentCapabilities"]["loadSession"])
        self.assertFalse(result["agentCapabilities"]["promptCapabilities"]["image"])
        self.assertFalse(result["agentCapabilities"]["promptCapabilities"]["audio"])
        self.assertTrue(result["agentCapabilities"]["promptCapabilities"]["embeddedContext"])
        self.assertEqual(result["agentCapabilities"]["mcpCapabilities"], {"http": False, "sse": False})
        self.assertEqual(result["authMethods"], [])

    def test_workspace_confinement_and_client_mcp_refusal(self) -> None:
        server = AcpServer(_offline_config(self.ws))
        server.handle_message({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": 1}})

        # Relative cwd refused.
        rel = server.handle_message(
            {"jsonrpc": "2.0", "id": 2, "method": "session/new", "params": {"cwd": "relative/path"}}
        )
        assert rel is not None
        self.assertEqual(rel["error"]["code"], JSONRPC_INVALID_PARAMS)

        # Escape outside operator --workspace refused.
        esc = server.handle_message(
            {"jsonrpc": "2.0", "id": 3, "method": "session/new", "params": {"cwd": str(self.outside)}}
        )
        assert esc is not None
        self.assertEqual(esc["error"]["code"], JSONRPC_INVALID_PARAMS)
        self.assertIn("workspace", esc["error"]["message"].lower())

        # Client-supplied mcpServers refused fail-closed.
        mcp = server.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "session/new",
                "params": {
                    "cwd": str(self.ws),
                    "mcpServers": [{"name": "evil", "command": "/bin/sh", "args": ["-c", "id"]}],
                },
            }
        )
        assert mcp is not None
        self.assertEqual(mcp["error"]["code"], JSONRPC_INVALID_PARAMS)
        self.assertIn("mcpServers", mcp["error"]["message"])

        # Empty mcpServers inside workspace succeeds.
        ok = server.handle_message(
            {"jsonrpc": "2.0", "id": 5, "method": "session/new", "params": {"cwd": str(self.ws), "mcpServers": []}}
        )
        assert ok is not None
        self.assertIn("sessionId", ok["result"])
        mode_ids = [m["id"] for m in ok["result"]["modes"]["availableModes"]]
        self.assertEqual(mode_ids, ["plan", "default"])

    def test_set_mode_tighten_only_and_never_allows_bypass(self) -> None:
        emitted: list[dict[str, Any]] = []
        server = AcpServer(_offline_config(self.ws, permission_mode="acceptEdits"), emit=emitted.append)
        server.handle_message({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": 1}})
        created = server.handle_message(
            {"jsonrpc": "2.0", "id": 2, "method": "session/new", "params": {"cwd": str(self.ws)}}
        )
        assert created is not None
        sid = created["result"]["sessionId"]

        # bypassPermissions is never exposed or accepted.
        bypass = server.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "session/set_mode",
                "params": {"sessionId": sid, "modeId": "bypassPermissions"},
            }
        )
        assert bypass is not None
        self.assertEqual(bypass["error"]["code"], JSONRPC_INVALID_PARAMS)

        # Tighten acceptEdits -> default -> plan succeeds.
        t1 = server.handle_message(
            {"jsonrpc": "2.0", "id": 4, "method": "session/set_mode", "params": {"sessionId": sid, "modeId": "default"}}
        )
        assert t1 is not None and "result" in t1
        t2 = server.handle_message(
            {"jsonrpc": "2.0", "id": 5, "method": "session/set_mode", "params": {"sessionId": sid, "modeId": "plan"}}
        )
        assert t2 is not None and "result" in t2

        # Re-widening plan -> default is refused (policy may only tighten).
        widen = server.handle_message(
            {"jsonrpc": "2.0", "id": 6, "method": "session/set_mode", "params": {"sessionId": sid, "modeId": "default"}}
        )
        assert widen is not None
        self.assertEqual(widen["error"]["code"], JSONRPC_INVALID_PARAMS)
        self.assertIn("tighten", widen["error"]["message"].lower())

        mode_updates = [
            msg["params"]["update"]["currentModeId"]
            for msg in emitted
            if msg.get("method") == "session/update"
            and msg["params"]["update"].get("sessionUpdate") == "current_mode_update"
        ]
        self.assertEqual(mode_updates, ["default", "plan"])

    def test_prompt_streams_tool_calls_plan_and_usage(self) -> None:
        emitted: list[dict[str, Any]] = []
        turns = (
            ScriptedTurn.tools(
                [
                    {"type": "tool_use", "name": "Read", "input": {"path": "notes.txt"}},
                    {
                        "type": "tool_use",
                        "name": "SubmitPlan",
                        "input": {
                            "summary": "Inspect notes",
                            "steps": ["Read notes.txt", "Report findings"],
                            "files_to_read": ["notes.txt"],
                            "files_to_edit": [],
                            "checks": [],
                        },
                    },
                ]
            ),
            ScriptedTurn.text("Read notes.txt and verified alpha/beta."),
        )
        server = AcpServer(_offline_config(self.ws, scripted_turns=turns), emit=emitted.append)
        server.handle_message({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": 1}})
        created = server.handle_message(
            {"jsonrpc": "2.0", "id": 2, "method": "session/new", "params": {"cwd": str(self.ws)}}
        )
        assert created is not None
        sid = created["result"]["sessionId"]

        resp = server.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "session/prompt",
                "params": {
                    "sessionId": sid,
                    "prompt": [
                        {"type": "text", "text": "Inspect notes.txt"},
                        {"type": "resource", "resource": {"uri": "file:///notes.txt", "text": "extra context"}},
                    ],
                },
            }
        )
        assert resp is not None and "result" in resp
        result = resp["result"]
        self.assertEqual(result["stopReason"], "end_turn")
        self.assertEqual(result["_meta"]["northstar"]["subtype"], "success")
        self.assertEqual(result["_meta"]["northstar"]["toolCallCount"], 2)

        updates = [m["params"]["update"] for m in emitted if m.get("method") == "session/update"]
        kinds = [u["sessionUpdate"] for u in updates]
        self.assertIn("tool_call", kinds)
        self.assertIn("tool_call_update", kinds)
        self.assertIn("plan", kinds)
        self.assertIn("agent_message_chunk", kinds)
        self.assertIn("usage_update", kinds)

        read_calls = [u for u in updates if u["sessionUpdate"] == "tool_call" and u["kind"] == "read"]
        self.assertEqual(len(read_calls), 1)
        self.assertIn("notes.txt", read_calls[0]["title"])

        plan_updates = [u for u in updates if u["sessionUpdate"] == "plan"]
        self.assertEqual(len(plan_updates[0]["entries"]), 2)

        text_chunks = "".join(
            u["content"]["text"] for u in updates if u["sessionUpdate"] == "agent_message_chunk"
        )
        self.assertIn("alpha/beta", text_chunks)

    def test_prompt_enforces_permission_denial_and_max_turns(self) -> None:
        # 1) Denied Shell tool stays blocked in default mode and surfaces permissionDenials.
        emitted: list[dict[str, Any]] = []
        denied_turns = (
            ScriptedTurn.tool("Shell", {"command": "echo hacked"}),
            ScriptedTurn.text("Shell was denied."),
        )
        server = AcpServer(_offline_config(self.ws, scripted_turns=denied_turns), emit=emitted.append)
        server.handle_message({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": 1}})
        sid = server.handle_message(
            {"jsonrpc": "2.0", "id": 2, "method": "session/new", "params": {"cwd": str(self.ws)}}
        )["result"]["sessionId"]
        resp = server.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "session/prompt",
                "params": {"sessionId": sid, "prompt": [{"type": "text", "text": "run shell"}]},
            }
        )
        assert resp is not None and "result" in resp
        self.assertGreaterEqual(len(resp["result"]["_meta"]["northstar"]["permissionDenials"]), 1)
        tool_updates = [
            m["params"]["update"]
            for m in emitted
            if m.get("method") == "session/update" and m["params"]["update"]["sessionUpdate"] == "tool_call_update"
        ]
        self.assertTrue(any(u["status"] == "failed" for u in tool_updates))

        # 2) Exceeding max_turns returns ACP stopReason "max_turn_requests".
        loop_turns = (
            ScriptedTurn.tool("Read", {"path": "notes.txt"}),
            ScriptedTurn.tool("Read", {"path": "notes.txt"}),
        )
        bounded = AcpServer(_offline_config(self.ws, scripted_turns=loop_turns, max_turns=1))
        bounded.handle_message({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": 1}})
        sid2 = bounded.handle_message(
            {"jsonrpc": "2.0", "id": 2, "method": "session/new", "params": {"cwd": str(self.ws)}}
        )["result"]["sessionId"]
        resp2 = bounded.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "session/prompt",
                "params": {"sessionId": sid2, "prompt": [{"type": "text", "text": "keep reading"}]},
            }
        )
        assert resp2 is not None and "result" in resp2
        self.assertEqual(resp2["result"]["stopReason"], "max_turn_requests")
        self.assertEqual(resp2["result"]["_meta"]["northstar"]["subtype"], "error_max_turns")

    def test_rejects_unsupported_image_content_block_and_bad_wire_frames(self) -> None:
        server = AcpServer(_offline_config(self.ws))
        server.handle_message({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": 1}})
        sid = server.handle_message(
            {"jsonrpc": "2.0", "id": 2, "method": "session/new", "params": {"cwd": str(self.ws)}}
        )["result"]["sessionId"]

        img = server.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "session/prompt",
                "params": {"sessionId": sid, "prompt": [{"type": "image", "data": "AAAA", "mimeType": "image/png"}]},
            }
        )
        assert img is not None
        self.assertEqual(img["error"]["code"], JSONRPC_INVALID_PARAMS)

        # Unknown method.
        unk = server.handle_message({"jsonrpc": "2.0", "id": 4, "method": "session/bogus", "params": {}})
        assert unk is not None
        self.assertEqual(unk["error"]["code"], JSONRPC_METHOD_NOT_FOUND)

        # Deeply nested JSON rejected cleanly.
        deep: Any = "leaf"
        for _ in range(140):
            deep = {"a": deep}
        nested = server.handle_message({"jsonrpc": "2.0", "id": 5, "method": "initialize", "params": deep})
        assert nested is not None
        self.assertEqual(nested["error"]["code"], JSONRPC_INVALID_REQUEST)

    def test_session_load_replays_persisted_transcript_and_continues(self) -> None:
        s1 = AcpServer(
            _offline_config(self.ws, scripted_turns=(ScriptedTurn.text("First turn reply."),)),
        )
        s1.handle_message({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": 1}})
        sid = s1.handle_message(
            {"jsonrpc": "2.0", "id": 2, "method": "session/new", "params": {"cwd": str(self.ws)}}
        )["result"]["sessionId"]
        turn1 = s1.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "session/prompt",
                "params": {"sessionId": sid, "prompt": [{"type": "text", "text": "Hello turn 1"}]},
            }
        )
        assert turn1 is not None and "result" in turn1
        persisted_id = turn1["result"]["_meta"]["northstar"]["sessionId"]
        self.assertTrue(persisted_id)

        # Fresh server instance loads that exact persisted session via session/load.
        replayed: list[dict[str, Any]] = []
        s2 = AcpServer(
            _offline_config(self.ws, scripted_turns=(ScriptedTurn.text("Second turn reply."),)),
            emit=replayed.append,
        )
        s2.handle_message({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": 1}})
        loaded = s2.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "session/load",
                "params": {"sessionId": persisted_id, "cwd": str(self.ws), "mcpServers": []},
            }
        )
        assert loaded is not None and "result" in loaded
        replayed_updates = [m["params"]["update"] for m in replayed if m.get("method") == "session/update"]
        self.assertTrue(any(u["sessionUpdate"] == "user_message_chunk" for u in replayed_updates))
        self.assertTrue(any(u["sessionUpdate"] == "agent_message_chunk" for u in replayed_updates))

        turn2 = s2.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "session/prompt",
                "params": {"sessionId": persisted_id, "prompt": [{"type": "text", "text": "Follow up"}]},
            }
        )
        assert turn2 is not None and "result" in turn2
        self.assertEqual(turn2["result"]["stopReason"], "end_turn")
        self.assertEqual(turn2["result"]["_meta"]["northstar"]["sessionId"], persisted_id)

    def test_session_load_refuses_tampered_transcript(self) -> None:
        s1 = AcpServer(_offline_config(self.ws, scripted_turns=(ScriptedTurn.text("Clean reply."),)))
        s1.handle_message({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": 1}})
        sid = s1.handle_message(
            {"jsonrpc": "2.0", "id": 2, "method": "session/new", "params": {"cwd": str(self.ws)}}
        )["result"]["sessionId"]
        turn1 = s1.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "session/prompt",
                "params": {"sessionId": sid, "prompt": [{"type": "text", "text": "Original prompt"}]},
            }
        )
        assert turn1 is not None and "result" in turn1
        persisted_id = turn1["result"]["_meta"]["northstar"]["sessionId"]

        # Tamper with the persisted JSONL transcript.
        session_file = self.ws / ".northstar" / "sessions" / f"{persisted_id}.jsonl"
        original = session_file.read_text(encoding="utf-8")
        self.assertIn("Clean reply.", original)
        session_file.write_text(original.replace("Clean reply.", "Tampered reply!"), encoding="utf-8")

        s2 = AcpServer(_offline_config(self.ws))
        s2.handle_message({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": 1}})
        loaded = s2.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "session/load",
                "params": {"sessionId": persisted_id, "cwd": str(self.ws), "mcpServers": []},
            }
        )
        assert loaded is not None and "error" in loaded
        self.assertEqual(loaded["error"]["code"], JSONRPC_INVALID_PARAMS)
        self.assertIn("verification failed", loaded["error"]["message"].lower())

    def test_prompt_writes_digest_first_evidence_bundle(self) -> None:
        evidence_base = self.root / "acp-evidence"
        server = AcpServer(
            _offline_config(
                self.ws,
                evidence_dir=str(evidence_base),
                evidence_required=True,
                scripted_turns=(
                    ScriptedTurn.tool("Read", {"path": "notes.txt"}),
                    ScriptedTurn.text("Verified with evidence."),
                ),
            )
        )
        server.handle_message({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": 1}})
        sid = server.handle_message(
            {"jsonrpc": "2.0", "id": 2, "method": "session/new", "params": {"cwd": str(self.ws)}}
        )["result"]["sessionId"]
        resp = server.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "session/prompt",
                "params": {"sessionId": sid, "prompt": [{"type": "text", "text": "Inspect with evidence"}]},
            }
        )
        assert resp is not None and "result" in resp
        ev_dir = resp["result"]["_meta"]["northstar"]["evidenceDir"]
        self.assertTrue(ev_dir and Path(ev_dir).is_dir())
        ev_path = Path(ev_dir)
        manifest = json.loads((ev_path / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["schema_version"], "northstar.runtime-evidence-manifest.v1")
        self.assertEqual(manifest["capture_policy"]["storage"], "digest-and-metadata-only")
        self.assertTrue(manifest["ok"])
        self.assertTrue(manifest["ledger"]["head_digest"])
        self.assertGreaterEqual(manifest["ledger"]["entry_count"], 2)
        self.assertTrue((ev_path / "ledger.jsonl").is_file())
        self.assertTrue((ev_path / "audit.ndjson").is_file())

    def test_stdio_cancel_and_malformed_json_recovery(self) -> None:
        # 1) Malformed JSON + oversized line recover cleanly in serve_stdio.
        bad_input = io.StringIO(
            "{not-json\n"
            + ("x" * (MAX_LINE_BYTES + 100)) + "\n"
            + json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": 1}}) + "\n"
        )
        out = io.StringIO()
        code = serve_stdio(_offline_config(self.ws), stdin=bad_input, stdout=out)
        self.assertEqual(code, 0)
        lines = [json.loads(line) for line in out.getvalue().splitlines() if line.strip()]
        self.assertEqual(lines[0]["error"]["code"], JSONRPC_PARSE_ERROR)
        self.assertEqual(lines[1]["error"]["code"], JSONRPC_INVALID_REQUEST)
        self.assertEqual(lines[2]["id"], 1)
        self.assertEqual(lines[2]["result"]["protocolVersion"], 1)

        # 2) Live session/cancel interrupts an in-flight prompt turn with stopReason="cancelled".
        entered = threading.Event()
        gate = threading.Event()
        slow_provider = _SlowCancelProvider(entered, gate)
        r_fd, w_fd = os.pipe()
        out_r_fd, out_w_fd = os.pipe()
        in_stream = os.fdopen(r_fd, "r", encoding="utf-8")
        out_stream = os.fdopen(out_w_fd, "w", encoding="utf-8")
        client_write = os.fdopen(w_fd, "w", encoding="utf-8")
        client_read = os.fdopen(out_r_fd, "r", encoding="utf-8")

        config = _offline_config(self.ws, provider=slow_provider, persist_sessions=False)
        server_thread = threading.Thread(
            target=serve_stdio,
            kwargs={"config": config, "stdin": in_stream, "stdout": out_stream},
            daemon=True,
        )
        server_thread.start()
        try:
            def send(obj: dict[str, Any]) -> None:
                client_write.write(json.dumps(obj) + "\n")
                client_write.flush()

            send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": 1}})
            init_resp = json.loads(client_read.readline())
            self.assertEqual(init_resp["id"], 1)

            send({"jsonrpc": "2.0", "id": 2, "method": "session/new", "params": {"cwd": str(self.ws)}})
            new_resp = json.loads(client_read.readline())
            sid = new_resp["result"]["sessionId"]

            send(
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "session/prompt",
                    "params": {"sessionId": sid, "prompt": [{"type": "text", "text": "take a while"}]},
                }
            )
            self.assertTrue(entered.wait(timeout=5.0), "provider never started")
            send({"jsonrpc": "2.0", "method": "session/cancel", "params": {"sessionId": sid}})
            # Send a synchronous ping so we know the stdio reader loop has processed session/cancel
            # before we unblock the provider turn.
            send({"jsonrpc": "2.0", "id": 99, "method": "authenticate", "params": {}})
            while True:
                ping = json.loads(client_read.readline())
                if ping.get("id") == 99:
                    break
            gate.set()

            prompt_resp = None
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline:
                raw = client_read.readline()
                if not raw:
                    break
                msg = json.loads(raw)
                if msg.get("id") == 3:
                    prompt_resp = msg
                    break
            assert prompt_resp is not None
            self.assertEqual(prompt_resp["result"]["stopReason"], "cancelled")
        finally:
            client_write.close()
            server_thread.join(timeout=5.0)
            in_stream.close()
            out_stream.close()
            client_read.close()

    def test_cli_acp_subprocess_end_to_end_and_dry_run(self) -> None:
        cli_bin = str(REPO_ROOT / "bin" / "northstar")

        # 1) --dry-run succeeds and prints governance stance.
        dry = subprocess.run(
            [
                cli_bin,
                "acp",
                "--dry-run",
                "--workspace",
                str(self.ws),
                "--permission-mode",
                "default",
                "--max-turns",
                "7",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(dry.returncode, 0, dry.stderr)
        self.assertIn("acp_protocol_version=1", dry.stdout)
        self.assertIn("client_mcp_servers=refused", dry.stdout)

        # 2) Invalid --max-turns returns USAGE_ERROR (64).
        bad = subprocess.run(
            [cli_bin, "acp", "--dry-run", "--max-turns", "0"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(bad.returncode, 64)

        # 3) Live NDJSON stdio session over subprocess pipes.
        proc = subprocess.Popen(
            [
                cli_bin,
                "acp",
                "--workspace",
                str(self.ws),
                "--provider",
                "scripted",
                "--scripted-text",
                "Governed ACP reply from Northstar.",
                "--permission-mode",
                "default",
                "--sandbox",
                "process",
                "--seccomp",
                "off",
                "--capdrop",
                "off",
                "--no-workspace-agents",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        assert proc.stdin is not None and proc.stdout is not None
        messages = [
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": 1}},
            {"jsonrpc": "2.0", "id": 2, "method": "session/new", "params": {"cwd": str(self.ws), "mcpServers": []}},
        ]
        for msg in messages:
            proc.stdin.write(json.dumps(msg) + "\n")
        proc.stdin.flush()

        init_line = json.loads(proc.stdout.readline())
        self.assertEqual(init_line["result"]["protocolVersion"], 1)
        new_line = json.loads(proc.stdout.readline())
        sid = new_line["result"]["sessionId"]

        proc.stdin.write(
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "session/prompt",
                    "params": {"sessionId": sid, "prompt": [{"type": "text", "text": "hello"}]},
                }
            )
            + "\n"
        )
        proc.stdin.flush()
        proc.stdin.close()

        remaining = [json.loads(line) for line in proc.stdout.read().splitlines() if line.strip()]
        stderr = proc.stderr.read() if proc.stderr else ""
        proc.stdout.close()
        if proc.stderr is not None:
            proc.stderr.close()
        proc.wait(timeout=10)
        self.assertEqual(proc.returncode, 0, stderr)

        responses = [m for m in remaining if m.get("id") == 3]
        self.assertEqual(len(responses), 1)
        self.assertEqual(responses[0]["result"]["stopReason"], "end_turn")
        updates = [m["params"]["update"] for m in remaining if m.get("method") == "session/update"]
        self.assertTrue(
            any(
                u.get("sessionUpdate") == "agent_message_chunk"
                and "Governed ACP reply from Northstar." in u["content"]["text"]
                for u in updates
            )
        )

    def test_interactive_permission_allow_once_and_per_call_binding(self) -> None:
        """ACP session/request_permission approves once per call and never caches."""
        turns = (
            ScriptedTurn.tool("Write", {"path": "first.txt", "content": "allowed-once"}),
            ScriptedTurn.tool("Write", {"path": "second.txt", "content": "should-be-denied"}),
            ScriptedTurn.text("Completed two write attempts."),
        )
        r_fd, w_fd = os.pipe()
        out_r_fd, out_w_fd = os.pipe()
        in_stream = os.fdopen(r_fd, "r", encoding="utf-8")
        out_stream = os.fdopen(out_w_fd, "w", encoding="utf-8")
        client_write = os.fdopen(w_fd, "w", encoding="utf-8")
        client_read = os.fdopen(out_r_fd, "r", encoding="utf-8")

        config = _offline_config(
            self.ws,
            permission_mode="default",
            interactive_permissions=True,
            permission_timeout_seconds=5.0,
            persist_sessions=False,
            scripted_turns=turns,
        )
        server_thread = threading.Thread(
            target=serve_stdio,
            kwargs={"config": config, "stdin": in_stream, "stdout": out_stream},
            daemon=True,
        )
        server_thread.start()
        perm_requests: list[dict[str, Any]] = []
        try:
            def send(obj: dict[str, Any]) -> None:
                client_write.write(json.dumps(obj) + "\n")
                client_write.flush()

            send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": 1}})
            self.assertEqual(json.loads(client_read.readline())["id"], 1)

            send({"jsonrpc": "2.0", "id": 2, "method": "session/new", "params": {"cwd": str(self.ws)}})
            sid = json.loads(client_read.readline())["result"]["sessionId"]

            send(
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "session/prompt",
                    "params": {"sessionId": sid, "prompt": [{"type": "text", "text": "write two files"}]},
                }
            )

            prompt_resp = None
            deadline = time.monotonic() + 10.0
            while time.monotonic() < deadline:
                raw = client_read.readline()
                if not raw:
                    break
                msg = json.loads(raw)
                if msg.get("method") == "session/request_permission":
                    perm_requests.append(msg)
                    option_id = "allow_once" if len(perm_requests) == 1 else "reject_once"
                    send(
                        {
                            "jsonrpc": "2.0",
                            "id": msg["id"],
                            "result": {"outcome": {"outcome": "selected", "optionId": option_id}},
                        }
                    )
                elif msg.get("id") == 3:
                    prompt_resp = msg
                    break

            assert prompt_resp is not None and "result" in prompt_resp
            self.assertEqual(prompt_resp["result"]["stopReason"], "end_turn")
            self.assertEqual(len(perm_requests), 2)
            # First call approved once; second call asked fresh (no caching) and rejected.
            self.assertEqual((self.ws / "first.txt").read_text(encoding="utf-8"), "allowed-once")
            self.assertFalse((self.ws / "second.txt").exists())
            self.assertEqual(len(prompt_resp["result"]["_meta"]["northstar"]["permissionDenials"]), 1)
            # Verify ACP v1 permission request structure + per-call digest binding.
            req0 = perm_requests[0]["params"]
            self.assertEqual(req0["toolCall"]["kind"], "edit")
            self.assertEqual([o["optionId"] for o in req0["options"]], ["allow_once", "reject_once"])
            self.assertTrue(req0["_meta"]["northstar"]["argumentsDigest"])
        finally:
            client_write.close()
            server_thread.join(timeout=5.0)
            in_stream.close()
            out_stream.close()
            client_read.close()

    def test_hard_denials_never_trigger_session_request_permission(self) -> None:
        emitted: list[dict[str, Any]] = []
        turns = (
            ScriptedTurn.tool("Write", {"path": "blocked.txt", "content": "nope"}),
            ScriptedTurn.tool("Shell", {"command": "echo nope"}),
            ScriptedTurn.text("denied without prompt"),
        )
        server = AcpServer(
            _offline_config(
                self.ws,
                permission_mode="plan",
                interactive_permissions=True,
                disallowed_tools=("Shell",),
                scripted_turns=turns,
            ),
            emit=emitted.append,
        )
        server.handle_message({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": 1}})
        sid = server.handle_message(
            {"jsonrpc": "2.0", "id": 2, "method": "session/new", "params": {"cwd": str(self.ws)}}
        )["result"]["sessionId"]
        resp = server.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "session/prompt",
                "params": {"sessionId": sid, "prompt": [{"type": "text", "text": "try mutations in plan mode"}]},
            }
        )
        assert resp is not None and "result" in resp
        self.assertFalse((self.ws / "blocked.txt").exists())
        perm_reqs = [m for m in emitted if m.get("method") == "session/request_permission"]
        self.assertEqual(perm_reqs, [])
        self.assertGreaterEqual(len(resp["result"]["_meta"]["northstar"]["permissionDenials"]), 2)

    def test_permission_timeout_and_cancel_fail_closed(self) -> None:
        # 1) Silent client hits permission_timeout_seconds and fails closed.
        emitted: list[dict[str, Any]] = []
        server = AcpServer(
            _offline_config(
                self.ws,
                permission_mode="default",
                interactive_permissions=True,
                permission_timeout_seconds=0.1,
                scripted_turns=(
                    ScriptedTurn.tool("Write", {"path": "timeout.txt", "content": "no"}),
                    ScriptedTurn.text("timed out"),
                ),
            ),
            emit=emitted.append,
        )
        server.handle_message({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": 1}})
        sid = server.handle_message(
            {"jsonrpc": "2.0", "id": 2, "method": "session/new", "params": {"cwd": str(self.ws)}}
        )["result"]["sessionId"]
        resp = server.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "session/prompt",
                "params": {"sessionId": sid, "prompt": [{"type": "text", "text": "write"}]},
            }
        )
        assert resp is not None and "result" in resp
        self.assertFalse((self.ws / "timeout.txt").exists())
        denials = resp["result"]["_meta"]["northstar"]["permissionDenials"]
        self.assertTrue(any("timed out" in d["reason"] for d in denials))

        # 2) session/cancel wakes a blocked permission waiter immediately and cancels the turn.
        r_fd, w_fd = os.pipe()
        out_r_fd, out_w_fd = os.pipe()
        in_stream = os.fdopen(r_fd, "r", encoding="utf-8")
        out_stream = os.fdopen(out_w_fd, "w", encoding="utf-8")
        client_write = os.fdopen(w_fd, "w", encoding="utf-8")
        client_read = os.fdopen(out_r_fd, "r", encoding="utf-8")

        config = _offline_config(
            self.ws,
            permission_mode="default",
            interactive_permissions=True,
            permission_timeout_seconds=30.0,
            persist_sessions=False,
            scripted_turns=(
                ScriptedTurn.tool("Write", {"path": "cancel.txt", "content": "no"}),
                ScriptedTurn.text("never"),
            ),
        )
        t = threading.Thread(
            target=serve_stdio,
            kwargs={"config": config, "stdin": in_stream, "stdout": out_stream},
            daemon=True,
        )
        t.start()
        try:
            def send(obj: dict[str, Any]) -> None:
                client_write.write(json.dumps(obj) + "\n")
                client_write.flush()

            send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": 1}})
            client_read.readline()
            send({"jsonrpc": "2.0", "id": 2, "method": "session/new", "params": {"cwd": str(self.ws)}})
            sid2 = json.loads(client_read.readline())["result"]["sessionId"]
            send(
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "session/prompt",
                    "params": {"sessionId": sid2, "prompt": [{"type": "text", "text": "write"}]},
                }
            )
            # Wait for session/request_permission, then send session/cancel instead of answering.
            prompt_resp = None
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline:
                msg = json.loads(client_read.readline())
                if msg.get("method") == "session/request_permission":
                    send({"jsonrpc": "2.0", "method": "session/cancel", "params": {"sessionId": sid2}})
                elif msg.get("id") == 3:
                    prompt_resp = msg
                    break
            assert prompt_resp is not None
            self.assertEqual(prompt_resp["result"]["stopReason"], "cancelled")
            self.assertFalse((self.ws / "cancel.txt").exists())
        finally:
            client_write.close()
            t.join(timeout=5.0)
            in_stream.close()
            out_stream.close()
            client_read.close()

    def test_camel_strict_escalation_bridges_to_acp_subprocess_permission(self) -> None:
        """Subprocess end-to-end: camel-strict Read -> Write escalates via ACP session/request_permission."""
        cli_bin = str(REPO_ROOT / "bin" / "northstar")
        script_path = self.root / "camel_script.json"
        script_path.write_text(
            json.dumps(
                {
                    "turns": [
                        {"tool": {"name": "Read", "input": {"path": "notes.txt"}}},
                        {"tool": {"name": "Write", "input": {"path": "tainted.txt", "content": "injected"}}},
                        {"text": "finished"},
                    ]
                }
            ),
            encoding="utf-8",
        )
        proc = subprocess.Popen(
            [
                cli_bin,
                "acp",
                "--workspace",
                str(self.ws),
                "--provider",
                "scripted",
                "--script",
                str(script_path),
                "--permission-mode",
                "acceptEdits",
                "--dataflow-policy",
                "camel-strict",
                "--interactive-permissions",
                "--permission-timeout-seconds",
                "5",
                "--sandbox",
                "process",
                "--seccomp",
                "off",
                "--capdrop",
                "off",
                "--no-workspace-agents",
                "--no-session",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        assert proc.stdin is not None and proc.stdout is not None
        try:
            def send(obj: dict[str, Any]) -> None:
                proc.stdin.write(json.dumps(obj) + "\n")
                proc.stdin.flush()

            send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": 1}})
            self.assertEqual(json.loads(proc.stdout.readline())["result"]["protocolVersion"], 1)

            send({"jsonrpc": "2.0", "id": 2, "method": "session/new", "params": {"cwd": str(self.ws)}})
            sid = json.loads(proc.stdout.readline())["result"]["sessionId"]

            send(
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "session/prompt",
                    "params": {"sessionId": sid, "prompt": [{"type": "text", "text": "read then write"}]},
                }
            )

            seen_perm = None
            prompt_resp = None
            while True:
                raw = proc.stdout.readline()
                if not raw:
                    break
                msg = json.loads(raw)
                if msg.get("method") == "session/request_permission":
                    seen_perm = msg
                    send(
                        {
                            "jsonrpc": "2.0",
                            "id": msg["id"],
                            "result": {"outcome": {"outcome": "selected", "optionId": "reject_once"}},
                        }
                    )
                elif msg.get("id") == 3:
                    prompt_resp = msg
                    break

            proc.stdin.close()
            stderr = proc.stderr.read() if proc.stderr else ""
            proc.stdout.close()
            if proc.stderr is not None:
                proc.stderr.close()
            proc.wait(timeout=10)
            self.assertEqual(proc.returncode, 0, stderr)
            assert seen_perm is not None
            self.assertIn("CaMeL integrity taint", seen_perm["params"]["_meta"]["northstar"]["reasonHint"])
            assert prompt_resp is not None and "result" in prompt_resp
            self.assertEqual(prompt_resp["result"]["stopReason"], "end_turn")
            self.assertFalse((self.ws / "tainted.txt").exists())
            self.assertEqual(len(prompt_resp["result"]["_meta"]["northstar"]["permissionDenials"]), 1)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=5)

    def _init_git_repo(self, path: Path) -> None:
        path.mkdir(parents=True, exist_ok=True)
        (path / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
        subprocess.run(["git", "init", "--quiet", str(path)], check=True)
        subprocess.run(["git", "-C", str(path), "config", "user.email", "acp-test@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(path), "config", "user.name", "ACP Test"], check=True)
        subprocess.run(["git", "-C", str(path), "add", "."], check=True)
        subprocess.run(["git", "-C", str(path), "commit", "--quiet", "-m", "baseline"], check=True)

    def test_code_worktree_isolates_edits_seals_admission_and_cleans_up(self) -> None:
        repo = self.root / "git_repo"
        self._init_git_repo(repo)
        evidence_root = self.root / "wt_evidence"

        server = AcpServer(
            _offline_config(
                repo,
                permission_mode="acceptEdits",
                code_worktree=True,
                evidence_dir=str(evidence_root),
                persist_sessions=False,
                scripted_turns=(
                    ScriptedTurn.tool("Write", {"path": "app.py", "content": "VALUE = 2\n"}),
                    ScriptedTurn.text("Updated app.py inside isolated worktree."),
                ),
            )
        )
        try:
            server.handle_message({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": 1}})
            created = server.handle_message(
                {"jsonrpc": "2.0", "id": 2, "method": "session/new", "params": {"cwd": str(repo)}}
            )
            assert created is not None and "result" in created
            sid = created["result"]["sessionId"]
            meta_new = created["result"]["_meta"]["northstar"]
            self.assertTrue(meta_new["codeWorktree"])
            wt_path = Path(meta_new["worktreePath"])
            self.assertTrue(wt_path.is_dir())
            self.assertNotEqual(wt_path.resolve(), repo.resolve())
            admission = json.loads(Path(meta_new["admissionPath"]).read_text(encoding="utf-8"))
            self.assertEqual(admission["schema"], "northstar.repository-admission.v1")
            self.assertFalse(admission["secrets_content_read"])
            self.assertTrue(admission["non_executing_scan"])

            resp = server.handle_message(
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "session/prompt",
                    "params": {"sessionId": sid, "prompt": [{"type": "text", "text": "update VALUE to 2"}]},
                }
            )
            assert resp is not None and "result" in resp
            ns = resp["result"]["_meta"]["northstar"]
            self.assertEqual(resp["result"]["stopReason"], "end_turn")
            self.assertTrue(ns["patchAuditOk"])
            self.assertTrue(Path(ns["patchPath"]).is_file())
            self.assertIn("+VALUE = 2", Path(ns["patchPath"]).read_text(encoding="utf-8"))
            # Live checkout remains 100% untouched!
            self.assertEqual((repo / "app.py").read_text(encoding="utf-8"), "VALUE = 1\n")
        finally:
            server.close_sessions()
        self.assertFalse(wt_path.exists())

    def test_code_worktree_refuses_benchjack_patch_via_delivery_audit(self) -> None:
        repo = self.root / "git_repo_attack"
        self._init_git_repo(repo)
        evidence_root = self.root / "wt_attack_evidence"

        server = AcpServer(
            _offline_config(
                repo,
                permission_mode="acceptEdits",
                code_worktree=True,
                evidence_dir=str(evidence_root),
                persist_sessions=False,
                scripted_turns=(
                    ScriptedTurn.tool("Write", {"path": "sitecustomize.py", "content": "import os\nos._exit(0)\n"}),
                    ScriptedTurn.text("Planted startup hook."),
                ),
            )
        )
        try:
            server.handle_message({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": 1}})
            sid = server.handle_message(
                {"jsonrpc": "2.0", "id": 2, "method": "session/new", "params": {"cwd": str(repo)}}
            )["result"]["sessionId"]
            resp = server.handle_message(
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "session/prompt",
                    "params": {"sessionId": sid, "prompt": [{"type": "text", "text": "plant hook"}]},
                }
            )
            assert resp is not None and "result" in resp
            ns = resp["result"]["_meta"]["northstar"]
            self.assertEqual(resp["result"]["stopReason"], "refusal")
            self.assertFalse(ns["patchAuditOk"])
            self.assertTrue(any(f.get("code") == "python_startup_hook" for f in ns["patchAuditFindings"]))
            self.assertFalse((repo / "sitecustomize.py").exists())
        finally:
            server.close_sessions()

    def test_code_worktree_rejects_non_git_dir_and_keep_worktree_preserves(self) -> None:
        non_git = self.root / "plain_dir"
        non_git.mkdir()
        server_bad = AcpServer(_offline_config(non_git, code_worktree=True, persist_sessions=False))
        server_bad.handle_message({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": 1}})
        err = server_bad.handle_message(
            {"jsonrpc": "2.0", "id": 2, "method": "session/new", "params": {"cwd": str(non_git)}}
        )
        assert err is not None and "error" in err
        self.assertEqual(err["error"]["code"], -32602)

        repo = self.root / "git_keep"
        self._init_git_repo(repo)
        ev = self.root / "keep_ev"
        server_keep = AcpServer(
            _offline_config(repo, code_worktree=True, keep_worktree=True, evidence_dir=str(ev), persist_sessions=False)
        )
        server_keep.handle_message({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": 1}})
        created = server_keep.handle_message(
            {"jsonrpc": "2.0", "id": 2, "method": "session/new", "params": {"cwd": str(repo)}}
        )
        wt_path = Path(created["result"]["_meta"]["northstar"]["worktreePath"])
        server_keep.close_sessions()
        self.assertTrue(wt_path.is_dir())
        # Clean up preserved worktree after assertion so TemporaryDirectory exits cleanly.
        subprocess.run(["git", "-C", str(repo), "worktree", "remove", "--force", str(wt_path)], check=False)

    def test_acp_editor_examples_and_offline_smoke_contract(self) -> None:
        repo_root = Path(__file__).resolve().parents[3]
        zed_cfg_path = repo_root / "examples" / "acp" / "zed-settings.json"
        nvim_cfg_path = repo_root / "examples" / "acp" / "neovim-acp.lua"
        smoke_path = repo_root / "examples" / "acp" / "smoke_offline.py"

        zed_cfg = json.loads(zed_cfg_path.read_text(encoding="utf-8"))
        servers = zed_cfg["agent_servers"]
        self.assertGreaterEqual(len(servers), 2)
        for name, spec in servers.items():
            args = spec["args"]
            self.assertEqual(args[0], "acp", name)
            self.assertIn("--code-worktree", args, name)
            self.assertIn("--interactive-permissions", args, name)
            self.assertNotIn("bypassPermissions", args, name)

        nvim_text = nvim_cfg_path.read_text(encoding="utf-8")
        self.assertIn("--code-worktree", nvim_text)
        self.assertIn("camel-strict", nvim_text)
        self.assertNotIn("bypassPermissions", nvim_text)

        res = subprocess.run(
            [sys.executable, str(smoke_path)],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(res.returncode, 0, res.stderr + res.stdout)
        self.assertIn("PASS: northstar acp offline smoke", res.stdout)


if __name__ == "__main__":
    unittest.main()
