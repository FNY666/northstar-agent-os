#!/usr/bin/env python3
"""Offline MCP stdio test server for the runtime's MCP client tests.

Pure standard library. Speaks just enough JSON-RPC 2.0 over stdio:

- initialize -> protocolVersion + tools capability
- notifications/initialized -> no reply
- tools/list -> two tools: echo (echoes text back) and fail (always errors)
- tools/call -> echo echoes; fail reports isError with a message; unknown
  method/tool is a JSON-RPC error

Environment switches used by the tests:

- MCP_SILENT=1    answer initialize, then never answer tools/list (timeout test)
- MCP_SLOW_TOOL=1 sleep before answering tools/call (call-timeout test)
- MCP_SPAWN_REPORT=/path  record cwd and MCP_TEST_* variables there at startup, so a test can
              prove what the *child process* was given (an imported env/cwd, not this test's)
"""
from __future__ import annotations

import json
import os
import sys
import time


def respond(message: dict) -> None:
    sys.stdout.write(json.dumps(message, ensure_ascii=False, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def _report_spawn() -> None:
    path = os.environ.get("MCP_SPAWN_REPORT")
    if not path:
        return
    seen = {key: value for key, value in os.environ.items() if key.startswith("MCP_TEST_")}
    with open(path, "w", encoding="utf-8") as handle:
        json.dump({"cwd": os.getcwd(), "env": seen}, handle)


def main() -> int:
    _report_spawn()
    silent = os.environ.get("MCP_SILENT") == "1"
    slow_tool = os.environ.get("MCP_SLOW_TOOL") == "1"
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            respond({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}})
            continue
        if not isinstance(request, dict):
            continue
        method = request.get("method")
        request_id = request.get("id")
        if request_id is None:  # notification
            continue
        if method == "initialize":
            respond({
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "mcp-echo-fixture", "version": "1.0"},
                },
            })
            if silent:
                # Never answer tools/list: the client must time out and kill us.
                time.sleep(3600)
        elif method == "tools/list":
            respond({
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "tools": [
                        {
                            "name": "echo",
                            "description": "Echoes the text argument back verbatim.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {"text": {"type": "string"}},
                                "required": ["text"],
                            },
                        },
                        {
                            "name": "fail",
                            "description": "Always fails with an isError result.",
                            "inputSchema": {"type": "object", "properties": {}},
                        },
                    ]
                },
            })
        elif method == "tools/call":
            params = request.get("params") or {}
            name = (params.get("name") or "") if isinstance(params, dict) else ""
            arguments = params.get("arguments") or {} if isinstance(params, dict) else {}
            if name == "echo":
                if slow_tool:
                    time.sleep(30)
                text = arguments.get("text", "") if isinstance(arguments, dict) else ""
                respond({
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {"content": [{"type": "text", "text": f"echo:{text}"}], "isError": False},
                })
            elif name == "fail":
                respond({
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {"content": [{"type": "text", "text": "boom"}], "isError": True},
                })
            else:
                respond({
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32602, "message": f"unknown tool {name!r}"},
                })
        else:
            respond({
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32601, "message": f"method not found {method!r}"},
            })
    return 0


if __name__ == "__main__":
    sys.exit(main())
