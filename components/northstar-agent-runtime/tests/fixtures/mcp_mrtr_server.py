#!/usr/bin/env python3
"""Modern-generation (2026-07-28) MCP server used by ``tests/test_mcp_generation.py``.

Behaviour is switched by environment variables so one fixture covers the paths the
client has to get right, and each request is echoed as a JSON line on stdout so a
test can assert on the **wire**: which version and capabilities were declared, and
how often a field appeared.

- ``MRTR_SERVER_MODE``: ``discover`` (default) answers ``server/discover``;
  ``modern-error-legacy-only`` refuses it with ``-32022`` and only legacy versions;
  ``discover-legacy-only`` returns a discovery result without a modern version;
  ``bare`` / ``bare-state`` answer with ``input_required`` and nothing to answer (the
  former is malformed; the latter is a valid state-only retry), which a client must
  not retry forever;
  ``no-discover`` fails the probe with method-not-found, which a client must read as
  "legacy" and refuse to answer ``elicitation/create``; ``legacy-only`` refuses
  ``server/discover`` but speaks ``initialize``; ``loop`` re-asks forever.
- ``MRTR_SERVER_ECHO``: JSON echoed back inside the tool result.
- ``MCP_STDIO_MAX_LINE_BYTES``: server-side cap, to prove the client survives a
  line the peer refuses.
"""

from __future__ import annotations

import json
import os
import sys

PROTOCOL_VERSION_META = "io.modelcontextprotocol/protocolVersion"

MAX_LINE_BYTES = max(256, int(os.environ.get("MCP_STDIO_MAX_LINE_BYTES", "262144")))
SUPPORTED = [
    "2026-07-28",
    "2025-11-25",
    "2025-06-18",
    "2025-03-26",
    "2024-11-05",
    "2024-10-07",
]


def emit(message: dict) -> None:
    payload = json.dumps(message, ensure_ascii=False, separators=(",", ":"))
    if len(payload.encode("utf-8")) + 1 > MAX_LINE_BYTES:
        emit({"jsonrpc": "2.0", "id": message.get("id"), "error": {"code": -32602, "message": "line too long"}})
        return
    sys.stdout.write(payload + "\n")
    sys.stdout.flush()


def respond(message_id, result=None, error=None, *, modern=False) -> None:
    if message_id is None:
        return
    body = {"jsonrpc": "2.0", "id": message_id}
    if error is not None:
        body["error"] = error
    else:
        if modern and isinstance(result, dict):
            result.setdefault("resultType", "complete")
        body["result"] = result
    emit(body)


def error(message_id, code, message, data=None) -> None:
    detail = {"code": code, "message": message}
    if data is not None:
        detail["data"] = data
    respond(message_id, error=detail)


def tool_definitions() -> list[dict]:
    return [
        {
            "name": "echo",
            "description": "Echo the arguments back.",
            "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}}},
        },
        {
            "name": "needs_input",
            "title": "Ask before acting",
            "description": "Returns input_required until the client answers.",
            "inputSchema": {"type": "object", "properties": {"note": {"type": "string"}}},
        },
        {
            "name": "needs_password",
            "description": "Asks for a secret, which the client must refuse to relay.",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "unknown_result_type",
            "description": "Returns a result type this client does not implement.",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "missing_result_type",
            "description": "Returns a modern result without its required discriminator.",
            "inputSchema": {"type": "object", "properties": {}},
        },
    ]


def main() -> int:
    mode = os.environ.get("MRTR_SERVER_MODE", "discover")
    echo = os.environ.get("MRTR_SERVER_ECHO")
    asked = 0      # tools/call rounds
    while True:
        line = sys.stdin.readline()
        if not line:
            return 0
        try:
            message = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(message, dict):
            continue
        method = message.get("method")
        message_id = message.get("id")
        params = message.get("params") or {}
        # Every inbound message is logged first, notifications included: "which bytes
        # did the client actually send" is the whole point of this fixture, and a
        # handshake notification is exactly the kind of thing a test needs to see.
        meta = params.get("_meta") or {}
        wire = {"method": method, "id": message.get("id"), "params": params, "meta": meta}
        line = json.dumps(wire, ensure_ascii=False, separators=(",", ":"))
        _wire = os.environ.get("MRTR_SERVER_WIRE")
        if _wire:
            with open(_wire, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        sys.stderr.write("WIRE " + line + "\n")
        sys.stderr.flush()
        if method == "notifications/initialized":
            continue  # notifications get no response
        if method == "server/discover":
            if mode in {"no-discover", "legacy-only"}:
                error(message_id, -32601, "method not found")
            elif mode == "modern-error-legacy-only":
                error(
                    message_id,
                    -32022,
                    "unsupported protocol version",
                    {"supported": ["2025-11-25"], "requested": meta.get(PROTOCOL_VERSION_META)},
                )
            else:
                offered = ["2025-11-25"] if mode == "discover-legacy-only" else SUPPORTED
                respond(
                    message_id,
                    {
                        "supportedVersions": offered,
                        "_meta": {"io.modelcontextprotocol/serverInfo": {"name": "mrtr-fixture", "version": "9"}},
                        "capabilities": {"tools": {"listChanged": False}, "prompts": {}, "resources": {}},
                    },
                    modern=True,
                )
            continue
        if method == "initialize":
            if mode == "legacy-only":
                respond(
                    message_id,
                    {
                        "protocolVersion": "2024-11-05",
                        "serverInfo": {"name": "mrtr-fixture", "version": "9"},
                        "capabilities": {"tools": {}},
                    },
                )
            else:
                error(message_id, -32022, "this server is modern-only; name your version in the error")
            continue
        if method == "tools/list":
            respond(message_id, {"tools": tool_definitions()}, modern=bool(meta.get(PROTOCOL_VERSION_META)))
            continue
        if method == "prompts/list":
            respond(
                message_id,
                {"prompts": [{"name": "greet", "description": "greet", "arguments": []}]},
                modern=bool(meta.get(PROTOCOL_VERSION_META)),
            )
            continue
        if method == "resources/list":
            respond(
                message_id,
                {"resources": [{"uri": "file:///a.txt", "name": "a", "mimeType": "text/plain"}]},
                modern=bool(meta.get(PROTOCOL_VERSION_META)),
            )
            continue
        if method == "tools/call":
            name = params.get("name")
            modern = bool(meta.get(PROTOCOL_VERSION_META))
            if name == "unknown_result_type":
                respond(
                    message_id,
                    {"resultType": "task", "content": [{"type": "text", "text": "not supported"}]},
                    modern=modern,
                )
                continue
            if name == "missing_result_type":
                respond(message_id, {"content": [{"type": "text", "text": "missing discriminator"}]})
                continue
            if name == "needs_password" and "inputResponses" in params:
                respond(
                    message_id,
                    {
                        "resultType": "complete",
                        "content": [
                            {
                                "type": "text",
                                "text": "secret accepted: "
                                + json.dumps(params["inputResponses"], ensure_ascii=False),
                            }
                        ],
                    },
                    modern=modern,
                )
                continue
            if name == "needs_password":
                respond(
                    message_id,
                    {
                        "resultType": "input_required",
                        "requestState": "state-with-secret",
                        "inputRequests": {
                            "key": {
                                "method": "elicitation/create",
                                "params": {
                                    "mode": "form",
                                    "message": "paste the token",
                                    "requestedSchema": {
                                        "type": "object",
                                        "properties": {"password": {"type": "string", "format": "password"}},
                                    },
                                },
                            }
                        },
                    },
                    modern=modern,
                )
                continue
            if name == "needs_input" and mode == "bare":
                # Invalid: input_required with no requests and no state gives the
                # client no way to proceed. It must error instead of retrying.
                respond(message_id, {"resultType": "input_required"}, modern=modern)
                continue
            if name == "needs_input" and mode == "bare-state":
                # Also legal: "retry whenever you like", with a state to echo and no
                # question attached.
                respond(message_id, {"resultType": "input_required", "requestState": "bare-%d" % asked}, modern=modern)
                continue
            if name == "needs_input" and (mode == "loop" or asked < 1):
                asked += 1
                respond(
                    message_id,
                    {
                        "resultType": "input_required",
                        "requestState": "state-" + str(asked),
                        "inputRequests": {
                            "confirm": {
                                "method": "elicitation/create",
                                "params": {
                                    "mode": "form",
                                    "message": "Allow deleting /tmp/x? (asked twice on purpose)",
                                    "requestedSchema": {
                                        "type": "object",
                                        "properties": {"approved": {"type": "boolean"}},
                                        "required": ["approved"],
                                    },
                                },
                            },
                            "ask_model": {
                                "method": "sampling/createMessage",
                                "params": {"messages": [{"role": "user", "content": {"type": "text", "text": "hi"}}]},
                            },
                        },
                    },
                    modern=modern,
                )
                continue
            if name == "needs_input":
                respond(
                    message_id,
                    {
                        "resultType": "complete",
                        "content": [
                            {
                                "type": "text",
                                "text": "answered after %d ask(s): %s" % (asked, json.dumps(params.get("inputResponses") or {})),
                            }
                        ],
                        "structuredContent": {"rounds": asked},
                    },
                    modern=modern,
                )
                continue
            payload = {"rounds": asked, "inputResponses": params.get("inputResponses"), "requestState": params.get("requestState")}
            if echo is not None:
                payload["echo"] = echo
            if name == "boom":
                respond(message_id, {"isError": True, "content": [{"type": "text", "text": "tool exploded"}]}, modern=modern)
                continue
            respond(message_id, {"content": [{"type": "text", "text": json.dumps(payload, ensure_ascii=False)}]}, modern=modern)
            continue
        error(message_id, -32601, "method not found: %s" % method)


if __name__ == "__main__":
    sys.exit(main())
