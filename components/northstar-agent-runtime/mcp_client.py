"""Minimal Model Context Protocol (MCP) stdio client for the governed runtime.

Scope is deliberately small and fail-closed:

- One server per ``McpStdioClient``: a child process speaking JSON-RPC 2.0 over
  stdio. The handshake (``initialize`` → ``notifications/initialized`` →
  ``tools/list``) runs with a deadline, then each remote tool becomes a local
  ``ToolSpec`` named ``mcp__<server>__<tool>``.
- Remote tools are treated as **mutating by default** (``kind="other"``), so
  under the runtime's ``default`` permission mode they are denied until an
  operator names them with ``--allow-tool``; everything still flows through the
  existing permission gate and hooks. MCP is a tool *transport*, never a policy
  bypass.
- Output is bounded: per-line and per-call caps apply on the client side, and a
  server that stops answering is TERM→KILLed as a process group (``close`` and
  every timeout path).
- No third-party dependency: plain ``json`` + ``select`` on POSIX.

Not implemented here (documented limits): MCP sampling/roots/prompts, image and
resource content blocks are passed through as text placeholders, and there is no
reconnection. The live-tool surface of the runtime remains the registry.
"""
from __future__ import annotations

import json
import os
import re
import select
import shlex
import signal
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any

from tools import ToolResult, ToolSpec, ToolContext

MCP_NAME_RE = "mcp__"
#: Guardrails for hostile or broken servers.
MAX_LINE_BYTES = 1_000_000          # one JSON-RPC line
MAX_SCHEMA_CHARS = 30_000           # one inputSchema
MAX_TOOLS_PER_SERVER = 25
MAX_DESCRIPTION_CHARS = 600
MIN_TIMEOUT_MS = 100
MAX_TIMEOUT_MS = 300_000
CLOSE_GRACE_SECONDS = 1.0
TOOL_NAME_PART_RE = "^[A-Za-z0-9_-]+$"
_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]*$")
_TOOL_PART_RE = re.compile(TOOL_NAME_PART_RE)


class McpError(ValueError):
    """MCP transport, protocol, or configuration error. Operator-facing."""


@dataclass
class RemoteTool:
    name: str
    description: str
    input_schema: dict[str, Any]
    annotations: dict[str, Any] = field(default_factory=dict)


def parse_mcp_flag(value: str) -> tuple[str, list[str]]:
    """Parse ``--mcp-server NAME=COMMAND ARG...`` (command split with shlex)."""
    if "=" not in value:
        raise ValueError(
            f"--mcp-server expects NAME=COMMAND... (e.g. --mcp-server demo=python3 server.py); got {value!r}"
        )
    name, _, command_text = value.partition("=")
    name = name.strip()
    if not name or not _NAME_RE.match(name):
        raise ValueError(
            f"--mcp-server name {name!r} must be a lowercase identifier matching [a-z][a-z0-9_-]*"
        )
    command = shlex.split(command_text.strip())
    if not command:
        raise ValueError(f"--mcp-server {name!r}: command must not be empty")
    return name, command


def _coerce_name_part(value: str, kind: str, server: str) -> str:
    if not value or not _TOOL_PART_RE.match(value):
        raise McpError(
            f"mcp server {server!r}: {kind} name {value!r} is not a plain identifier "
            f"matching {TOOL_NAME_PART_RE}"
        )
    return value


class McpStdioClient:
    """One MCP server over stdio, handshaken and ready to call."""

    def __init__(self, name: str, command: list[str], *, timeout_ms: int = 15_000) -> None:
        if not 100 <= timeout_ms <= MAX_TIMEOUT_MS:
            raise ValueError(f"--mcp-timeout-ms must be between {MIN_TIMEOUT_MS} and {MAX_TIMEOUT_MS}")
        self.name = name
        self.command = list(command)
        self.timeout_ms = timeout_ms
        self._proc: subprocess.Popen[bytes] | None = None
        self._request_id = 0
        self._tools: dict[str, RemoteTool] = {}

    # -- lifecycle -----------------------------------------------------------

    @property
    def connected(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def connect(self) -> None:
        """Spawn the server, handshake, and list its tools."""
        if self._proc is not None:
            raise McpError(f"mcp server {self.name!r} is already connected")
        try:
            proc = subprocess.Popen(
                self.command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,  # server logs never block the client
                start_new_session=True,      # own process group for TERM->KILL cleanup
            )
        except OSError as error:
            raise McpError(f"mcp server {self.name!r}: cannot start {self.command[0]}: {error}") from error
        self._proc = proc
        try:
            result = self._request("initialize", {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "northstar-agent-runtime", "version": "0.1.0.dev0"},
            })
            if not isinstance(result, dict):
                raise McpError(f"mcp server {self.name!r}: initialize returned a non-object result")
            self._notify("notifications/initialized")
            listed = self._request("tools/list", {})
            tools = listed.get("tools") if isinstance(listed, dict) else None
            if not isinstance(tools, list) or len(tools) > MAX_TOOLS_PER_SERVER:
                raise McpError(
                    f"mcp server {self.name!r}: tools/list must return an array of at most "
                    f"{MAX_TOOLS_PER_SERVER} tools"
                )
            for raw in tools:
                if not isinstance(raw, dict):
                    raise McpError(f"mcp server {self.name!r}: a tool entry is not an object")
                tool_name = _coerce_name_part(str(raw.get("name", "")), "tool", self.name)
                description = str(raw.get("description", "") or "")[:MAX_DESCRIPTION_CHARS]
                schema = raw.get("inputSchema") or {}
                if not isinstance(schema, dict):
                    raise McpError(f"mcp server {self.name!r}: tool {tool_name!r} inputSchema is not an object")
                encoded = json.dumps(schema, sort_keys=True)
                if len(encoded) > MAX_SCHEMA_CHARS:
                    raise McpError(
                        f"mcp server {self.name!r}: tool {tool_name!r} inputSchema is "
                        f"{len(encoded)} chars (cap {MAX_SCHEMA_CHARS})"
                    )
                self._tools[tool_name] = RemoteTool(
                    name=tool_name,
                    description=description,
                    input_schema=schema,
                )
        except Exception:
            self.close()
            raise

    def tool_names(self) -> tuple[str, ...]:
        return tuple(sorted(self._tools))

    def tool(self, name: str) -> RemoteTool:
        try:
            return self._tools[name]
        except KeyError:
            raise McpError(f"mcp server {self.name!r} has no tool {name!r}") from None

    # -- calls ---------------------------------------------------------------

    def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> ToolResult:
        """Invoke one remote tool; flatten its content blocks into a ToolResult."""
        try:
            self.tool(tool_name)  # raises McpError for an unknown tool
            result = self._request("tools/call", {"name": tool_name, "arguments": arguments})
        except McpError as error:
            return ToolResult.error(f"mcp {self.name}/{tool_name}: {error}")
        if not isinstance(result, dict):
            return ToolResult.error(f"mcp {self.name}/{tool_name}: tools/call returned a non-object result")
        is_error = bool(result.get("isError"))
        content = result.get("content")
        text = _flatten_content(content, self.name, tool_name)
        if is_error:
            return ToolResult.error(text)
        return ToolResult.ok(text)

    def close(self) -> None:
        """TERM the process group, then KILL after a grace period. Idempotent."""
        proc = self._proc
        self._proc = None
        if proc is None:
            return
        if proc.poll() is None:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                pass
            try:
                proc.wait(timeout=CLOSE_GRACE_SECONDS)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
                proc.wait()
        else:
            proc.wait()
        for stream in (proc.stdin, proc.stdout):
            if stream is not None and not stream.closed:
                stream.close()

    # -- json-rpc plumbing ----------------------------------------------------

    def _notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        self._send({"jsonrpc": "2.0", "method": method, "params": params or {}})

    def _request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        self._request_id += 1
        request_id = self._request_id
        self._send({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params or {}})
        deadline = time.monotonic() + self.timeout_ms / 1000
        while True:
            line = self._read_line(deadline)
            if line is None:
                raise McpError(
                    f"mcp server {self.name!r}: {method} timed out after {self.timeout_ms} ms"
                )
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                continue  # a malformed line is not our response; keep waiting
            if not isinstance(message, dict) or message.get("id") != request_id:
                continue  # notifications and other ids are ignored
            if "error" in message:
                error = message.get("error")
                detail = error.get("message", "unknown error") if isinstance(error, dict) else error
                raise McpError(f"mcp server {self.name!r}: {method}: {detail}")
            result = message.get("result")
            if not isinstance(result, dict):
                raise McpError(f"mcp server {self.name!r}: {method}: result is not an object")
            return result

    def _send(self, message: dict[str, Any]) -> None:
        if not self.connected or self._proc is None or self._proc.stdin is None:
            raise McpError(f"mcp server {self.name!r} is not running")
        payload = json.dumps(message, ensure_ascii=False, separators=(",", ":")) + "\n"
        try:
            self._proc.stdin.write(payload.encode("utf-8"))
            self._proc.stdin.flush()
        except (BrokenPipeError, OSError) as error:
            raise McpError(f"mcp server {self.name!r}: write failed: {error}") from error

    def _read_line(self, deadline: float) -> str | None:
        """Read one line with a deadline and a byte cap; ``None`` on timeout/EOF."""
        if self._proc is None or self._proc.stdout is None:
            return None
        fd = self._proc.stdout.fileno()
        buffer = bytearray()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            ready, _, _ = select.select([fd], [], [], remaining)
            if not ready:
                return None
            chunk = os.read(fd, 65536)
            if not chunk:  # EOF: a closed server has no more responses
                return None
            buffer.extend(chunk)
            newline = buffer.find(b"\n")
            if newline != -1:
                return bytes(buffer[: newline + 1]).decode("utf-8", errors="replace").strip()
            if len(buffer) > MAX_LINE_BYTES:
                raise McpError(
                    f"mcp server {self.name!r} sent a line larger than {MAX_LINE_BYTES} bytes"
                )


def _flatten_content(content: Any, server: str, tool_name: str) -> str:
    """Join MCP content blocks into text; images/resources become placeholders."""
    if content is None:
        return ""
    if not isinstance(content, list):
        return str(content)
    parts: list[str] = []
    for block in content:
        if not isinstance(block, dict):
            parts.append(str(block))
            continue
        kind = block.get("type")
        if kind == "text":
            parts.append(str(block.get("text", "")))
        elif kind in ("image", "resource", "audio", "video"):
            parts.append(f"[mcp {kind} block omitted by northstar: not representable as text]")
        else:
            parts.append(json.dumps(block, ensure_ascii=False, sort_keys=True, default=str))
    text = "\n".join(parts)
    return text[: 200_000] + ("\n[mcp result truncated by northstar]" if len(text) > 200_000 else "")


def mcp_tool_specs(client: McpStdioClient) -> tuple[ToolSpec, ...]:
    """Build governed ``ToolSpec``s (mutating by default) for one connected server."""
    specs: list[ToolSpec] = []
    for name in client.tool_names():
        remote = client.tool(name)
        tool_name = f"{MCP_NAME_RE}{client.name}__{name}"
        specs.append(
            ToolSpec(
                name=tool_name,
                description=f"MCP tool via server '{client.name}': {remote.description}",
                input_schema=remote.input_schema or {"type": "object", "properties": {}},
                kind="other",  # mutating by default: denied until --allow-tool names it
                is_mutating=True,
                needs_workspace=False,
                handler=_make_handler(client, name),
            )
        )
    return tuple(specs)


def _make_handler(client: McpStdioClient, tool_name: str):
    def handler(payload: dict[str, Any], _ctx: ToolContext) -> ToolResult:
        if not isinstance(payload, dict):
            return ToolResult.error(f"mcp {client.name}/{tool_name}: arguments must be an object")
        return client.call_tool(tool_name, payload)

    return handler
