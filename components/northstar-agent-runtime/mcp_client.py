"""Minimal Model Context Protocol (MCP) stdio client for the governed runtime.

Scope is deliberately small and fail-closed:

- One server per ``McpStdioClient``: a child process speaking JSON-RPC 2.0 over
  stdio. ``protocol="auto"`` probes the generation the way the 2026-07-28 revision
  requires - ``server/discover`` first, and the older ``initialize`` handshake only
  when that probe is refused - and the whole conversation then follows one era.
  ``"legacy"``/``"modern"`` pin it when the peer is already known. Each remote tool
  becomes a local ``ToolSpec`` named ``mcp__<server>__<tool>``.
- On the modern generation there is no handshake and no session id: version, client
  info and capabilities ride in ``params._meta`` on *every* request, and a server that
  needs something from a human answers with ``resultType: "input_required"`` instead
  of opening a channel of its own. Those embedded requests are routed to the same
  approval gate as everything else (see :mod:`mcp_elicitation`); with no approver
  attached they are declined, never answered by the model.
- Remote tools are treated as **mutating by default** (``kind="other"``), so
  under the runtime's ``default`` permission mode they are denied until an
  operator names them with ``--allow-tool``; everything still flows through the
  existing permission gate and hooks. MCP is a tool *transport*, never a policy
  bypass.
- Output is bounded: per-line and per-call caps apply on the client side. A
  server that stops answering surfaces a timeout error and stays alive for
  reuse; the process group is TERM→KILLed on ``close()`` and on connect
  failure.
- No third-party dependency: plain ``json`` + ``select`` on POSIX.

Not implemented here (documented limits): MCP sampling/roots/prompts, image and
resource content blocks are passed through as text placeholders, and there is no
reconnection. The live-tool surface of the runtime remains the registry.
"""
from __future__ import annotations

import hashlib
import errno
import json
import os
import re
import secrets
import select
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from _version import __version__
from tools.seccomp import prctl_loader_argv, validate_mode
from tools.sandbox import landlock_abi_version, landlock_loader_argv, network_deny_profile
from mcp_elicitation import (
    ACCEPT,
    CANCEL,
    ElicitationError,
    decode_input_requests,
    resolve_requests,
)
from mcp_negotiate import (
    DISCOVER_METHOD,
    LEGACY_VERSIONS,
    MAX_INPUT_ROUNDS,
    MODERN_VERSION,
    RESULT_INPUT_REQUIRED,
    client_capabilities,
    decide_era,
    discover_summary,
    input_requests,
    request_meta,
    request_state,
    result_type,
    retry_params,
)
from tools import ToolProvenance, ToolResult, ToolSpec, ToolContext


MCP_NAME_RE = "mcp__"
#: Guardrails for hostile or broken servers.
MAX_LINE_BYTES = 1_000_000          # one JSON-RPC line
MAX_JSON_DEPTH = 128                # bound recursive JSON containers from untrusted peers
MAX_UNTRUSTED_NOTIFICATIONS = 64
MAX_UNTRUSTED_NOTIFICATION_BYTES = 64 * 1024
MAX_SCHEMA_CHARS = 30_000           # one inputSchema
MAX_TOOLS_PER_SERVER = 25
# Bound pagination even when a server keeps returning empty pages and fresh cursors.
MAX_TOOL_LIST_PAGES = 25
MAX_DESCRIPTION_CHARS = 600
MIN_TIMEOUT_MS = 100
MAX_TIMEOUT_MS = 300_000
MAX_BASELINE_BYTES = 4 * 1024 * 1024
_BASELINE_FILENAME = "mcp-tool-baseline.json"
_BASELINE_LOCK_FILENAME = ".mcp-tool-baseline.lock"
CLOSE_GRACE_SECONDS = 1.0
_SUBSCRIPTION_ID_META = "io.modelcontextprotocol/subscriptionId"
# Default environment allowlist for MCP servers (minimum required for Python/Node servers)
DEFAULT_MCP_ENV_ALLOWLIST = frozenset({
    "PATH",
    "PYTHONPATH",
    "HOME",
    "USER",
    "LANG",
    "LC_ALL",
    "TMPDIR",
    "TEMP",
    "TMP",
    # Protocol fixture controls used by the offline MCP test servers. These are
    # non-secret coordination variables, not credentials.
    "MCP_SILENT",
    "MCP_SLOW_TOOL",
    "MCP_SPAWN_REPORT",
    "MRTR_SERVER_MODE",
    "MRTR_SERVER_WIRE",
})


TOOL_NAME_PART_RE = "^[A-Za-z0-9_-]+$"
_NAME_RE = re.compile(r"^[a-z][a-z0-9_-]*$")
_TOOL_PART_RE = re.compile(TOOL_NAME_PART_RE)


class McpError(ValueError):
    """MCP transport, protocol, or configuration error. Operator-facing."""


class _McpToolListError(McpError):
    """The server returned an invalid or over-budget tools/list pagination chain."""


def _strict_json_loads(raw: str, *, server: str) -> Any:
    """Parse a server line as unambiguous JSON, rejecting duplicate keys/constants."""
    depth = 0
    in_string = False
    escaped = False
    for character in raw:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > MAX_JSON_DEPTH:
                raise McpError(
                    f"mcp server {server!r} sent JSON nested deeper than {MAX_JSON_DEPTH} containers"
                )
        elif character in "]}":
            depth -= 1

    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key {key!r}")
            result[key] = value
        return result

    def reject_constant(value: str):
        raise ValueError(f"non-standard JSON constant {value}")

    try:
        return json.loads(raw, object_pairs_hook=unique_object, parse_constant=reject_constant)
    except (ValueError, RecursionError) as error:
        raise McpError(f"mcp server {server!r} sent invalid JSON: {error}") from error


@dataclass
class RemoteTool:
    name: str
    description: str
    input_schema: dict[str, Any]
    output_schema: dict[str, Any] | None = None
    annotations: dict[str, Any] = field(default_factory=dict)


def tool_definition_digest(
    server: str,
    name: str,
    description: str,
    input_schema: Mapping[str, Any],
    output_schema: Mapping[str, Any] | None = None,
) -> str:
    """Canonical digest pinning one MCP tool's definition.

    Covers ``(server identity, tool name, description, input_schema,
    output_schema)`` with
    the JCS canonicalization, so any drift -- a renamed tool, a rewritten
    description, a widened schema -- changes the digest. The admission
    baseline stores these digests; ``refresh_tools`` recomputes them and
    quarantines the server on mismatch.
    """
    from canonical_json import jcs_canonical_json as _jcs

    payload = {
        "server": server,
        "name": name,
        "description": description,
        "input_schema": dict(input_schema),
    }
    if output_schema is not None:
        payload["output_schema"] = dict(output_schema)
    return hashlib.sha256(_jcs(payload)).hexdigest()


# Tool-description coercion patterns (ToolHijacker / ToolCommander family).
# Scanned at admission: a description that coerces tool *selection* is an
# attack on the layer before any permission gate fires. Each pattern is a
# (name, regex, severity) triple; severity weights reflect how rarely the
# phrasing appears in legitimate descriptions.
_COERCION_PATTERNS: tuple[tuple[str, str, int], ...] = (
    # Cross-tool shadowing: "before using any other tool..."
    ("shadowing", r"\bbefore\s+(?:using|calling|invoking|running)\s+(?:any\s+)?(?:other|another|all|every|each)\b", 3),
    # Authority injection: claims system-level instruction power.
    ("authority", r"\b(?:system\s+instruction|as\s+an?\s+ai\s+(?:assistant|agent)|you\s+must\s+(?:always|first)|override\s+(?:your|the)\s+(?:instruction|directive))\b", 3),
    # Instruction embedding: imperative directed at the agent.
    ("instruction", r"\b(?:ignore\s+(?:previous|prior|all|your)\s+(?:instruction|directive)|do\s+not\s+(?:ask|tell|inform|notify)\s+(?:the\s+)?user)\b", 3),
    # Concealment: asks to hide behavior.
    ("concealment", r"\b(?:don'?t\s+tell|hide\s+(?:this|the|from)|keep\s+(?:this\s+)?secret|without\s+(?:informing|telling|notifying))\b", 3),
    # Exfiltration lure: directs the agent to hunt credentials.
    ("exfiltration", r"\b(?:ssh\s+keys?|cloud\s+credentials?|api\s+keys?|shell\s+history|environment\s+variables?)\b", 2),
    # Deprecation claim: "X is deprecated, use me instead".
    ("deprecation", r"\b(?:deprecated|obsolete|no\s+longer\s+(?:supported|maintained|recommended))\b", 1),
)


def scan_description_coercion(description: str) -> list[tuple[str, str]]:
    """Scan a tool description for selection-coercion patterns.

    Returns a list of ``(pattern_name, matched_text)`` for each hit.
    Empty means no coercion signals. This is a heuristic admission
    screen, not a verdict: hits are surfaced to the operator and
    recorded in the audit trail; the pinning/quarantine pipeline still
    enforces integrity at runtime.
    """
    hits: list[tuple[str, str]] = []
    if not description:
        return hits
    for name, pattern, _severity in _COERCION_PATTERNS:
        match = re.search(pattern, description, re.IGNORECASE)
        if match:
            hits.append((name, match.group(0)))
    return hits


def coercion_severity(hits: list[tuple[str, str]]) -> int:
    """Total severity weight of coercion hits (0 = clean)."""
    weights = {name: sev for name, _pat, sev in _COERCION_PATTERNS}
    return sum(weights.get(name, 0) for name, _text in hits)


@dataclass
class ToolDrift:
    """One tool definition that drifted from the admission baseline."""

    tool_name: str
    kind: str  # "added" | "removed" | "changed"
    expected_digest: str | None
    observed_digest: str | None


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
    """One MCP server over stdio: modern (per-request metadata) or legacy (handshake).

    The generation is decided once per server process, as the spec requires, and is a
    property of the *server*: ``auto`` probes with ``server/discover`` and falls back
    to ``initialize`` on any error that is not a recognized modern error.
    """

    def __init__(
        self,
        name: str,
        command: list[str],
        *,
        timeout_ms: int = 15_000,
        protocol: str = "auto",
        elicitor: Any | None = None,
        audit: Any | None = None,
        workspace_root: str = "",
        allow_sensitive_input: bool = False,
        allow_roots: bool = False,
        max_input_rounds: int = MAX_INPUT_ROUNDS,
        env: Mapping[str, str] | None = None,
        cwd: str | None = None,
        seccomp: str = "auto",
        network: str = "denied",
    ) -> None:
        if not 100 <= timeout_ms <= MAX_TIMEOUT_MS:
            raise ValueError(f"--mcp-timeout-ms must be between {MIN_TIMEOUT_MS} and {MAX_TIMEOUT_MS}")
        if protocol not in {"auto", "modern", "legacy"}:
            raise ValueError("--mcp-protocol must be auto, modern or legacy")
        if not 1 <= max_input_rounds <= 8:
            raise ValueError("--mcp-max-rounds must be between 1 and 8")
        self.seccomp = validate_mode(seccomp)
        self.network = self._validate_network_mode(network)
        self.name = name
        self.command = list(command)
        self.timeout_ms = timeout_ms
        self.protocol = protocol
        self.elicitor = elicitor
        self.audit = audit
        self.workspace_root = str(Path(workspace_root).resolve()) if workspace_root else ""
        # Environment variables: use allowlist for security.
        # MCP servers inherit only a minimal set (PATH, HOME, etc.) plus explicitly
        # configured extras. This prevents leaking API keys/tokens to untrusted servers.
        # The old "trimming is the host OS's job" claim was incorrect: subprocess.Popen
        # gives us full control over child environment, and external threat models
        # (Doppler/WorkOS/Corgea MCP security spec) unanimously recommend allowlist.
        base_env = {key: os.environ[key] for key in DEFAULT_MCP_ENV_ALLOWLIST if key in os.environ}
        self.extra_env = {**base_env, **{str(key): str(value) for key, value in dict(env or {}).items()}}
        self.cwd = str(cwd) if cwd else ""
        self.allow_sensitive_input = bool(allow_sensitive_input)
        self.allow_roots = bool(allow_roots)
        self.max_input_rounds = int(max_input_rounds)
        self.era = "unknown"
        self.protocol_version = ""
        self.negotiation = ""
        self.discovery: dict[str, Any] = {}
        self.elicitation_log: list[dict[str, Any]] = []
        self._proc: subprocess.Popen[bytes] | None = None
        # os.read() may return more than one newline-delimited JSON-RPC message.
        # Keep the unread suffix instead of silently dropping coalesced lines.
        self._stdout_buffer = bytearray()
        self._request_id = 0
        self._last_request_id: int | None = None
        self._tools: dict[str, RemoteTool] = {}
        # Tool-definition pinning: digests captured at connect() time. Any
        # drift detected by refresh_tools() quarantines the server.
        self._tool_digests: dict[str, str] = {}
        self._quarantined: bool = False
        self._quarantine_reason: str = ""
        # Pin-flap distrust (Keel-style): repeated quarantines escalate.
        # A server that flaps 3+ times is marked distrusted and needs an
        # explicit re_admit() -- not just a fresh client -- to recover.
        self._quarantine_count: int = 0
        self._distrusted: bool = False
        self._re_admit_pending: bool = False
        # Set when the server pushes notifications/tools/list_changed. The
        # next call_tool() drains it via refresh_tools() so a live rug-pull
        # is caught even between manual refreshes.
        self._pending_list_changed: bool = False
        # MCP 2026-07-28: explicit opt-in required for notification types.
        # Notifications arriving before opt-in are spec violations (untrusted).
        self._list_changed_subscribed: bool = False
        self._subscription_id: int | None = None
        self._server_capabilities: dict[str, Any] = {}
        self._untrusted_notifications: list[str] = []
        self._untrusted_notification_bytes = 0
        self._untrusted_notifications_dropped = 0
        self._info = {"name": "northstar-agent-runtime", "version": __version__}

    def _list_all_tools(self) -> list[Any]:
        """Fetch every MCP tools/list page under fixed page and tool-count caps."""
        tools: list[Any] = []
        params: dict[str, Any] = {}
        seen_cursors: set[str] = set()
        for _page_number in range(MAX_TOOL_LIST_PAGES):
            listed = self._request("tools/list", params)
            page = listed.get("tools")
            if not isinstance(page, list):
                raise _McpToolListError(
                    f"mcp server {self.name!r}: tools/list must return an array"
                )
            if len(tools) + len(page) > MAX_TOOLS_PER_SERVER:
                raise _McpToolListError(
                    f"mcp server {self.name!r}: tools/list returned more than "
                    f"{MAX_TOOLS_PER_SERVER} tools"
                )
            tools.extend(page)
            cursor = listed.get("nextCursor")
            if cursor is None:
                return tools
            if not isinstance(cursor, str):
                raise _McpToolListError(
                    f"mcp server {self.name!r}: tools/list nextCursor must be a string"
                )
            if cursor in seen_cursors:
                raise _McpToolListError(
                    f"mcp server {self.name!r}: tools/list repeated a pagination cursor"
                )
            seen_cursors.add(cursor)
            params = {"cursor": cursor}
        raise _McpToolListError(
            f"mcp server {self.name!r}: tools/list exceeded the {MAX_TOOL_LIST_PAGES} page limit"
        )

    # -- lifecycle -----------------------------------------------------------

    @property
    def connected(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    @property
    def modern(self) -> bool:
        return self.era == "modern"

    def _capabilities(self) -> dict[str, Any]:
        # The capability that matters: a server MUST NOT send an input request the
        # client did not declare, so with no approver attached the question never
        # arrives at all instead of arriving and being answered by a default.
        return client_capabilities(can_elicit=self.elicitor is not None, can_list_roots=self.allow_roots)

    def _meta(self) -> dict[str, Any]:
        # Before the era is settled, "the version we propose" is the newest one this
        # client speaks; afterwards it is the one the server agreed to.
        return request_meta(
            protocol_version=self.protocol_version or MODERN_VERSION,
            client_info=self._info,
            capabilities=self._capabilities(),
        )

    def _negotiate(self) -> None:
        """Decide the era, once, before any other request."""
        if self.protocol == "legacy":
            self.era, self.protocol_version = "legacy", LEGACY_VERSIONS[0]
            self.negotiation = "--mcp-protocol legacy: handshake without probing"
            self._legacy_handshake()
            return
        if self.protocol == "modern":
            self.era, self.protocol_version = "modern", MODERN_VERSION
            self.negotiation = "--mcp-protocol modern: per-request metadata, no handshake"
            return
        result, error, timed_out = self._exchange(DISCOVER_METHOD, None, force_meta=True)
        if isinstance(result, dict):
            self.discovery = discover_summary(result)
            capabilities = result.get("capabilities")
            self._server_capabilities = dict(capabilities) if isinstance(capabilities, Mapping) else {}
        decision = decide_era(result if isinstance(result, dict) else None, error, timed_out=timed_out)
        self.era, self.protocol_version = decision.era, decision.version
        self.negotiation = decision.reason
        if not decision.modern:
            self._legacy_handshake()

    def _legacy_handshake(self) -> None:
        result = self._request("initialize", {
            "protocolVersion": self.protocol_version or LEGACY_VERSIONS[0],
            "capabilities": self._capabilities(),
            "clientInfo": self._info,
        })
        if not isinstance(result, dict):
            raise McpError(f"mcp server {self.name!r}: initialize returned a non-object result")
        capabilities = result.get("capabilities")
        self._server_capabilities = dict(capabilities) if isinstance(capabilities, Mapping) else {}
        if self._server_supports_tool_list_changed():
            # Legacy generations deliver list_changed directly on stdio.
            self._list_changed_subscribed = True
        self._notify("notifications/initialized")

    def _server_supports_tool_list_changed(self) -> bool:
        tools = self._server_capabilities.get("tools")
        return isinstance(tools, Mapping) and tools.get("listChanged") is True

    def _open_tool_list_subscription(self) -> None:
        """Open and acknowledge a modern stdio subscriptions/listen stream."""
        if self._list_changed_subscribed:
            return
        if not self.modern or not self._server_supports_tool_list_changed():
            return
        self._request_id += 1
        subscription_id = self._request_id
        self._send({
            "jsonrpc": "2.0",
            "id": subscription_id,
            "method": "subscriptions/listen",
            "params": self._params({"notifications": {"toolsListChanged": True}}),
        })
        deadline = time.monotonic() + self.timeout_ms / 1000
        while True:
            line = self._read_line(deadline)
            if line is None:
                raise McpError(f"mcp server {self.name!r} did not acknowledge subscriptions/listen")
            message = _strict_json_loads(line, server=self.name)
            if not isinstance(message, dict):
                continue
            if message.get("method") == "notifications/subscriptions/acknowledged":
                params = message.get("params")
                meta = params.get("_meta") if isinstance(params, Mapping) else None
                acknowledged_id = meta.get(_SUBSCRIPTION_ID_META) if isinstance(meta, Mapping) else None
                if type(acknowledged_id) is not int or acknowledged_id != subscription_id:
                    self._record_untrusted_notification(line)
                    continue
                if message.get("jsonrpc") != "2.0":
                    raise McpError(
                        f"mcp server {self.name!r} sent a subscription acknowledgment without jsonrpc 2.0"
                    )
                notifications = params.get("notifications")
                if not isinstance(notifications, Mapping) or notifications.get("toolsListChanged") is not True:
                    raise McpError(
                        f"mcp server {self.name!r} acknowledged subscriptions/listen without toolsListChanged"
                    )
                self._subscription_id = subscription_id
                self._list_changed_subscribed = True
                return
            response_id = message.get("id")
            if type(response_id) is int and response_id == subscription_id:
                error = message.get("error")
                if message.get("jsonrpc") != "2.0" or "result" in message or not isinstance(error, Mapping):
                    raise McpError(
                        f"mcp server {self.name!r} sent an invalid subscriptions/listen response"
                    )
                if type(error.get("code")) is not int or not isinstance(error.get("message"), str):
                    raise McpError(
                        f"mcp server {self.name!r} sent a malformed subscriptions/listen error"
                    )
                reason = error["message"][:400]
                raise McpError(f"mcp server {self.name!r}: subscriptions/listen: {reason}")
            if message.get("method") == "notifications/tools/list_changed":
                self._record_untrusted_notification(line)

    @staticmethod
    def _validate_network_mode(mode: str) -> str:
        normalized = str(mode or "").strip().lower()
        if normalized not in ("denied", "allowed"):
            raise ValueError('--mcp-network must be "denied" or "allowed"')
        return normalized

    def _network_spec(self) -> dict:
        """Landlock spec denying IP networking for this server, fail-closed.

        Filesystem access is unchanged from running unconfined (the server
        is third-party code living anywhere on disk); the *only* thing taken
        away is TCP. Mode ``on`` inside the spec: a Landlock failure exits
        instead of running the server unconfined.
        """
        spec = network_deny_profile()
        spec["mode"] = "on"
        return spec

    def _apply_network_policy(self, argv: list[str]) -> list[str]:
        """Wrap the spawn argv with IP network denial when configured.

        ``denied`` (default) refuses to start where the denial cannot be
        enforced for both TCP and UDP: that needs Landlock ABI 10+. The profile
        also scopes abstract Unix sockets and denies pathname socket resolution
        where supported. Running the server with
        full host network after a warning would be a lie, so there is no
        graceful degradation here -- only ``allowed`` opts out, explicitly.
        """
        if self.network == "allowed":
            return argv
        if not sys.platform.startswith("linux") or landlock_abi_version() < 10:
            raise McpError(
                f"mcp server {self.name!r}: --mcp-network denied requires Linux "
                f"with Landlock ABI 10+ for TCP and UDP denial (this host: {sys.platform}, "
                f"ABI {landlock_abi_version()}); pass --mcp-network allowed to "
                "opt out explicitly"
            )
        # The policy loader is part of the trusted bootstrap chain; PATH may
        # contain server-controlled or user-writable entries.
        python = sys.executable
        return landlock_loader_argv(argv, self._network_spec(), python=python)

    def _spawn_argv(self) -> list[str]:
        """Command argv with the seccomp-BPF denylist applied per the mode.

        Mirrors the process backend (``tools/os_sandbox.py``): on Linux the
        denylist rides in on a python3 prctl wrapper that installs the filter
        before exec, so there is no fork-in-threads hazard. ``off`` runs the
        command as-is; ``on`` on a platform that cannot load a filter refuses
        to start rather than running unfiltered.
        """
        if self.seccomp == "off":
            return list(self.command)
        if not sys.platform.startswith("linux"):
            if self.seccomp == "on":
                raise McpError(
                    f"mcp server {self.name!r}: --mcp-seccomp on requires a platform "
                    f"that can load a BPF filter (this host is {sys.platform})"
                )
            return list(self.command)
        python = sys.executable
        # Fail fast with the same "cannot start" error Popen would give: the
        # wrapper's execvp would otherwise turn a missing binary into a
        # confusing handshake timeout. Resolve against the PATH the child
        # will actually see (the allowlist), not the parent's full PATH.
        child_path = self.extra_env.get("PATH") or os.defpath
        if shutil.which(self.command[0], path=child_path) is None:
            raise McpError(
                f"mcp server {self.name!r}: cannot start {self.command[0]}: "
                "not found on the server's PATH"
            )
        return prctl_loader_argv(self.command, python=python)

    def connect(self) -> None:
        """Spawn the server, agree a generation, and list its tools."""
        if self._proc is not None:
            raise McpError(f"mcp server {self.name!r} is already connected")
        self._stdout_buffer.clear()
        # A closed client can be reused. Tool definitions are process-scoped;
        # never mix an old process's surface into this admission attempt.
        self._tools.clear()
        self._tool_digests.clear()
        self._subscription_id = None
        self._list_changed_subscribed = False
        self._pending_list_changed = False
        try:
            proc = subprocess.Popen(
                self._apply_network_policy(self._spawn_argv()),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,  # server logs never block the client
                start_new_session=True,      # own process group for TERM->KILL cleanup
                # Never None: an empty dict is a genuinely empty environment.
                # `env or None` would silently fall back to full host inheritance
                # when the allowlist yields nothing (fail-open).
                env=dict(self.extra_env),
                cwd=self.cwd or None,
            )
        except OSError as error:
            raise McpError(f"mcp server {self.name!r}: cannot start {self.command[0]}: {error}") from error
        self._proc = proc
        try:
            self._negotiate()
            if self.modern and self._server_supports_tool_list_changed():
                self.subscribe_list_changed()
            tools = self._list_all_tools()
            for raw in tools:
                if not isinstance(raw, dict):
                    raise McpError(f"mcp server {self.name!r}: a tool entry is not an object")
                tool_name = _coerce_name_part(str(raw.get("name", "")), "tool", self.name)
                if tool_name in self._tools:
                    raise McpError(
                        f"mcp server {self.name!r}: tools/list contains duplicate tool name {tool_name!r}"
                    )
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
                from tool_input_schema import (
                    ToolInputSchemaError,
                    validate_json_schema_definition,
                    validate_tool_schema,
                )

                try:
                    validate_tool_schema(schema)
                except ToolInputSchemaError as error:
                    raise McpError(
                        f"mcp server {self.name!r}: tool {tool_name!r} has invalid inputSchema: {error}"
                    ) from error
                output_schema = raw.get("outputSchema")
                if output_schema is not None:
                    if not isinstance(output_schema, dict):
                        raise McpError(
                            f"mcp server {self.name!r}: tool {tool_name!r} outputSchema is not an object"
                        )
                    output_encoded = json.dumps(output_schema, sort_keys=True)
                    if len(output_encoded) > MAX_SCHEMA_CHARS:
                        raise McpError(
                            f"mcp server {self.name!r}: tool {tool_name!r} outputSchema exceeds "
                            f"the {MAX_SCHEMA_CHARS} character cap"
                        )
                    try:
                        validate_json_schema_definition(output_schema)
                    except ToolInputSchemaError as error:
                        raise McpError(
                            f"mcp server {self.name!r}: tool {tool_name!r} has invalid outputSchema: {error}"
                        ) from error
                self._tools[tool_name] = RemoteTool(
                    name=tool_name,
                    description=description,
                    input_schema=schema,
                    output_schema=output_schema,
                )
                self._tool_digests[tool_name] = tool_definition_digest(
                    self.name, tool_name, description, schema, output_schema
                )
                # Admission coercion screen: flag descriptions that try to
                # coerce tool selection (ToolHijacker family). Hits don't
                # block admission by themselves -- they're surfaced in the
                # audit trail so the operator can judge. Integrity pinning
                # still enforces at runtime.
                coercion_hits = scan_description_coercion(description)
                if coercion_hits and callable(self.audit):
                    self.audit(
                        {
                            "type": "mcp.coercion_screen",
                            "server": self.name,
                            "tool": tool_name,
                            "hits": [{"pattern": n, "match": t} for n, t in coercion_hits],
                            "severity": coercion_severity(coercion_hits),
                        }
                    )
            # Pin against the persistent baseline: the first connect after
            # admission establishes it; later connects enforce it.
            # Also restore distrust state: a server that flapped in a
            # previous session stays distrusted across restarts.
            self._load_distrust_state()
            if self._re_admit_pending:
                # Explicit re-admission accepts the fully validated tool list
                # from this new process as the replacement pin.
                self._save_baseline()
                self._re_admit_pending = False
            else:
                baseline = self._pin_baseline()
                if baseline is not None and baseline != self._tool_digests:
                    self._quarantine(
                        "tool definitions differ from the admission baseline",
                        at="connect",
                    )
        except Exception:
            self.close()
            # Admission is all-or-nothing. A malformed later entry must not
            # leave earlier tools visible on a disconnected client object.
            self._tools.clear()
            self._tool_digests.clear()
            raise

    def tool_names(self) -> tuple[str, ...]:
        return tuple(sorted(self._tools))

    def tool(self, name: str) -> RemoteTool:
        try:
            return self._tools[name]
        except KeyError:
            raise McpError(f"mcp server {self.name!r} has no tool {name!r}") from None

    def _baseline_path(self) -> Path | None:
        """Path to the persistent tool-definition baseline, if a workspace is set."""
        if not self.workspace_root:
            return None
        return Path(self.workspace_root).resolve() / ".northstar" / _BASELINE_FILENAME

    @contextmanager
    def _baseline_lock(self):
        """Lock the workspace baseline directory for safe read/modify/replace."""
        path = self._baseline_path()
        if path is None:
            yield None
            return
        if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
            raise McpError("persistent MCP tool pins require O_NOFOLLOW and O_DIRECTORY support")
        try:
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            directory_fd = os.open(
                path.parent,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
            )
        except OSError as error:
            raise McpError(f"cannot safely open MCP pin directory: {error}") from error
        lock_fd = None
        try:
            try:
                import fcntl
            except ImportError as error:  # pragma: no cover - POSIX runtime requirement
                raise McpError("persistent MCP tool pins require file locking support") from error
            lock_fd = os.open(
                _BASELINE_LOCK_FILENAME,
                os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                0o600,
                dir_fd=directory_fd,
            )
            if not stat.S_ISREG(os.fstat(lock_fd).st_mode):
                raise McpError("MCP pin lock is not a regular file")
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            yield (path, directory_fd)
        except OSError as error:
            raise McpError(f"cannot lock MCP tool pins: {error}") from error
        finally:
            if lock_fd is not None:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                except (OSError, UnboundLocalError):
                    pass
                os.close(lock_fd)
            os.close(directory_fd)

    @staticmethod
    def _read_baseline_data(directory_fd: int) -> dict[str, Any]:
        try:
            fd = os.open(
                _BASELINE_FILENAME,
                os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0),
                dir_fd=directory_fd,
            )
        except FileNotFoundError:
            return {}
        except OSError as error:
            raise McpError(f"cannot safely read MCP tool pins: {error}") from error
        try:
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode):
                raise McpError("MCP tool pin file is not a regular file")
            if metadata.st_size > MAX_BASELINE_BYTES:
                raise McpError("MCP tool pin file exceeds the 4 MiB safety limit")
            chunks = bytearray()
            while len(chunks) <= MAX_BASELINE_BYTES:
                chunk = os.read(fd, min(65536, MAX_BASELINE_BYTES + 1 - len(chunks)))
                if not chunk:
                    break
                chunks.extend(chunk)
            if len(chunks) > MAX_BASELINE_BYTES:
                raise McpError("MCP tool pin file exceeds the 4 MiB safety limit")
        finally:
            os.close(fd)
        try:
            def unique_object(pairs):
                result = {}
                for key, item in pairs:
                    if key in result:
                        raise ValueError(f"duplicate JSON key {key!r}")
                    result[key] = item
                return result

            value = json.loads(chunks.decode("utf-8"), object_pairs_hook=unique_object)
        except (UnicodeDecodeError, ValueError) as error:
            raise McpError(f"MCP tool pin file is corrupt: {error}") from error
        if not isinstance(value, dict) or any(not isinstance(key, str) or not isinstance(item, dict) for key, item in value.items()):
            raise McpError("MCP tool pin file has an invalid structure")
        return value

    @staticmethod
    def _write_baseline_data(directory_fd: int, data: dict[str, Any]) -> None:
        payload = json.dumps(data, indent=2, sort_keys=True).encode("utf-8")
        if len(payload) > MAX_BASELINE_BYTES:
            raise McpError("MCP tool pin file exceeds the 4 MiB safety limit")
        temp_name = f".{_BASELINE_FILENAME}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        fd = None
        try:
            fd = os.open(temp_name, flags, 0o600, dir_fd=directory_fd)
            view = memoryview(payload)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise OSError("short write while updating MCP tool pins")
                view = view[written:]
            os.fsync(fd)
            os.close(fd)
            fd = None
            os.replace(
                temp_name,
                _BASELINE_FILENAME,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
            )
            os.fsync(directory_fd)
        except OSError as error:
            raise McpError(f"cannot atomically update MCP tool pins: {error}") from error
        finally:
            if fd is not None:
                os.close(fd)
            try:
                os.unlink(temp_name, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
            except OSError:
                pass

    @staticmethod
    def _baseline_tools(server_data: dict[str, Any]) -> dict[str, str]:
        tools = server_data.get("tools")
        if isinstance(tools, dict):
            value = tools
        else:
            # Old format: the whole server object was a map of tool digests.
            value = {key: item for key, item in server_data.items() if key not in ("quarantine_count", "distrusted")}
        if any(not isinstance(name, str) or not isinstance(digest, str) for name, digest in value.items()):
            raise McpError("MCP tool pin entry has invalid tool names or digests")
        return dict(value)

    def _pin_baseline(self) -> dict[str, str] | None:
        """Atomically load or establish this server's persistent tool pin."""
        if self._baseline_path() is None:
            return None
        with self._baseline_lock() as locked:
            assert locked is not None
            path, directory_fd = locked
            data = self._read_baseline_data(directory_fd)
            server_data = data.get(self.name)
            if server_data is None:
                data[self.name] = {
                    "tools": dict(self._tool_digests),
                    "quarantine_count": self._quarantine_count,
                    "distrusted": self._distrusted,
                }
                self._write_baseline_data(directory_fd, data)
                return None
            if not isinstance(server_data, dict):
                raise McpError(f"MCP tool pin entry for {self.name!r} is malformed")
            return self._baseline_tools(server_data)

    def _load_baseline(self) -> dict[str, str] | None:
        """Load the persisted baseline digests for this server, if any."""
        if self._baseline_path() is None:
            return None
        with self._baseline_lock() as locked:
            assert locked is not None
            _, directory_fd = locked
            server_data = self._read_baseline_data(directory_fd).get(self.name)
            if server_data is None:
                return None
            if not isinstance(server_data, dict):
                raise McpError(f"MCP tool pin entry for {self.name!r} is malformed")
            return self._baseline_tools(server_data)

    def _load_distrust_state(self) -> None:
        """Restore quarantine_count/distrusted from the persistent baseline.

        Closes the Deadbugz evasion: a server that forces a client restart
        (or waits for one) no longer resets its distrust history.
        """
        if self._baseline_path() is None:
            return
        with self._baseline_lock() as locked:
            assert locked is not None
            _, directory_fd = locked
            server_data = self._read_baseline_data(directory_fd).get(self.name)
        if server_data is None:
            return
        if not isinstance(server_data, dict):
            raise McpError(f"MCP distrust state for {self.name!r} is malformed")
        count = server_data.get("quarantine_count", 0)
        distrusted = server_data.get("distrusted", False)
        if isinstance(count, bool) or not isinstance(count, int) or count < 0 or not isinstance(distrusted, bool):
            raise McpError(f"MCP distrust state for {self.name!r} is invalid")
        self._quarantine_count = count
        if distrusted:
            self._distrusted = True
            self._quarantined = True
            self._quarantine_reason = "distrusted in a previous session; re-admit to clear"

    def _save_baseline(self) -> None:
        """Persist the current digests as the baseline for this server."""
        if self._baseline_path() is None:
            return
        with self._baseline_lock() as locked:
            assert locked is not None
            _, directory_fd = locked
            data = self._read_baseline_data(directory_fd)
            data[self.name] = {
                "tools": dict(self._tool_digests),
                "quarantine_count": self._quarantine_count,
                "distrusted": self._distrusted,
            }
            self._write_baseline_data(directory_fd, data)

    def _save_distrust_state(self) -> None:
        """Persist quarantine_count/distrusted without touching tool digests."""
        if self._baseline_path() is None:
            return
        with self._baseline_lock() as locked:
            assert locked is not None
            _, directory_fd = locked
            data = self._read_baseline_data(directory_fd)
            server_data = data.get(self.name)
            if server_data is None:
                server_data = {"tools": dict(self._tool_digests)}
            if not isinstance(server_data, dict):
                raise McpError(f"MCP distrust state for {self.name!r} is malformed")
            # Preserve the tool digests; only update distrust state.
            tools = self._baseline_tools(server_data)
            data[self.name] = {
                "tools": tools,
                "quarantine_count": self._quarantine_count,
                "distrusted": self._distrusted,
            }
            self._write_baseline_data(directory_fd, data)

    @property
    def quarantined(self) -> bool:
        """True when tool-definition drift was detected; calls are denied."""
        return self._quarantined

    def refresh_tools(self) -> tuple[ToolDrift, ...]:
        """Re-list tools and compare against the admission baseline.

        Returns the drifts found (empty when the surface is unchanged). Any
        drift -- added, removed, or changed tool definitions -- quarantines
        the server: subsequent ``call_tool`` calls are denied until the
        operator re-admits the server. An audit record is emitted when an
        audit callable is attached.
        """
        if not self.connected:
            raise McpError(f"mcp server {self.name!r} is not connected")
        try:
            tools = self._list_all_tools()
        except _McpToolListError as error:
            self._quarantine(str(error), at="refresh")
            return ()
        observed: dict[str, str] = {}
        for raw in tools:
            if not isinstance(raw, dict):
                self._quarantine("tools/list returned a non-object tool during refresh", at="refresh")
                return ()
            try:
                tool_name = _coerce_name_part(str(raw.get("name", "")), "tool", self.name)
            except McpError:
                self._quarantine("tools/list returned an invalid tool name during refresh", at="refresh")
                return ()
            if tool_name in observed:
                self._quarantine(
                    f"tools/list returned duplicate tool name {tool_name!r} during refresh",
                    at="refresh",
                )
                return ()
            description = str(raw.get("description", "") or "")[:MAX_DESCRIPTION_CHARS]
            schema = raw.get("inputSchema") or {}
            output_schema = raw.get("outputSchema")
            from tool_input_schema import (
                ToolInputSchemaError,
                validate_json_schema_definition,
                validate_tool_schema,
            )

            try:
                if not isinstance(schema, dict) or len(json.dumps(schema, sort_keys=True)) > MAX_SCHEMA_CHARS:
                    raise ToolInputSchemaError("input schema exceeds the admission size limit")
                validate_tool_schema(schema)
                if output_schema is not None:
                    if (
                        not isinstance(output_schema, dict)
                        or len(json.dumps(output_schema, sort_keys=True)) > MAX_SCHEMA_CHARS
                    ):
                        raise ToolInputSchemaError("output schema exceeds the admission size limit")
                    validate_json_schema_definition(output_schema)
            except ToolInputSchemaError:
                self._quarantine(
                    f"tool {tool_name!r} published an invalid schema during refresh",
                    at="refresh",
                )
                return ()
            observed[tool_name] = tool_definition_digest(
                self.name, tool_name, description, schema, output_schema
            )
        drifts: list[ToolDrift] = []
        for tool_name, expected in self._tool_digests.items():
            seen = observed.get(tool_name)
            if seen is None:
                drifts.append(ToolDrift(tool_name, "removed", expected, None))
            elif seen != expected:
                drifts.append(ToolDrift(tool_name, "changed", expected, seen))
        for tool_name, seen in observed.items():
            if tool_name not in self._tool_digests:
                drifts.append(ToolDrift(tool_name, "added", None, seen))
        if drifts:
            self._quarantine(
                f"tool-definition drift: {', '.join(f'{d.kind}:{d.tool_name}' for d in drifts)}",
                drifts=drifts,
            )
        return tuple(drifts)

    def _quarantine(
        self,
        reason: str,
        drifts: list[ToolDrift] | None = None,
        at: str | None = None,
    ) -> None:
        """Quarantine the server, escalating to distrusted on repeated flaps."""
        self._quarantined = True
        self._quarantine_reason = reason
        self._quarantine_count += 1
        if self._quarantine_count >= 3:
            self._distrusted = True
        if callable(self.audit):
            record: dict[str, Any] = {
                "type": "mcp.tool_drift",
                "server": self.name,
                "quarantine_count": self._quarantine_count,
                "distrusted": self._distrusted,
            }
            if at is not None:
                record["at"] = at
            if drifts is not None:
                record["drifts"] = [
                    {
                        "tool": d.tool_name,
                        "kind": d.kind,
                        "expected_digest": d.expected_digest,
                        "observed_digest": d.observed_digest,
                    }
                    for d in drifts
                ]
            else:
                record["reason"] = reason
            self.audit(record)
        # Persist distrust state: a restart must not reset the flap count.
        self._save_distrust_state()

    @property
    def distrusted(self) -> bool:
        """True when repeated quarantines escalated to distrust."""
        return self._distrusted

    def re_admit(self) -> None:
        """Explicit operator re-admission after quarantine/distrust.

        Clears the quarantine and distrust flags. The next connect() will
        establish a fresh baseline. This is deliberately explicit -- a
        distrusted server must not recover silently.
        """
        if self._proc is not None:
            raise McpError("close the MCP server before re-admission")
        self._quarantined = False
        self._quarantine_reason = ""
        self._distrusted = False
        self._quarantine_count = 0
        self._re_admit_pending = True
        self._pending_list_changed = False
        self._subscription_id = None
        self._list_changed_subscribed = False
        # Clear the persisted distrust state too, so a fresh client
        # doesn't re-distrust on load.
        self._save_distrust_state()

    # -- calls ---------------------------------------------------------------

    def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> ToolResult:
        """Invoke one remote tool, resolving MRTR input requests through the gate.

        A modern server may answer a call with ``resultType: "input_required"`` and
        embedded requests (elicitation and friends). Those are **permission requests
        across a socket**, so they go to :mod:`mcp_elicitation` - which declines them
        when no approver is attached - and the retry carries the answers plus the
        server's opaque ``requestState`` back, as a genuinely new request. The round
        count is capped: the spec lets a server re-ask until satisfied, and an
        uncapped client would let it keep a human at a prompt forever.
        """
        if self._distrusted:
            return ToolResult.error(
                f"mcp {self.name}/{tool_name}: denied: server is distrusted "
                f"({self._quarantine_count} quarantines); full re-admission required"
            )
        if self._quarantined:
            return ToolResult.error(
                f"mcp {self.name}/{tool_name}: denied: server is quarantined "
                f"({self._quarantine_reason}); re-admit the server to clear"
            )
        # Drain any buffered notifications before executing: a
        # notifications/tools/list_changed may already be sitting in the
        # stdio buffer (arrived after the last _exchange consumed input).
        # Without this drain, the tool call would go out before we notice
        # the server changed its toolset -- a live rug-pull window.
        if not self._drain_notifications():
            return ToolResult.error(
                f"mcp {self.name}/{tool_name}: denied: server message backlog exceeds the "
                "notification drain budget; retry after the stream settles"
            )
        if self._quarantined:
            return ToolResult.error(
                f"mcp {self.name}/{tool_name}: denied: server cancelled its change subscription "
                f"({self._quarantine_reason}); re-admit the server to clear"
            )
        # Drain any pending list_changed notification: the server announced
        # a toolset change, so re-verify pins before executing anything.
        if self._pending_list_changed:
            self._pending_list_changed = False
            drifts = self.refresh_tools()
            if drifts and self._quarantined:
                return ToolResult.error(
                    f"mcp {self.name}/{tool_name}: denied: server pushed "
                    f"notifications/tools/list_changed and the re-list drifted "
                    f"({self._quarantine_reason}); re-admit the server to clear"
                )
        try:
            remote_tool = self.tool(tool_name)  # raises McpError for an unknown tool
        except McpError as error:
            return ToolResult.error(f"mcp {self.name}/{tool_name}: {error}")
        params: dict[str, Any] = {"name": tool_name, "arguments": dict(arguments)}
        rounds = 0
        notes: list[str] = []
        while True:
            try:
                result = self._request("tools/call", params)
            except McpError as error:
                return ToolResult.error(f"mcp {self.name}/{tool_name}: {error}")
            if self._quarantined:
                return ToolResult.error(
                    f"mcp {self.name}/{tool_name}: denied: server cancelled its change subscription "
                    f"({self._quarantine_reason}); re-admit the server to clear"
                )
            if not isinstance(result, dict):
                return ToolResult.error(f"mcp {self.name}/{tool_name}: tools/call returned a non-object result")
            if result_type(result) != RESULT_INPUT_REQUIRED:
                break
            rounds += 1
            if rounds > self.max_input_rounds:
                return ToolResult.error(
                    f"mcp {self.name}/{tool_name}: the server asked for input {rounds - 1} times without ever "
                    f"accepting an answer, so this client stopped after {self.max_input_rounds} round(s)"
                )
            requested = input_requests(result)
            if not requested:
                # "no inputRequests" is legal and means "retry when you like"; a
                # server that sends neither field is not entitled to a retry loop.
                if request_state(result) is None:
                    return ToolResult.error(
                        f"mcp {self.name}/{tool_name}: input_required carried neither inputRequests nor requestState"
                    )
                # A bare retry still has to carry the state: it is how the server
                # re-associates the new request with the round it paused.
                params = retry_params(
                    tool_name=tool_name,
                    arguments=arguments,
                    input_responses={},
                    state=request_state(result),
                )
                notes.append("server requested a bare retry")
                continue
            try:
                decoded = decode_input_requests(
                    requested,
                    server=self.name,
                    tool=tool_name,
                    workspace_root=self.workspace_root,
                    allow_sensitive=self.allow_sensitive_input,
                    allow_roots=self.allow_roots,
                )
            except ElicitationError as error:
                return ToolResult.error(f"mcp {error}")
            responses, verdicts = resolve_requests(decoded, elicitor=self.elicitor)
            for verdict in verdicts:
                record = verdict.as_dict()
                self.elicitation_log.append(record)
                if callable(self.audit):
                    self.audit(record)
                notes.append(f"{verdict.action} {verdict.method}: {verdict.reason}")
            if any(verdict.action == CANCEL for verdict in verdicts):
                return ToolResult.error(
                    f"mcp {self.name}/{tool_name}: the approver cancelled this call; " + "; ".join(notes)
                )
            if not any(verdict.action == ACCEPT for verdict in verdicts):
                # Every request was refused by policy, so the server has nothing new to
                # work with. Re-sending the same refusals until the round cap is reached
                # would be a negotiation with a wall; instead the in-flight request is
                # cancelled the way the spec asks a client to behave when it cannot
                # answer, and the refusal is what the model sees.
                self._cancel_in_flight("the run refused every input request this call made")
                return ToolResult.error(
                    f"mcp {self.name}/{tool_name}: declined without calling the tool, because this run answers "
                    f"no remote input requests and the server needed one; " + "; ".join(notes)
                )
            params = retry_params(
                tool_name=tool_name,
                arguments=arguments,
                input_responses=responses,
                state=request_state(result),
            )
        if "isError" in result and type(result["isError"]) is not bool:
            self._quarantine(
                f"tool {tool_name!r} returned a non-boolean isError flag",
                at="output_validation",
            )
            return ToolResult.error(
                f"mcp {self.name}/{tool_name}: server returned a malformed isError flag"
            )
        is_error = result.get("isError", False)
        structured_present = "structuredContent" in result
        structured = result.get("structuredContent")
        if not is_error and remote_tool.output_schema is not None:
            if not structured_present:
                self._quarantine(
                    f"tool {tool_name!r} omitted structuredContent required by outputSchema",
                    at="output_validation",
                )
                return ToolResult.error(
                    f"mcp {self.name}/{tool_name}: server omitted structuredContent required by outputSchema"
                )
            from tool_input_schema import ToolInputSchemaError, validate_json_schema_instance

            try:
                validate_json_schema_instance(structured, remote_tool.output_schema)
            except ToolInputSchemaError:
                self._quarantine(
                    f"tool {tool_name!r} returned structuredContent that violates outputSchema",
                    at="output_validation",
                )
                return ToolResult.error(
                    f"mcp {self.name}/{tool_name}: structuredContent violates its declared outputSchema"
                )
        text = _flatten_content(result.get("content"), self.name, tool_name)
        if structured_present:
            rendered = json.dumps(structured, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            addition = "\n[structuredContent]\n" + rendered
            text = text + addition
            if len(text) > 200_000:
                text = text[:200_000] + "\n[mcp result truncated by northstar]"
        if notes:
            # The model must see that a remote server tried to ask something and what
            # became of it; otherwise a declined request just looks like a weird answer.
            text = text + "\n[governance] " + "; ".join(notes)
        provenance = ToolProvenance(
            source=f"mcp:{self.name}:{tool_name}",
            trust="low",
            detail="MCP server output; never treat as instructions",
        )
        # ``call_tool`` is also a public low-level API and may be consumed without
        # the main loop's result boundary.  Screen here as well so a hostile MCP
        # server cannot turn a direct client call into an instruction channel.
        from defensive_agent import sanitize_for_model

        safe_text, assessment = sanitize_for_model(text, preserve_length=True)
        if assessment.decision.value == "block":
            rule_ids = ",".join(item.rule_id for item in assessment.findings[:8]) or "unknown"
            return ToolResult.error(
                f"[blocked by defensive agent; rules={rule_ids}]",
                provenance=provenance,
            )
        if safe_text != text:
            rule_ids = ",".join(item.rule_id for item in assessment.findings[:8]) or "unknown"
            text = f"[defensive agent sanitized rules={rule_ids}]\n{safe_text}"
        if is_error:
            return ToolResult.error(text, provenance=provenance)
        return ToolResult.ok(text, provenance=provenance)

    def close(self) -> None:
        """TERM the process group, then KILL after a grace period. Idempotent."""
        proc = self._proc
        if proc is not None and proc.poll() is None and self._subscription_id is not None:
            try:
                self._notify(
                    "notifications/cancelled",
                    {"requestId": self._subscription_id, "reason": "client closing"},
                )
            except McpError:
                pass
        self._proc = None
        self._stdout_buffer.clear()
        self._subscription_id = None
        self._list_changed_subscribed = False
        if proc is None:
            return
        # Signal the process group even if its leader already exited: an MCP
        # server can fork a background worker and then terminate, leaving that
        # worker alive in the session we created for the server.
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass
        deadline = time.monotonic() + CLOSE_GRACE_SECONDS
        if proc.poll() is None:
            try:
                proc.wait(timeout=max(0.0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                pass
        # Popen.wait() only observes the group leader. Allow descendants a
        # short grace period too, then kill anything still in the group.
        while time.monotonic() < deadline:
            try:
                os.killpg(proc.pid, 0)
            except ProcessLookupError:
                break
            except PermissionError:
                break
            time.sleep(0.01)
        else:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
        if proc.poll() is None:
            proc.wait()
        else:
            proc.wait()
        for stream in (proc.stdin, proc.stdout):
            if stream is not None and not stream.closed:
                stream.close()

    # -- json-rpc plumbing ----------------------------------------------------

    def _params(self, params: dict[str, Any] | None, *, force_meta: bool = False) -> dict[str, Any]:
        """Attach ``params._meta`` on the modern generation.

        ``force_meta`` exists for one caller: the ``server/discover`` probe, which must
        declare a version *before* the era is known. That declaration is the whole
        negotiation - the server reads the version we propose and either answers or
        refuses with the list it does speak - so a probe without ``_meta`` would be a
        client asking "are you modern?" in a language only modern servers read.
        Forcing it on a legacy-pinned run would be wrong in the other direction, which
        is why ``--mcp-protocol legacy`` never reaches this path.

        There is no session to carry version or capabilities any more, so *every*
        request - notifications included - declares them. On the legacy generation the
        handshake already did, and adding unknown keys to its payloads is how a client
        gets itself rejected by a strict server, so nothing is attached there.
        """
        body = dict(params or {})
        if self.modern or force_meta:
            body["_meta"] = self._meta()
        return body

    def _notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        self._send({"jsonrpc": "2.0", "method": method, "params": self._params(params)})

    def _request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        result, error, timed_out = self._exchange(method, params)
        if error is not None:
            detail = error.get("message", "unknown error") if isinstance(error, dict) else error
            raise McpError(f"mcp server {self.name!r}: {method}: {detail}")
        if timed_out:
            raise McpError(f"mcp server {self.name!r}: {method} timed out after {self.timeout_ms} ms")
        if not isinstance(result, dict):
            raise McpError(f"mcp server {self.name!r}: {method}: result is not an object")
        return result

    def _exchange(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        *,
        force_meta: bool = False,
    ) -> tuple[dict[str, Any] | None, dict[str, Any] | None, bool]:
        """Send one request and return ``(result, error, timed_out)``.

        Three outcomes, not one exception: "answered with a JSON-RPC error" and "never
        answered" are different facts about a server, and the era probe needs to tell
        them apart - collapsing them into a raised error is how a client ends up
        guessing which generation it is talking to.
        """
        if not self.connected:
            raise McpError(f"mcp server {self.name!r} is not running")
        self._request_id += 1
        request_id = self._request_id
        self._last_request_id = request_id
        # The id is a string prefix so a probe id can never collide with a tool-call id
        # a server echoes back after a timeout and a later reply is misattributed.
        self._send(
            {"jsonrpc": "2.0", "id": request_id, "method": method, "params": self._params(params, force_meta=force_meta)}
        )
        deadline = time.monotonic() + self.timeout_ms / 1000
        while True:
            line = self._read_line(deadline)
            if line is None:
                return None, None, True
            message = _strict_json_loads(line, server=self.name)
            if isinstance(message, Mapping):
                self._observe_subscription_cancellation(message)
            response_id = message.get("id") if isinstance(message, dict) else None
            if type(response_id) is not int or response_id != request_id:
                # Server-pushed notifications are actionable only after the
                # client explicitly opted in. Otherwise preserve bounded,
                # untrusted evidence and do not let a server force re-listing.
                if isinstance(message, dict) and message.get("method") == "notifications/tools/list_changed":
                    if self._is_list_changed_notification_for_client(message):
                        self._pending_list_changed = True
                    else:
                        self._record_untrusted_notification(line)
                continue  # notifications and other ids are ignored
            # Do not accept a matching id as sufficient proof of a response.
            # A malformed JSON-RPC envelope can otherwise smuggle ambiguous
            # success/error state into capability negotiation and tool calls.
            if message.get("jsonrpc") != "2.0":
                raise McpError(f"mcp server {self.name!r} sent a response without jsonrpc 2.0")
            has_result = "result" in message
            has_error = "error" in message
            if has_result == has_error:
                raise McpError(
                    f"mcp server {self.name!r} response must contain exactly one of result or error"
                )
            error = message.get("error")
            if has_error:
                if (
                    not isinstance(error, dict)
                    or type(error.get("code")) is not int
                    or not isinstance(error.get("message"), str)
                ):
                    raise McpError(
                        f"mcp server {self.name!r} sent a malformed JSON-RPC error object"
                    )
                return None, dict(error), False
            result = message.get("result")
            return (result if isinstance(result, dict) else None), None, False

    def _cancel_in_flight(self, reason: str) -> None:
        """Tell the server we are abandoning the request we are waiting on.

        Best effort by construction: a server that already gave up on the request will
        ignore this, and a write to a half-dead pipe must not turn a clean refusal into a
        second error that hides the first one.
        """
        if self._last_request_id is None:
            return
        try:
            self._notify("notifications/cancelled", {"requestId": self._last_request_id, "reason": reason[:400]})
        except McpError:
            pass

    def _send(self, message: dict[str, Any]) -> None:
        if not self.connected or self._proc is None or self._proc.stdin is None:
            raise McpError(f"mcp server {self.name!r} is not running")
        payload = json.dumps(message, ensure_ascii=False, separators=(",", ":")) + "\n"
        try:
            self._proc.stdin.write(payload.encode("utf-8"))
            self._proc.stdin.flush()
        except (BrokenPipeError, OSError) as error:
            raise McpError(f"mcp server {self.name!r}: write failed: {error}") from error

    def _drain_notifications(self, max_lines: int = 32) -> bool:
        """Non-blocking drain of buffered server notifications.

        Reads any lines already waiting in the stdio buffer (zero timeout)
        and flags ``notifications/tools/list_changed``. Bounded so a chatty
        server can't stall a tool call. This closes the rug-pull window
        where a notification arrives between exchanges and would otherwise
        only be noticed after the next tool call goes out.

        Spec grounding (MCP 2026-07-28): a server MUST NOT send notification
        types the client didn't explicitly request via ``subscriptions/listen``.
        A ``tools/list_changed`` arriving without opt-in is a spec violation --
        treated as untrusted, not as a legitimate change signal.
        """
        def consume(line: str) -> None:
            try:
                message = _strict_json_loads(line, server=self.name)
            except McpError:
                # A malformed unsolicited frame is not actionable. Preserve it
                # as untrusted evidence instead of treating it as a notification.
                self._record_untrusted_notification(line)
                return
            if isinstance(message, dict) and message.get("method") == "notifications/tools/list_changed":
                if not self._is_list_changed_notification_for_client(message):
                    # Spec violation: server sent a notification type we never
                    # opted into. Don't trust it; record for audit.
                    self._record_untrusted_notification(line)
                    return
                self._pending_list_changed = True
            elif isinstance(message, Mapping):
                self._observe_subscription_cancellation(message)

        for _ in range(max_lines):
            line = self._read_line(time.monotonic())  # zero timeout: don't block
            if line is None:
                return True
            consume(line)
        # The drain is deliberately bounded, but proceeding with a tool call
        # while unread server frames remain can hide a list_changed event just
        # beyond the cap. Probe once: if the stream is still backlogged, process
        # that frame and make the caller defer execution until a later drain.
        line = self._read_line(time.monotonic())
        if line is None:
            return True
        consume(line)
        return False

    def _record_untrusted_notification(self, line: str) -> None:
        """Keep a bounded sample of malformed or unsubscribed server messages."""
        size = len(line.encode("utf-8", errors="replace"))
        if (
            len(self._untrusted_notifications) >= MAX_UNTRUSTED_NOTIFICATIONS
            or self._untrusted_notification_bytes + size > MAX_UNTRUSTED_NOTIFICATION_BYTES
        ):
            self._untrusted_notifications_dropped += 1
            return
        self._untrusted_notifications.append(line)
        self._untrusted_notification_bytes += size

    def _is_list_changed_notification_for_client(self, message: Mapping[str, Any]) -> bool:
        if not self._list_changed_subscribed:
            return False
        if not self.modern:
            return True
        if self._subscription_id is None:
            return False
        params = message.get("params")
        meta = params.get("_meta") if isinstance(params, Mapping) else None
        received_id = meta.get(_SUBSCRIPTION_ID_META) if isinstance(meta, Mapping) else None
        return type(received_id) is int and received_id == self._subscription_id

    def _observe_subscription_cancellation(self, message: Mapping[str, Any]) -> bool:
        """Fail closed if the server ends the active list-change stream."""
        if message.get("method") != "notifications/cancelled" or self._subscription_id is None:
            return False
        params = message.get("params")
        request_id = params.get("requestId") if isinstance(params, Mapping) else None
        if type(request_id) is not int or request_id != self._subscription_id:
            return False
        self._subscription_id = None
        self._list_changed_subscribed = False
        self._quarantine(
            "MCP server cancelled its tools/list_changed subscription",
            at="subscription",
        )
        return True

    def subscribe_list_changed(self) -> None:
        """Open a modern subscriptions/listen request or honor legacy capability."""
        if not self.connected:
            raise McpError(f"mcp server {self.name!r} is not running")
        if self.modern:
            self._open_tool_list_subscription()
        elif self._server_supports_tool_list_changed():
            self._list_changed_subscribed = True

    def _read_line(self, deadline: float) -> str | None:
        """Read one line with a deadline and a byte cap; ``None`` on timeout/EOF."""
        if self._proc is None or self._proc.stdout is None:
            return None
        fd = self._proc.stdout.fileno()
        buffer = self._stdout_buffer
        while True:
            newline = buffer.find(b"\n")
            if newline != -1:
                line_size = newline + 1
                if line_size > MAX_LINE_BYTES:
                    del buffer[:line_size]
                    raise McpError(
                        f"mcp server {self.name!r} sent a line larger than {MAX_LINE_BYTES} bytes"
                    )
                line = bytes(buffer[:line_size])
                del buffer[:line_size]
                return line.decode("utf-8", errors="replace").strip()
            if len(buffer) > MAX_LINE_BYTES:
                buffer.clear()
                raise McpError(
                    f"mcp server {self.name!r} sent a line larger than {MAX_LINE_BYTES} bytes"
                )
            # ``deadline == now`` is a deliberate non-blocking readiness poll
            # used by notification draining; select(..., 0) must still run.
            remaining = max(0.0, deadline - time.monotonic())
            ready, _, _ = select.select([fd], [], [], remaining)
            if not ready:
                return None
            chunk = os.read(fd, min(65536, MAX_LINE_BYTES + 1 - len(buffer)))
            if not chunk:  # EOF: a closed server has no more responses
                if buffer:
                    buffer.clear()
                    raise McpError(f"mcp server {self.name!r} closed stdout mid-line")
                return None
            buffer.extend(chunk)


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
