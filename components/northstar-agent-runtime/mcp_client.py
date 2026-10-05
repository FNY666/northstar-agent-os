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
import json
import os
import re
import select
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
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


@dataclass
class RemoteTool:
    name: str
    description: str
    input_schema: dict[str, Any]
    annotations: dict[str, Any] = field(default_factory=dict)


def tool_definition_digest(
    server: str, name: str, description: str, input_schema: Mapping[str, Any]
) -> str:
    """Canonical digest pinning one MCP tool's definition.

    Covers ``(server identity, tool name, description, input_schema)`` with
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
    return hashlib.sha256(_jcs(payload)).hexdigest()


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
        self._request_id = 0
        self._last_request_id: int | None = None
        self._tools: dict[str, RemoteTool] = {}
        # Tool-definition pinning: digests captured at connect() time. Any
        # drift detected by refresh_tools() quarantines the server.
        self._tool_digests: dict[str, str] = {}
        self._quarantined: bool = False
        self._quarantine_reason: str = ""
        # Set when the server pushes notifications/tools/list_changed. The
        # next call_tool() drains it via refresh_tools() so a live rug-pull
        # is caught even between manual refreshes.
        self._pending_list_changed: bool = False
        self._info = {"name": "northstar-agent-runtime", "version": __version__}

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
        self._notify("notifications/initialized")

    @staticmethod
    def _validate_network_mode(mode: str) -> str:
        normalized = str(mode or "").strip().lower()
        if normalized not in ("denied", "allowed"):
            raise ValueError('--mcp-network must be "denied" or "allowed"')
        return normalized

    def _network_spec(self) -> dict:
        """Landlock spec denying TCP for this server, fail-closed.

        Filesystem access is unchanged from running unconfined (the server
        is third-party code living anywhere on disk); the *only* thing taken
        away is TCP. Mode ``on`` inside the spec: a Landlock failure exits
        instead of running the server unconfined.
        """
        spec = network_deny_profile()
        spec["mode"] = "on"
        return spec

    def _apply_network_policy(self, argv: list[str]) -> list[str]:
        """Wrap the spawn argv with network denial when configured.

        ``denied`` (default) refuses to start where the denial cannot be
        enforced: TCP denial needs Landlock ABI 4+. Running the server with
        full host network after a warning would be a lie, so there is no
        graceful degradation here -- only ``allowed`` opts out, explicitly.
        """
        if self.network == "allowed":
            return argv
        if not sys.platform.startswith("linux") or landlock_abi_version() < 4:
            raise McpError(
                f"mcp server {self.name!r}: --mcp-network denied requires Linux "
                f"with Landlock ABI 4+ for TCP denial (this host: {sys.platform}, "
                f"ABI {landlock_abi_version()}); pass --mcp-network allowed to "
                "opt out explicitly"
            )
        python = shutil.which("python3") or sys.executable
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
        python = shutil.which("python3") or sys.executable
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
                self._tool_digests[tool_name] = tool_definition_digest(
                    self.name, tool_name, description, schema
                )
            # Pin against the persistent baseline: the first connect after
            # admission establishes it; later connects enforce it.
            baseline = self._load_baseline()
            if baseline is None:
                self._save_baseline()
            elif baseline != self._tool_digests:
                self._quarantined = True
                self._quarantine_reason = "tool definitions differ from the admission baseline"
                if callable(self.audit):
                    self.audit(
                        {
                            "type": "mcp.tool_drift",
                            "server": self.name,
                            "at": "connect",
                            "reason": self._quarantine_reason,
                        }
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

    def _baseline_path(self) -> Path | None:
        """Path to the persistent tool-definition baseline, if a workspace is set."""
        if not self.workspace_root:
            return None
        return Path(self.workspace_root) / ".northstar" / "mcp-tool-baseline.json"

    def _load_baseline(self) -> dict[str, str] | None:
        """Load the persisted baseline digests for this server, if any."""
        path = self._baseline_path()
        if path is None or not path.is_file():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if not isinstance(data, dict):
            return None
        server_data = data.get(self.name)
        if not isinstance(server_data, dict):
            return None
        return {str(k): str(v) for k, v in server_data.items()}

    def _save_baseline(self) -> None:
        """Persist the current digests as the baseline for this server."""
        path = self._baseline_path()
        if path is None:
            return
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            data: dict[str, Any] = {}
            if path.is_file():
                try:
                    data = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    data = {}
            if not isinstance(data, dict):
                data = {}
            data[self.name] = dict(self._tool_digests)
            path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
        except OSError:
            pass  # Baseline persistence is best-effort; in-memory still protects this run.

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
        listed = self._request("tools/list", {})
        tools = listed.get("tools") if isinstance(listed, dict) else None
        if not isinstance(tools, list):
            raise McpError(f"mcp server {self.name!r}: tools/list must return an array")
        observed: dict[str, str] = {}
        for raw in tools:
            if not isinstance(raw, dict):
                continue
            tool_name = _coerce_name_part(str(raw.get("name", "")), "tool", self.name)
            description = str(raw.get("description", "") or "")[:MAX_DESCRIPTION_CHARS]
            schema = raw.get("inputSchema") or {}
            if not isinstance(schema, dict):
                schema = {}
            observed[tool_name] = tool_definition_digest(self.name, tool_name, description, schema)
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
            self._quarantined = True
            self._quarantine_reason = (
                f"tool-definition drift: {', '.join(f'{d.kind}:{d.tool_name}' for d in drifts)}"
            )
            if callable(self.audit):
                self.audit(
                    {
                        "type": "mcp.tool_drift",
                        "server": self.name,
                        "drifts": [
                            {
                                "tool": d.tool_name,
                                "kind": d.kind,
                                "expected_digest": d.expected_digest,
                                "observed_digest": d.observed_digest,
                            }
                            for d in drifts
                        ],
                    }
                )
        return tuple(drifts)

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
        if self._quarantined:
            return ToolResult.error(
                f"mcp {self.name}/{tool_name}: denied: server is quarantined "
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
            self.tool(tool_name)  # raises McpError for an unknown tool
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
        is_error = bool(result.get("isError"))
        text = _flatten_content(result.get("content"), self.name, tool_name)
        if notes:
            # The model must see that a remote server tried to ask something and what
            # became of it; otherwise a declined request just looks like a weird answer.
            text = text + "\n[governance] " + "; ".join(notes)
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
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                continue  # a malformed line is not our response; keep waiting
            if not isinstance(message, dict) or message.get("id") != request_id:
                # Server-pushed notification: the only one we act on is
                # tools/list_changed (live rug-pull signal). Anything else
                # is ignored as before.
                if isinstance(message, dict) and message.get("method") == "notifications/tools/list_changed":
                    self._pending_list_changed = True
                continue  # notifications and other ids are ignored
            error = message.get("error")
            if isinstance(error, dict):
                return None, dict(error), False
            if "error" in message:
                return None, {"message": str(message.get("error"))}, False
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
