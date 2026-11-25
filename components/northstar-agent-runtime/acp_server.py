"""Thin Agent Client Protocol (ACP v1) stdio adapter for Northstar Agent OS.

Exposes the governed Northstar runtime as a standard ACP v1 coding agent
(JSON-RPC 2.0 NDJSON over stdin/stdout) so compatible editors and hosts
(such as Zed, JetBrains IDEs, and Android Studio) can drive Northstar without
bypassing host governance.

Security and governance invariants enforced at the ACP boundary:

* **Single governance kernel**: every ``session/prompt`` turn runs through
  :func:`sdk.stream_run` with Northstar's permission gate, ceilings, hooks,
  workspace path containment, default-deny ``Shell``, and append-only sessions.
* **Policy may only tighten**: ACP clients cannot escalate beyond the operator's
  ``--permission-mode`` ceiling, cannot request ``bypassPermissions``, and
  cannot re-widen a session once narrowed via ``session/set_mode``.
* **No client-injected MCP servers**: non-empty ``mcpServers`` in
  ``session/new`` or ``session/load`` are refused fail-closed (``-32602``).
  MCP servers remain host-operator policy, never IDE-wire input.
* **Workspace confinement**: ``cwd`` must be an existing absolute directory and
  must stay within the operator's ``--workspace`` root when configured.
* **Bounded wire parsing**: inbound JSON-RPC lines and container nesting depth
  are bounded before dispatch.
* **Zero third-party dependencies**: pure Python standard library + Northstar
  runtime modules.
"""
from __future__ import annotations

import json
import os
import sys
import threading
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence, TextIO

from _version import __version__
from sdk import DEFAULT_MODEL, RunOptions, stream_run
from sessions import SessionIntegrityError, SessionStore

_PROVIDER_DEFAULT_MODELS: dict[str, str] = {
    "scripted": DEFAULT_MODEL,
    "anthropic": DEFAULT_MODEL,
    "openai": "gpt-4.1",
}


def _resolve_acp_model(provider: str | Any, model: str = "") -> str:
    if not isinstance(provider, str):
        return (model or "").strip() or str(getattr(provider, "model", DEFAULT_MODEL) or DEFAULT_MODEL)
    chosen = (model or "").strip() or _PROVIDER_DEFAULT_MODELS.get(provider, "")
    if not chosen:
        raise ValueError(f"unknown provider {provider!r}; no default model is configured for it")
    if provider == "openai" and chosen.startswith("claude"):
        raise ValueError(
            f"--provider openai cannot serve {chosen!r}: pass an OpenAI-compatible model id"
        )
    if provider == "anthropic" and chosen.startswith(("gpt-", "o1", "o3", "o4")):
        raise ValueError(
            f"--provider anthropic cannot serve {chosen!r}: pass a Claude model id"
        )
    return chosen

ACP_PROTOCOL_VERSION = 1

# JSON-RPC 2.0 standard and ACP server error codes.
JSONRPC_PARSE_ERROR = -32700
JSONRPC_INVALID_REQUEST = -32600
JSONRPC_METHOD_NOT_FOUND = -32601
JSONRPC_INVALID_PARAMS = -32602
JSONRPC_INTERNAL_ERROR = -32603
ACP_SERVER_ERROR = -32000
ACP_NOT_INITIALIZED = -32002

# Wire guardrails for untrusted or buggy clients.
MAX_LINE_BYTES = 1_000_000
MAX_JSON_DEPTH = 128
MAX_PROMPT_CHARS = 256_000
MAX_EMBEDDED_RESOURCE_CHARS = 64_000
MAX_TOOL_OUTPUT_PREVIEW_CHARS = 16_000

# Tighten-only permission ladder exposed over ACP (bypassPermissions is never exposed).
_MODE_SPECS: tuple[tuple[str, str, str], ...] = (
    ("plan", "Plan (Read-Only)", "Inspect repository and plan without editing files or running commands."),
    ("default", "Default (Governed)", "Read-only tools allowed; mutating tools require explicit host allow-listing."),
    ("acceptEdits", "Accept Edits", "Workspace file edits allowed under Northstar boundaries; Shell stays default-deny."),
)
_MODE_RANK: dict[str, int] = {mode_id: idx for idx, (mode_id, _, _) in enumerate(_MODE_SPECS)}

_TOOL_KIND_MAP: dict[str, str] = {
    "Read": "read",
    "LS": "read",
    "RepoMap": "read",
    "Grep": "search",
    "SearchCode": "search",
    "GitInspect": "search",
    "Edit": "edit",
    "Write": "edit",
    "ApplyPatch": "edit",
    "Shell": "execute",
    "RunCheck": "execute",
    "Fetch": "fetch",
    "SubmitPlan": "think",
    "Task": "think",
    "DescribeTools": "think",
}


class AcpProtocolError(Exception):
    """Structured JSON-RPC error returned to the ACP client."""

    def __init__(self, code: int, message: str, data: Any = None) -> None:
        super().__init__(message)
        self.code = int(code)
        self.message = str(message)
        self.data = data

    def to_rpc_error(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.data is not None:
            payload["data"] = self.data
        return payload


@dataclass(frozen=True)
class AcpServerConfig:
    """Host-operator configuration bounding every ACP session."""

    workspace: str | None = None
    provider: str = "scripted"
    model: str = ""
    base_url: str = ""
    temperature: float | None = None
    permission_mode: str = "default"
    read_only: bool = False
    allowed_tools: tuple[str, ...] = ()
    disallowed_tools: tuple[str, ...] = ()
    max_turns: int = 25
    max_tool_calls: int | None = 50
    max_budget_usd: float | None = None
    max_output_tokens: int = 4096
    shell_backend: str = "auto"
    shell_seccomp: str = "auto"
    shell_capdrop: str = "on"
    session_dir: str | None = None
    persist_sessions: bool = True
    evidence_dir: str | None = None
    evidence_required: bool = False
    code_worktree: bool = False
    keep_worktree: bool = False
    dataflow_policy: Any = None
    interactive_permissions: bool = False
    permission_timeout_seconds: float = 60.0
    workspace_agents: bool = True
    code_tools: bool = True
    scripted_turns: tuple[Any, ...] | None = None

    def resolved_dataflow_policy(self) -> Any:
        """Resolve a DataflowPolicy instance or named preset (default|camel|camel-strict|path)."""
        raw = self.dataflow_policy
        if raw is None or raw == "":
            return None
        from dataflow_policy import DataflowPolicy

        if isinstance(raw, DataflowPolicy):
            return raw
        if not isinstance(raw, str):
            raise ValueError("dataflow_policy must be a DataflowPolicy, preset name, or TOML path")
        key = raw.strip()
        if key == "default":
            return DataflowPolicy.default()
        if key == "camel":
            return DataflowPolicy.camel_default()
        if key == "camel-strict":
            return DataflowPolicy.camel_strict()
        return DataflowPolicy.from_toml_file(key)

    def effective_ceiling_mode(self) -> str:
        """Tightest operator-imposed permission mode ceiling."""
        if self.read_only or self.permission_mode == "plan":
            return "plan"
        if self.permission_mode not in _MODE_RANK:
            raise ValueError(
                f"ACP adapter does not permit permission_mode={self.permission_mode!r}; "
                "use one of: plan, default, acceptEdits"
            )
        return self.permission_mode

    def resolved_workspace_root(self) -> Path | None:
        if not self.workspace:
            return None
        root = Path(self.workspace).expanduser().resolve()
        if not root.is_dir():
            raise ValueError(f"workspace is not a directory: {root}")
        return root

    def resolved_model(self) -> str:
        return _resolve_acp_model(self.provider, self.model)

    def available_modes(self) -> list[dict[str, str]]:
        ceiling_rank = _MODE_RANK[self.effective_ceiling_mode()]
        return [
            {"id": mode_id, "name": name, "description": desc}
            for mode_id, name, desc in _MODE_SPECS
            if _MODE_RANK[mode_id] <= ceiling_rank
        ]


@dataclass
class _PendingClientRequest:
    """In-flight Agent -> Client JSON-RPC request awaiting a response."""

    session_id: str
    event: threading.Event = field(default_factory=threading.Event)
    response: dict[str, Any] | None = None
    cancelled_reason: str | None = None


@dataclass
class AcpSessionState:
    """Per-session governed runtime binding inside an ACP connection."""

    session_id: str
    cwd: Path
    session_dir: Path | None
    current_mode: str
    runtime_session_id: str | None = None
    turn_index: int = 0
    cancel_event: threading.Event = field(default_factory=threading.Event)
    turn_lock: threading.Lock = field(default_factory=threading.Lock)
    active_turn: bool = False
    isolated_workspace: Any = None
    admission_path: Path | None = None

    @property
    def execution_cwd(self) -> Path:
        if self.isolated_workspace is not None:
            return Path(self.isolated_workspace.execution_root)
        return self.cwd


def _check_json_depth(value: Any, max_depth: int = MAX_JSON_DEPTH) -> None:
    """Reject deeply nested untrusted JSON without hitting Python recursion limits."""
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        current, depth = stack.pop()
        if depth > max_depth:
            raise AcpProtocolError(
                JSONRPC_INVALID_REQUEST,
                f"JSON nesting exceeds maximum depth of {max_depth}",
            )
        if isinstance(current, dict):
            stack.extend((child, depth + 1) for child in current.values())
        elif isinstance(current, list):
            stack.extend((child, depth + 1) for child in current)


def _tool_kind(tool_name: str) -> str:
    return _TOOL_KIND_MAP.get(tool_name, "other")


def _tool_title(tool_name: str, tool_input: Any) -> str:
    """Build a concise, human-readable ACP tool-call title."""
    if isinstance(tool_input, Mapping):
        for key in ("path", "file_path", "pattern", "command", "action", "url", "query"):
            value = tool_input.get(key)
            if isinstance(value, str) and value.strip():
                snippet = " ".join(value.strip().split())
                if len(snippet) > 80:
                    snippet = snippet[:77] + "..."
                return f"{tool_name}: {snippet}"
    return tool_name


def _extract_prompt_text(blocks: Any) -> str:
    """Convert ACP v1 ContentBlock[] into one bounded user prompt string."""
    if not isinstance(blocks, list) or not blocks:
        raise AcpProtocolError(
            JSONRPC_INVALID_PARAMS,
            "prompt must be a non-empty array of ACP content blocks",
        )
    parts: list[str] = []
    total_chars = 0
    for index, block in enumerate(blocks):
        if not isinstance(block, dict):
            raise AcpProtocolError(
                JSONRPC_INVALID_PARAMS,
                f"prompt[{index}] must be a content block object",
            )
        btype = block.get("type")
        if btype == "text":
            text = block.get("text")
            if not isinstance(text, str):
                raise AcpProtocolError(
                    JSONRPC_INVALID_PARAMS,
                    f"prompt[{index}].text must be a string",
                )
            chunk = text
        elif btype == "resource":
            resource = block.get("resource")
            if not isinstance(resource, dict):
                raise AcpProtocolError(
                    JSONRPC_INVALID_PARAMS,
                    f"prompt[{index}].resource must be an object",
                )
            if "blob" in resource and "text" not in resource:
                raise AcpProtocolError(
                    JSONRPC_INVALID_PARAMS,
                    f"prompt[{index}] binary resource blobs are not supported",
                )
            uri = str(resource.get("uri") or "(unknown)")
            text = resource.get("text")
            if not isinstance(text, str):
                raise AcpProtocolError(
                    JSONRPC_INVALID_PARAMS,
                    f"prompt[{index}].resource.text must be a string",
                )
            if len(text) > MAX_EMBEDDED_RESOURCE_CHARS:
                text = text[:MAX_EMBEDDED_RESOURCE_CHARS] + "\n...[truncated]"
            chunk = f"[Embedded resource (untrusted data): {uri}]\n{text}\n[/Embedded resource]"
        elif btype == "resource_link":
            uri = str(block.get("uri") or "").strip()
            name = str(block.get("name") or uri or "resource").strip()
            if not uri:
                raise AcpProtocolError(
                    JSONRPC_INVALID_PARAMS,
                    f"prompt[{index}].uri must be a non-empty string",
                )
            chunk = f"[Resource link: {name} ({uri})]"
        else:
            raise AcpProtocolError(
                JSONRPC_INVALID_PARAMS,
                f"unsupported ACP content block type {btype!r} at prompt[{index}]",
            )
        total_chars += len(chunk)
        if total_chars > MAX_PROMPT_CHARS:
            raise AcpProtocolError(
                JSONRPC_INVALID_PARAMS,
                f"prompt exceeds maximum allowed length of {MAX_PROMPT_CHARS} characters",
            )
        parts.append(chunk)
    joined = "\n\n".join(parts).strip()
    if not joined:
        raise AcpProtocolError(
            JSONRPC_INVALID_PARAMS,
            "prompt contains no non-whitespace text",
        )
    return joined


def _map_stop_reason(subtype: str) -> str | None:
    """Map a Northstar terminal subtype to an ACP v1 StopReason (or None for RPC error)."""
    if subtype in {"success", "success_unverified"}:
        return "end_turn"
    if subtype in {"error_max_turns", "error_max_tool_calls"}:
        return "max_turn_requests"
    if subtype == "error_max_budget_usd":
        return "max_tokens"
    if subtype in {"error_permission_denied", "error_postconditions_failed"}:
        return "refusal"
    return None


def _acp_usage(total_usage: Mapping[str, Any] | None) -> dict[str, int]:
    usage = total_usage or {}
    input_tokens = int(usage.get("input_tokens") or 0)
    output_tokens = int(usage.get("output_tokens") or 0)
    cached_read = int(usage.get("cache_read_input_tokens") or 0)
    cached_write = int(usage.get("cache_creation_input_tokens") or 0)
    return {
        "inputTokens": input_tokens,
        "outputTokens": output_tokens,
        "cachedReadTokens": cached_read,
        "cachedWriteTokens": cached_write,
        "totalTokens": input_tokens + output_tokens + cached_read + cached_write,
    }


def _build_acp_provider(config: AcpServerConfig, model: str) -> str | Any:
    if config.provider == "openai":
        from providers.openai_compat import OpenAICompatProvider

        base_url = (config.base_url or os.environ.get("OPENAI_BASE_URL", "")).strip() or None
        return OpenAICompatProvider(
            model=model,
            base_url=base_url,
            max_tokens=config.max_output_tokens,
            temperature=config.temperature,
        )
    return config.provider


class AcpServer:
    """Stateful ACP v1 JSON-RPC 2.0 server wrapping Northstar's governed runtime."""

    def __init__(
        self,
        config: AcpServerConfig,
        *,
        emit: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self.config = config
        self.ceiling_mode = config.effective_ceiling_mode()
        self.workspace_root = config.resolved_workspace_root()
        self.model = config.resolved_model()
        self.dataflow_policy = config.resolved_dataflow_policy()
        if config.permission_timeout_seconds <= 0:
            raise ValueError("permission_timeout_seconds must be > 0")
        self._emit = emit or (lambda _msg: None)
        self._initialized = False
        self._client_capabilities: dict[str, Any] = {}
        self._client_info: dict[str, Any] = {}
        self._sessions: dict[str, AcpSessionState] = {}
        self._pending_requests: dict[str, _PendingClientRequest] = {}
        self._lock = threading.RLock()

    def _notify(self, method: str, params: dict[str, Any]) -> None:
        self._emit({"jsonrpc": "2.0", "method": method, "params": params})

    def _emit_session_update(self, session_id: str, update: dict[str, Any]) -> None:
        self._notify("session/update", {"sessionId": session_id, "update": update})

    def _validate_cwd(self, raw_cwd: Any) -> Path:
        if not isinstance(raw_cwd, str) or not raw_cwd.strip():
            raise AcpProtocolError(JSONRPC_INVALID_PARAMS, "cwd must be a non-empty absolute path string")
        if "\x00" in raw_cwd:
            raise AcpProtocolError(JSONRPC_INVALID_PARAMS, "cwd contains NUL byte")
        candidate = Path(raw_cwd)
        if not candidate.is_absolute():
            raise AcpProtocolError(JSONRPC_INVALID_PARAMS, "cwd must be an absolute path")
        resolved = candidate.resolve()
        if not resolved.is_dir():
            raise AcpProtocolError(JSONRPC_INVALID_PARAMS, f"cwd is not an existing directory: {raw_cwd}")
        if self.workspace_root is not None:
            try:
                resolved.relative_to(self.workspace_root)
            except ValueError as error:
                raise AcpProtocolError(
                    JSONRPC_INVALID_PARAMS,
                    "cwd escapes the operator-configured --workspace boundary",
                ) from error
        return resolved

    def _validate_mcp_servers(self, raw_servers: Any) -> None:
        if raw_servers is None:
            return
        if not isinstance(raw_servers, list):
            raise AcpProtocolError(JSONRPC_INVALID_PARAMS, "mcpServers must be an array")
        if raw_servers:
            raise AcpProtocolError(
                JSONRPC_INVALID_PARAMS,
                "client-supplied mcpServers are refused by Northstar governance; "
                "configure MCP servers through host operator policy",
            )

    def _session_dir_for(self, cwd: Path) -> Path | None:
        if not self.config.persist_sessions:
            return None
        if self.config.session_dir:
            return Path(self.config.session_dir).expanduser().resolve()
        return cwd / ".northstar" / "sessions"

    def _require_initialized(self) -> None:
        if not self._initialized:
            raise AcpProtocolError(
                ACP_NOT_INITIALIZED,
                "ACP connection is not initialized; send initialize first",
            )

    def _get_session(self, session_id: Any) -> AcpSessionState:
        if not isinstance(session_id, str) or not session_id:
            raise AcpProtocolError(JSONRPC_INVALID_PARAMS, "sessionId must be a non-empty string")
        with self._lock:
            session = self._sessions.get(session_id)
        if session is None:
            raise AcpProtocolError(JSONRPC_INVALID_PARAMS, f"unknown sessionId: {session_id}")
        return session

    # -- ACP methods ---------------------------------------------------------

    def _handle_initialize(self, params: dict[str, Any]) -> dict[str, Any]:
        version = params.get("protocolVersion")
        if type(version) is not int or version < 1:
            raise AcpProtocolError(
                JSONRPC_INVALID_PARAMS,
                "initialize requires an integer protocolVersion >= 1",
            )
        caps = params.get("clientCapabilities")
        if caps is not None and not isinstance(caps, dict):
            raise AcpProtocolError(JSONRPC_INVALID_PARAMS, "clientCapabilities must be an object")
        info = params.get("clientInfo")
        if info is not None and not isinstance(info, dict):
            raise AcpProtocolError(JSONRPC_INVALID_PARAMS, "clientInfo must be an object")
        with self._lock:
            self._initialized = True
            self._client_capabilities = dict(caps or {})
            self._client_info = dict(info or {})
        return {
            "protocolVersion": ACP_PROTOCOL_VERSION,
            "agentInfo": {
                "name": "northstar",
                "title": "Northstar Agent OS",
                "version": __version__,
            },
            "agentCapabilities": {
                "loadSession": True,
                "promptCapabilities": {
                    "image": False,
                    "audio": False,
                    "embeddedContext": True,
                },
                "mcpCapabilities": {
                    "http": False,
                    "sse": False,
                },
            },
            "authMethods": [],
        }

    def _handle_authenticate(self, _params: dict[str, Any]) -> dict[str, Any]:
        self._require_initialized()
        return {}

    def _handle_session_new(self, params: dict[str, Any]) -> dict[str, Any]:
        self._require_initialized()
        cwd = self._validate_cwd(params.get("cwd"))
        self._validate_mcp_servers(params.get("mcpServers"))
        session_id = f"acp-{uuid.uuid4().hex[:12]}"
        isolated_workspace: Any = None
        admission_path: Path | None = None
        if self.config.code_worktree:
            from code_task import CodeTaskError, IsolatedCodeWorkspace

            try:
                isolated_workspace = IsolatedCodeWorkspace(
                    source=cwd,
                    run_id=session_id,
                    evidence_root=(
                        Path(self.config.evidence_dir).expanduser().resolve()
                        if self.config.evidence_dir
                        else None
                    ),
                ).prepare()
                admission_path = isolated_workspace.record_admission_receipt()
            except (CodeTaskError, OSError, ValueError) as error:
                raise AcpProtocolError(
                    JSONRPC_INVALID_PARAMS,
                    f"failed to prepare isolated git worktree for {cwd}: {error}",
                ) from error

        session = AcpSessionState(
            session_id=session_id,
            cwd=cwd,
            session_dir=self._session_dir_for(cwd),
            current_mode=self.ceiling_mode,
            isolated_workspace=isolated_workspace,
            admission_path=admission_path,
        )
        with self._lock:
            self._sessions[session_id] = session
        result: dict[str, Any] = {
            "sessionId": session_id,
            "modes": {
                "currentModeId": session.current_mode,
                "availableModes": self.config.available_modes(),
            },
        }
        if isolated_workspace is not None:
            result["_meta"] = {
                "northstar": {
                    "codeWorktree": True,
                    "worktreePath": str(isolated_workspace.worktree),
                    "admissionPath": str(admission_path) if admission_path is not None else None,
                    "startCommit": isolated_workspace.start_commit,
                    "evidenceDir": str(isolated_workspace.evidence_dir),
                }
            }
        return result

    def close_sessions(self) -> None:
        """Clean up or preserve isolated git worktrees owned by active ACP sessions."""
        with self._lock:
            sessions = list(self._sessions.values())
        for session in sessions:
            ws = session.isolated_workspace
            if ws is None:
                continue
            try:
                if self.config.keep_worktree:
                    ws.preserve(reason="ACP --keep-worktree requested")
                else:
                    ws.cleanup()
            except Exception:
                pass
            session.isolated_workspace = None

    def _handle_session_load(self, params: dict[str, Any]) -> dict[str, Any]:
        self._require_initialized()
        session_id = params.get("sessionId")
        if not isinstance(session_id, str) or not session_id.strip():
            raise AcpProtocolError(JSONRPC_INVALID_PARAMS, "sessionId must be a non-empty string")
        cwd = self._validate_cwd(params.get("cwd"))
        self._validate_mcp_servers(params.get("mcpServers"))
        session_dir = self._session_dir_for(cwd)
        if session_dir is None:
            raise AcpProtocolError(
                JSONRPC_INVALID_PARAMS,
                "session persistence is disabled; cannot load a persisted session",
            )
        store = SessionStore(session_dir)
        try:
            if session_id not in store.list_sessions():
                raise FileNotFoundError(f"session not found in {session_dir}")
            messages = store.transcript(session_id, require_integrity=True)
        except (FileNotFoundError, SessionIntegrityError, ValueError, OSError) as error:
            raise AcpProtocolError(
                JSONRPC_INVALID_PARAMS,
                f"cannot load session {session_id!r}: {error}",
            ) from error

        session = AcpSessionState(
            session_id=session_id,
            cwd=cwd,
            session_dir=session_dir,
            current_mode=self.ceiling_mode,
            runtime_session_id=session_id,
        )
        with self._lock:
            self._sessions[session_id] = session

        # Replay historical text chunks per ACP v1 session/load semantics.
        for message in messages:
            role = str(getattr(message, "role", "") or (message.get("role", "") if isinstance(message, dict) else ""))
            content = getattr(message, "content", None) if not isinstance(message, dict) else message.get("content")
            update_kind = "user_message_chunk" if role == "user" else "agent_message_chunk"
            if isinstance(content, str) and content:
                self._emit_session_update(
                    session_id,
                    {"sessionUpdate": update_kind, "content": {"type": "text", "text": content}},
                )
            elif isinstance(content, (list, tuple)):
                for block in content:
                    text = getattr(block, "text", None) if not isinstance(block, dict) else (
                        block.get("text") if block.get("type") == "text" else None
                    )
                    if isinstance(text, str) and text:
                        self._emit_session_update(
                            session_id,
                            {"sessionUpdate": update_kind, "content": {"type": "text", "text": text}},
                        )

        return {
            "modes": {
                "currentModeId": session.current_mode,
                "availableModes": self.config.available_modes(),
            }
        }

    def _handle_session_set_mode(self, params: dict[str, Any]) -> dict[str, Any]:
        self._require_initialized()
        session = self._get_session(params.get("sessionId"))
        mode_id = params.get("modeId")
        if not isinstance(mode_id, str) or mode_id not in _MODE_RANK:
            raise AcpProtocolError(
                JSONRPC_INVALID_PARAMS,
                f"unsupported modeId {mode_id!r}; allowed modes: {', '.join(m['id'] for m in self.config.available_modes())}",
            )
        ceiling_rank = _MODE_RANK[self.ceiling_mode]
        current_rank = _MODE_RANK[session.current_mode]
        requested_rank = _MODE_RANK[mode_id]
        if requested_rank > ceiling_rank:
            raise AcpProtocolError(
                JSONRPC_INVALID_PARAMS,
                f"modeId {mode_id!r} exceeds host operator ceiling {self.ceiling_mode!r}",
            )
        if requested_rank > current_rank:
            raise AcpProtocolError(
                JSONRPC_INVALID_PARAMS,
                f"policy may only tighten within a session ({session.current_mode!r} -> {mode_id!r} refused)",
            )
        session.current_mode = mode_id
        self._emit_session_update(
            session.session_id,
            {"sessionUpdate": "current_mode_update", "currentModeId": mode_id},
        )
        return {}

    def _handle_session_cancel(self, params: dict[str, Any]) -> None:
        if not self._initialized:
            return
        session_id = params.get("sessionId")
        if not isinstance(session_id, str) or not session_id:
            return
        with self._lock:
            session = self._sessions.get(session_id)
            pending = [
                req for req in self._pending_requests.values() if req.session_id == session_id
            ]
        if session is not None:
            session.cancel_event.set()
        for req in pending:
            req.cancelled_reason = "ACP session cancelled while awaiting permission"
            req.event.set()

    def cancel_all_pending(self, reason: str = "ACP transport closed") -> None:
        """Fail-close every pending Agent -> Client request (e.g., on stdin EOF)."""
        with self._lock:
            pending = list(self._pending_requests.values())
        for req in pending:
            req.cancelled_reason = reason
            req.event.set()

    def _resolve_client_response(self, message: dict[str, Any]) -> None:
        req_id = message.get("id")
        if not isinstance(req_id, (str, int)) or isinstance(req_id, bool):
            return
        key = str(req_id)
        with self._lock:
            pending = self._pending_requests.get(key)
        if pending is None:
            return
        pending.response = message
        pending.event.set()

    def _request_client(
        self,
        method: str,
        params: dict[str, Any],
        *,
        session_id: str,
        timeout: float,
    ) -> tuple[dict[str, Any] | None, str | None]:
        """Send an Agent -> Client JSON-RPC request and wait for its response."""
        req_id = f"perm-{uuid.uuid4().hex[:12]}"
        pending = _PendingClientRequest(session_id=session_id)
        with self._lock:
            self._pending_requests[req_id] = pending
        try:
            self._emit(
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "method": method,
                    "params": params,
                }
            )
            if not pending.event.wait(timeout=timeout):
                return None, f"ACP {method} timed out after {timeout:.1f}s (fail-closed)"
            if pending.cancelled_reason:
                return None, pending.cancelled_reason
            return pending.response, None
        finally:
            with self._lock:
                self._pending_requests.pop(req_id, None)

    def _make_permission_callback(
        self, session: AcpSessionState
    ) -> Callable[[str, dict[str, Any], Any], dict[str, Any]] | None:
        """Bridge Northstar's per-call approval gate to ACP session/request_permission."""
        if not self.config.interactive_permissions:
            return None

        def _can_use_tool(tool_name: str, tool_input: dict[str, Any], ctx: Any) -> dict[str, Any]:
            if session.cancel_event.is_set():
                return {"allowed": False, "reason": "ACP session cancelled"}
            call_id = str(getattr(ctx, "call_id", "") or f"call-{uuid.uuid4().hex[:8]}")
            arguments_digest = str(getattr(ctx, "arguments_digest", "") or "")
            reason_hint = str(getattr(ctx, "reason_hint", "") or "")
            ctx_data = getattr(ctx, "data", None) or {}
            params: dict[str, Any] = {
                "sessionId": session.session_id,
                "toolCall": {
                    "toolCallId": call_id,
                    "title": _tool_title(tool_name, tool_input),
                    "kind": _tool_kind(tool_name),
                    "status": "pending",
                    "rawInput": tool_input if isinstance(tool_input, dict) else {},
                },
                "options": [
                    {
                        "optionId": "allow_once",
                        "name": "Allow once",
                        "kind": "allow_once",
                    },
                    {
                        "optionId": "reject_once",
                        "name": "Reject",
                        "kind": "reject_once",
                    },
                ],
                "_meta": {
                    "northstar": {
                        "argumentsDigest": arguments_digest,
                        "mode": str(getattr(ctx, "mode", session.current_mode) or session.current_mode),
                        "agent": str(getattr(ctx, "agent", "main") or "main"),
                        "depth": int(getattr(ctx, "depth", 0) or 0),
                        "reasonHint": reason_hint,
                        "dataflowEscalation": ctx_data.get("dataflow_escalation"),
                    }
                },
            }
            response, failure = self._request_client(
                "session/request_permission",
                params,
                session_id=session.session_id,
                timeout=self.config.permission_timeout_seconds,
            )
            if failure is not None:
                return {"allowed": False, "reason": failure}
            if not isinstance(response, dict):
                return {"allowed": False, "reason": "malformed ACP permission response (fail-closed)"}
            if "error" in response:
                err = response.get("error")
                msg = err.get("message") if isinstance(err, dict) else str(err)
                return {
                    "allowed": False,
                    "reason": f"ACP client returned error for session/request_permission: {msg}",
                }
            result = response.get("result")
            if not isinstance(result, dict):
                return {"allowed": False, "reason": "missing result in ACP permission response (fail-closed)"}
            outcome = result.get("outcome")
            if not isinstance(outcome, dict):
                return {"allowed": False, "reason": "missing outcome in ACP permission response (fail-closed)"}
            outcome_kind = outcome.get("outcome")
            option_id = outcome.get("optionId")
            if outcome_kind == "selected" and option_id == "allow_once":
                return {"allowed": True, "reason": "approved once via ACP session/request_permission"}
            if outcome_kind == "cancelled":
                return {"allowed": False, "reason": "rejected: ACP client cancelled permission request"}
            return {
                "allowed": False,
                "reason": f"rejected by ACP client (outcome={outcome_kind!r}, optionId={option_id!r})",
            }

        return _can_use_tool

    def _handle_session_prompt(self, params: dict[str, Any]) -> dict[str, Any]:
        self._require_initialized()
        session = self._get_session(params.get("sessionId"))
        raw_blocks = params.get("prompt") if "prompt" in params else params.get("content")
        prompt_text = _extract_prompt_text(raw_blocks)

        if not session.turn_lock.acquire(blocking=False):
            raise AcpProtocolError(
                ACP_SERVER_ERROR,
                "another prompt turn is already active on this session",
            )
        try:
            session.active_turn = True
            session.cancel_event.clear()
            return self._execute_prompt_turn(session, prompt_text)
        finally:
            session.active_turn = False
            session.turn_lock.release()

    def _execute_prompt_turn(self, session: AcpSessionState, prompt_text: str) -> dict[str, Any]:
        session.turn_index += 1
        turn_evidence_dir: str | None = None
        if self.config.evidence_dir:
            base_evidence = Path(self.config.evidence_dir).expanduser().resolve()
            turn_evidence_dir = str(base_evidence / session.session_id / f"turn-{session.turn_index:04d}")
        provider_obj = _build_acp_provider(self.config, self.model)
        can_stream = True if isinstance(provider_obj, str) else bool(getattr(provider_obj, "streams", False))
        options = RunOptions(
            prompt=prompt_text,
            workspace=str(session.execution_cwd),
            provider=provider_obj,
            model=self.model,
            scripted_turns=self.config.scripted_turns,
            permission_mode=session.current_mode,
            dataflow_policy=self.dataflow_policy,
            can_use_tool=self._make_permission_callback(session),
            allowed_tools=self.config.allowed_tools,
            disallowed_tools=self.config.disallowed_tools,
            read_only=(self.config.read_only or session.current_mode == "plan"),
            max_turns=self.config.max_turns,
            max_tool_calls=self.config.max_tool_calls,
            max_budget_usd=self.config.max_budget_usd,
            max_output_tokens=self.config.max_output_tokens,
            temperature=self.config.temperature,
            session_dir=str(session.session_dir) if session.session_dir is not None else None,
            checkpoint_turns=1 if session.session_dir is not None else 0,
            evidence_dir=turn_evidence_dir,
            evidence_required=bool(self.config.evidence_required and turn_evidence_dir is not None),
            workspace_agents=self.config.workspace_agents,
            code_tools=self.config.code_tools,
            shell_backend=self.config.shell_backend,
            shell_seccomp=self.config.shell_seccomp,
            shell_capdrop=self.config.shell_capdrop,
            stream=can_stream,
        )
        resume_id = session.runtime_session_id if session.session_dir is not None else None

        result_event: dict[str, Any] | None = None
        streamed_text_this_turn = False
        tool_call_count = 0
        cancelled = False

        try:
            for event in stream_run(options, resume=resume_id):
                if session.cancel_event.is_set():
                    cancelled = True
                    break
                etype = event.get("type")
                if etype == "system" and event.get("subtype") == "init":
                    data = event.get("data") or {}
                    rt_sid = data.get("session_id")
                    if isinstance(rt_sid, str) and rt_sid and session.session_dir is not None:
                        session.runtime_session_id = rt_sid
                elif etype == "stream_delta":
                    text = event.get("text")
                    if isinstance(text, str) and text:
                        streamed_text_this_turn = True
                        self._emit_session_update(
                            session.session_id,
                            {
                                "sessionUpdate": "agent_message_chunk",
                                "content": {"type": "text", "text": text},
                            },
                        )
                elif etype == "assistant":
                    for block in event.get("content") or ():
                        if not isinstance(block, dict):
                            continue
                        btype = block.get("type")
                        if btype == "text":
                            text = block.get("text")
                            if isinstance(text, str) and text and not streamed_text_this_turn:
                                self._emit_session_update(
                                    session.session_id,
                                    {
                                        "sessionUpdate": "agent_message_chunk",
                                        "content": {"type": "text", "text": text},
                                    },
                                )
                        elif btype == "tool_use":
                            tool_call_count += 1
                            call_id = str(block.get("id") or f"call-{uuid.uuid4().hex[:8]}")
                            tool_name = str(block.get("name") or "tool")
                            tool_input = block.get("input")
                            self._emit_session_update(
                                session.session_id,
                                {
                                    "sessionUpdate": "tool_call",
                                    "toolCallId": call_id,
                                    "title": _tool_title(tool_name, tool_input),
                                    "kind": _tool_kind(tool_name),
                                    "status": "in_progress",
                                    "rawInput": tool_input if isinstance(tool_input, dict) else {},
                                },
                            )
                            if tool_name == "SubmitPlan" and isinstance(tool_input, dict):
                                steps = tool_input.get("steps")
                                if isinstance(steps, list) and steps:
                                    entries = [
                                        {
                                            "content": str(step),
                                            "priority": "medium",
                                            "status": "pending",
                                        }
                                        for step in steps[:32]
                                    ]
                                    self._emit_session_update(
                                        session.session_id,
                                        {"sessionUpdate": "plan", "entries": entries},
                                    )
                    streamed_text_this_turn = False
                elif etype == "user":
                    for block in event.get("content") or ():
                        if not isinstance(block, dict) or block.get("type") != "tool_result":
                            continue
                        call_id = str(block.get("tool_use_id") or "")
                        is_error = bool(block.get("is_error", False))
                        text = str(block.get("content") or "")
                        if len(text) > MAX_TOOL_OUTPUT_PREVIEW_CHARS:
                            text = text[:MAX_TOOL_OUTPUT_PREVIEW_CHARS] + "\n...[truncated]"
                        self._emit_session_update(
                            session.session_id,
                            {
                                "sessionUpdate": "tool_call_update",
                                "toolCallId": call_id,
                                "status": "failed" if is_error else "completed",
                                "content": [
                                    {
                                        "type": "content",
                                        "content": {"type": "text", "text": text},
                                    }
                                ],
                            },
                        )
                elif etype == "result":
                    result_event = event
                    rt_sid = event.get("session_id")
                    if isinstance(rt_sid, str) and rt_sid and session.session_dir is not None:
                        session.runtime_session_id = rt_sid
        except Exception as error:
            raise AcpProtocolError(
                ACP_SERVER_ERROR,
                f"Northstar runtime execution error: {error}",
            ) from error

        if cancelled or session.cancel_event.is_set():
            return {"stopReason": "cancelled"}

        if result_event is None:
            raise AcpProtocolError(
                ACP_SERVER_ERROR,
                "Northstar runtime stream ended without a terminal result event",
            )

        usage = _acp_usage(result_event.get("total_usage"))
        total_cost = float(result_event.get("total_cost_usd") or 0.0)
        self._emit_session_update(
            session.session_id,
            {
                "sessionUpdate": "usage_update",
                "used": usage["totalTokens"],
                "size": 200_000,
                "cost": {"amount": round(total_cost, 6), "currency": "USD"},
            },
        )

        subtype = str(result_event.get("subtype") or "error_during_execution")
        stop_reason = _map_stop_reason(subtype)
        if stop_reason is None:
            raise AcpProtocolError(
                ACP_SERVER_ERROR,
                f"Northstar run ended with {subtype}",
                data={
                    "subtype": subtype,
                    "errors": list(result_event.get("errors") or ()),
                    "permissionDenials": list(result_event.get("permission_denials") or ()),
                },
            )

        patch_meta: dict[str, Any] = {}
        if session.isolated_workspace is not None:
            import hashlib
            from code_task import audit_delivery_patch

            ws = session.isolated_workspace
            audit = audit_delivery_patch(ws.worktree, evidence_dir=ws.evidence_dir)
            audit_ok = bool(audit.get("ok", False))
            if not audit_ok and not cancelled:
                subtype = "error_postconditions_failed"
                stop_reason = "refusal"
            patch_path = ws.capture(
                exit_code=0 if audit_ok and not cancelled else 1,
                terminal=subtype,
            )
            patch_bytes = patch_path.read_bytes() if patch_path.is_file() else b""
            patch_meta = {
                "codeWorktree": True,
                "worktreePath": str(ws.worktree),
                "patchPath": str(patch_path),
                "patchSha256": hashlib.sha256(patch_bytes).hexdigest(),
                "patchBytes": len(patch_bytes),
                "patchAuditOk": audit_ok,
                "patchAuditFindings": list(audit.get("findings") or ()),
            }

        return {
            "stopReason": stop_reason,
            "usage": usage,
            "_meta": {
                "northstar": {
                    "subtype": subtype,
                    "sessionId": result_event.get("session_id"),
                    "numTurns": int(result_event.get("num_turns") or 0),
                    "toolCallCount": tool_call_count,
                    "permissionDenials": list(result_event.get("permission_denials") or ()),
                    "totalCostUsd": round(total_cost, 6),
                    "permissionMode": session.current_mode,
                    "sandboxBackend": self.config.shell_backend,
                    "evidenceDir": turn_evidence_dir,
                    **patch_meta,
                }
            },
        }

    # -- JSON-RPC 2.0 dispatch -----------------------------------------------

    def handle_message(self, message: Any) -> dict[str, Any] | None:
        """Process one parsed JSON-RPC 2.0 message; return a response dict or None."""
        try:
            _check_json_depth(message)
        except AcpProtocolError as error:
            return {"jsonrpc": "2.0", "id": None, "error": error.to_rpc_error()}

        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            return {
                "jsonrpc": "2.0",
                "id": message.get("id") if isinstance(message, dict) else None,
                "error": AcpProtocolError(
                    JSONRPC_INVALID_REQUEST,
                    "message must be a JSON-RPC 2.0 object",
                ).to_rpc_error(),
            }

        method = message.get("method")
        has_id = "id" in message
        req_id = message.get("id")
        if has_id and req_id is not None and not isinstance(req_id, (str, int)) or isinstance(req_id, bool):
            return {
                "jsonrpc": "2.0",
                "id": None,
                "error": AcpProtocolError(
                    JSONRPC_INVALID_REQUEST,
                    "JSON-RPC id must be a string, integer, or null",
                ).to_rpc_error(),
            }
        # Inbound JSON-RPC response to an Agent -> Client request (e.g. session/request_permission).
        if method is None and has_id and ("result" in message or "error" in message):
            self._resolve_client_response(message)
            return None
        if not isinstance(method, str) or not method:
            if not has_id:
                return None
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": AcpProtocolError(
                    JSONRPC_INVALID_REQUEST,
                    "JSON-RPC method must be a non-empty string",
                ).to_rpc_error(),
            }

        params = message.get("params")
        if params is None:
            params = {}
        elif not isinstance(params, dict):
            if not has_id:
                return None
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": AcpProtocolError(
                    JSONRPC_INVALID_PARAMS,
                    "JSON-RPC params must be an object",
                ).to_rpc_error(),
            }

        # Notifications (no id).
        if not has_id:
            if method == "session/cancel":
                self._handle_session_cancel(params)
            return None

        handlers: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
            "initialize": self._handle_initialize,
            "authenticate": self._handle_authenticate,
            "session/new": self._handle_session_new,
            "session/load": self._handle_session_load,
            "session/set_mode": self._handle_session_set_mode,
            "session/prompt": self._handle_session_prompt,
        }
        handler = handlers.get(method)
        if handler is None:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": AcpProtocolError(
                    JSONRPC_METHOD_NOT_FOUND,
                    f"unknown ACP method: {method}",
                ).to_rpc_error(),
            }

        try:
            result = handler(params)
        except AcpProtocolError as error:
            return {"jsonrpc": "2.0", "id": req_id, "error": error.to_rpc_error()}
        except Exception as error:  # pragma: no cover - defensive boundary
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": AcpProtocolError(
                    JSONRPC_INTERNAL_ERROR,
                    f"internal error: {error}",
                ).to_rpc_error(),
            }
        return {"jsonrpc": "2.0", "id": req_id, "result": result}


def serve_stdio(
    config: AcpServerConfig,
    *,
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
) -> int:
    """Run the ACP v1 NDJSON stdio server until EOF.

    ``session/prompt`` runs on a worker thread so an incoming ``session/cancel``
    notification on stdin can interrupt an active turn without deadlocking.
    """
    in_stream = stdin if stdin is not None else sys.stdin
    out_stream = stdout if stdout is not None else sys.stdout
    write_lock = threading.Lock()
    workers: list[threading.Thread] = []

    def send(payload: dict[str, Any]) -> None:
        encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n"
        with write_lock:
            out_stream.write(encoded)
            out_stream.flush()

    server = AcpServer(config, emit=send)

    def dispatch_async(msg: dict[str, Any]) -> None:
        response = server.handle_message(msg)
        if response is not None:
            send(response)

    while True:
        raw_line = in_stream.readline(MAX_LINE_BYTES + 1)
        if not raw_line:
            break
        if len(raw_line.encode("utf-8", errors="replace")) > MAX_LINE_BYTES:
            # Drain until newline so framing recovers cleanly.
            while raw_line and not raw_line.endswith("\n"):
                raw_line = in_stream.readline(MAX_LINE_BYTES)
            send(
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": AcpProtocolError(
                        JSONRPC_INVALID_REQUEST,
                        f"JSON-RPC line exceeds {MAX_LINE_BYTES} bytes",
                    ).to_rpc_error(),
                }
            )
            continue
        stripped = raw_line.strip()
        if not stripped:
            continue
        try:
            message = json.loads(stripped)
        except json.JSONDecodeError as error:
            send(
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": AcpProtocolError(
                        JSONRPC_PARSE_ERROR,
                        f"malformed JSON: {error}",
                    ).to_rpc_error(),
                }
            )
            continue

        # Run session/prompt on a worker thread so session/cancel notifications
        # can still be read immediately from stdin.
        if isinstance(message, dict) and message.get("method") == "session/prompt" and "id" in message:
            worker = threading.Thread(target=dispatch_async, args=(message,), daemon=True)
            workers.append(worker)
            worker.start()
        else:
            response = server.handle_message(message)
            if response is not None:
                send(response)

    server.cancel_all_pending("ACP client closed stdin")
    for worker in workers:
        worker.join(timeout=30.0)
    server.close_sessions()
    return 0


def format_dry_run(config: AcpServerConfig) -> str:
    """Human-readable summary printed by ``northstar acp --dry-run``."""
    ceiling = config.effective_ceiling_mode()
    root = config.resolved_workspace_root()
    model = config.resolved_model()
    dataflow = config.resolved_dataflow_policy()
    modes = ", ".join(item["id"] for item in config.available_modes())
    dataflow_label = (
        f"on (camel-integrity={'on' if dataflow.has_integrity_rules else 'off'})"
        if dataflow is not None
        else "off"
    )
    lines = [
        f"acp_protocol_version={ACP_PROTOCOL_VERSION}",
        f"agent=northstar {__version__}",
        f"provider={config.provider} model={model}",
        f"permission_ceiling={ceiling} available_modes={modes} (tighten-only)",
        f"interactive_permissions={'on' if config.interactive_permissions else 'off'} timeout_s={config.permission_timeout_seconds}",
        f"dataflow_policy={dataflow_label}",
        f"workspace_root={root if root is not None else '(client cwd; any existing absolute directory)'}",
        f"allowed_tools={','.join(config.allowed_tools) or '(none)'} disallowed_tools={','.join(config.disallowed_tools) or '(none)'}",
        f"max_turns={config.max_turns} max_tool_calls={config.max_tool_calls if config.max_tool_calls is not None else 'unlimited'} max_budget_usd={config.max_budget_usd or 'unlimited'}",
        f"sandbox={config.shell_backend} seccomp={config.shell_seccomp} capdrop={config.shell_capdrop}",
        f"sessions={'on' if config.persist_sessions else 'off'} session_dir={config.session_dir or '<cwd>/.northstar/sessions'}",
        f"evidence_dir={config.evidence_dir or '(off)'} evidence_required={'on' if config.evidence_required else 'off'}",
        f"code_worktree={'on' if config.code_worktree else 'off'} keep_worktree={'on' if config.keep_worktree else 'off'}",
        "client_mcp_servers=refused (fail-closed; declare MCP servers via host operator policy)",
        "dry-run: ACP configuration is valid; stdin/stdout server was not started",
    ]
    return "\n".join(lines)
