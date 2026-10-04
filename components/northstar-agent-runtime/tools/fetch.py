"""Agent-facing network tool routed through the egress sidecar.

This is the wire that makes the egress enforcement boundary real for the
agent loop: the ``Fetch`` tool is the *only* network capability the agent
can call, and every byte it sends goes through ``EgressClient`` to the
egress sidecar over AF_UNIX. The sidecar — not the agent — resolves DNS,
authorizes the destination at CONNECT time, injects brokered credentials,
and enforces DLP tripwires and byte budgets.

Security posture:
- ``kind="network"``, ``is_mutating=True``: the permission gate denies it
  under ``default`` mode until the operator explicitly allows it
  (``--allow-tool Fetch``). Network access is never ambient.
- The tool is only registered when an egress socket is configured
  (``--egress-socket``); without a sidecar there is no Fetch tool at all.
- Destinations whose policy sets ``require_approval=True`` are denied with
  ``egress.approval_binding_invalid``: the live loop does not mint action
  cards yet, so approved-destination egress is unavailable via Fetch until
  the card flow is wired into the loop. This is fail-closed, not silent.
- The agent never sees brokered credentials: the sidecar injects them
  server-side and scrubs reflections from responses.
"""
from __future__ import annotations

from typing import Any

FETCH_TOOL_NAME = "Fetch"

#: Hard caps on what the tool will even ask the sidecar for. The sidecar
#: enforces its own (smaller-or-equal) limits; these are the tool's.
FETCH_MAX_BODY_BYTES = 1_000_000
FETCH_MAX_TIMEOUT_MS = 120_000
FETCH_MIN_TIMEOUT_MS = 1_000


def fetch_tool_spec() -> Any:
    """Schema for the sidecar-routed network tool.

    Registered only when an egress socket is configured. The handler pulls
    the ``EgressClient`` from the tool context's ``egress`` service.
    """
    from tools import ToolResult, ToolSpec, _schema

    def handler(payload: dict[str, Any], ctx: Any) -> ToolResult:
        client = ctx.service("egress")
        if client is None:
            return ToolResult.error("no egress client is attached to this context")
        host = str(payload.get("host") or "").strip()
        path = str(payload.get("path") or "")
        method = str(payload.get("method") or "GET").upper()
        if not host:
            return ToolResult.error("Fetch needs a non-empty 'host'")
        if not path.startswith("/"):
            return ToolResult.error("Fetch 'path' must start with '/'")
        port = payload.get("port", 443)
        try:
            port = int(port)
        except (TypeError, ValueError):
            return ToolResult.error("Fetch 'port' must be an integer")
        body_text = payload.get("body", "")
        if body_text is None:
            body_text = ""
        if not isinstance(body_text, str):
            return ToolResult.error("Fetch 'body' must be a string")
        body = body_text.encode("utf-8")
        if len(body) > FETCH_MAX_BODY_BYTES:
            return ToolResult.error(
                f"Fetch body {len(body)} bytes exceeds the {FETCH_MAX_BODY_BYTES} cap"
            )
        headers = payload.get("headers") or {}
        if not isinstance(headers, dict):
            return ToolResult.error("Fetch 'headers' must be a mapping")
        timeout_ms = payload.get("timeout_ms")
        try:
            timeout_ms = int(timeout_ms) if timeout_ms is not None else None
        except (TypeError, ValueError):
            return ToolResult.error("Fetch 'timeout_ms' must be an integer")
        if timeout_ms is not None:
            timeout_ms = max(FETCH_MIN_TIMEOUT_MS, min(FETCH_MAX_TIMEOUT_MS, timeout_ms))

        # The call_id binds this tool call to the sidecar request; the
        # permission gate already pinned the approval to (call_id,
        # arguments_digest), so the sidecar sees the same identity.
        result = client.request(
            agent_id=str(getattr(ctx, "agent", "main") or "main"),
            run_id=str(getattr(ctx, "session_id", "") or ""),
            host=host,
            port=port,
            method=method,
            path=path,
            headers={str(k): str(v) for k, v in headers.items()},
            body=body,
            timeout_ms=timeout_ms,
            call_id=str(getattr(ctx, "call_id", "") or ""),
            arguments=dict(payload),
        )
        if result.status == "ok":
            text = result.body.decode("utf-8", errors="replace")
            return ToolResult(
                content=text,
                data={
                    "http_status": result.http_status,
                    "truncated": result.truncated,
                    "receipt": result.receipt,
                },
            )
        if result.status == "denied":
            return ToolResult.error(
                f"egress denied ({result.deny_code}): {result.error or 'policy refusal'}",
                deny_code=result.deny_code,
                receipt=result.receipt,
            )
        return ToolResult.error(
            f"egress {result.status}: {result.error or 'sidecar failure'}",
            status=result.status,
            receipt=result.receipt,
        )

    return ToolSpec(
        name=FETCH_TOOL_NAME,
        description=(
            "Make one HTTP request through the Northstar egress sidecar. "
            "The sidecar resolves DNS itself, authorizes the destination at "
            "CONNECT time, and enforces the egress policy (SSRF guard, DLP, "
            "byte budgets). Only allowlisted destinations are reachable; "
            "brokered credentials are injected server-side and never visible. "
            "This is the only network access the agent has."
        ),
        input_schema=_schema(
            {
                "host": {"type": "string", "description": "Destination hostname (must be allowlisted)"},
                "port": {"type": "integer", "description": "Destination port, default 443"},
                "method": {"type": "string", "description": "HTTP method, e.g. GET or POST"},
                "path": {"type": "string", "description": "Request path, must start with '/'"},
                "headers": {"type": "object", "description": "Optional request headers"},
                "body": {"type": "string", "description": "Optional request body as text"},
                "timeout_ms": {"type": "integer", "description": "Optional timeout in milliseconds"},
            },
            ["host", "method", "path"],
        ),
        handler=handler,
        # Network egress is mutating by definition: bytes leave the boundary.
        # The gate denies it under `default` until `--allow-tool Fetch`.
        kind="network",
        is_mutating=True,
    )
