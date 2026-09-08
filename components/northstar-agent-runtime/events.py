"""Public event vocabulary of a governed run: dict events + result exit codes.

A run's event stream is its public, machine-readable surface. Every event the
loop yields can be rendered as a plain JSON-safe dict via :func:`event_to_dict`
— this module is the single source of that shape, shared by the CLI's
``--json`` mode, by :mod:`sdk` (``stream_run``/``RunReport.events``) and by
anyone embedding ``AgentRuntime`` directly.

``EXIT_CODES`` maps a result subtype to the process exit code a CLI wrapper
should use. The runtime itself reports *subtypes*, never exit codes; the codes
are a terminal convention shared with ``cli`` so an embedded run and a
``python -m cli run`` wrapper agree.

The ``result`` dict additionally carries ``errors`` and ``permission_denials``
lists so a programmatic caller never has to re-derive why a run ended.
"""
from __future__ import annotations

from typing import Any

#: Terminal convention for each result subtype (0 success … 5 permission).
EXIT_CODES: dict[str, int] = {
    "success": 0,
    "error_during_execution": 1,
    "error_max_turns": 2,
    "error_max_tool_calls": 3,
    "error_max_budget_usd": 4,
    "error_permission_denied": 5,
}


def event_to_dict(event: Any) -> dict[str, Any]:
    """Render one run event as a plain dict (the shape ``--json`` emits)."""
    kind = type(event).__name__
    if kind == "ResultMessage":
        return {
            "type": "result",
            "subtype": event.subtype,
            "is_error": event.is_error,
            "num_turns": event.num_turns,
            "duration_ms": event.duration_ms,
            "total_cost_usd": event.total_cost_usd,
            "total_usage": event.total_usage.as_dict(),
            "session_id": event.session_id,
            "pricing_estimated": event.pricing_estimated,
            "context_windows": event.context_windows,
            "context_overflow_retries": event.context_overflow_retries,
            "errors": list(event.errors),
            "permission_denials": list(event.permission_denials),
        }
    if kind == "SystemMessage":
        return {"type": "system", "subtype": event.subtype, "content": event.content, "data": event.data}
    if kind == "AssistantMessage":
        return {
            "type": "assistant",
            "content": [block.to_api() for block in event.content],
            "model": event.model,
            "usage": event.usage.as_dict(),
            "stop_reason": event.stop_reason,
        }
    if kind == "UserMessage":
        return {"type": "user", "content": [block.to_api() for block in event.content], "is_meta": event.is_meta}
    return {"type": kind.lower(), "repr": str(event)[:400]}
