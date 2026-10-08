"""OTel integration: span creation (mock), Simulated.

Implements OpenTelemetry-style tracing primitives without the SDK:
SpanContext (trace_id/span_id), Span (attributes, events, status),
Tracer that records spans in memory. Parent-child via context.

What this IS: a drop-in-shaped mock for wiring gate boundaries
(declare/authorize/assess) with trace IDs that can be sealed into
the ledger.

What this IS NOT:
* Not the real opentelemetry SDK -- no exporters, no contextvars
  propagation. Host swaps in the real SDK later.
"""

from __future__ import annotations

import ast
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

#: Module version.
MONITOR_01_VERSION = "monitor-01.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.monitor-01.v1"


class OTelError(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class SpanContext:
    """Immutable trace/span identity."""

    trace_id: str  # 32 hex chars
    span_id: str  # 16 hex chars
    parent_span_id: Optional[str] = None

    def __post_init__(self) -> None:
        if not _is_hex(self.trace_id, 32):
            raise OTelError("trace_id must be 32 hex chars")
        if not _is_hex(self.span_id, 16):
            raise OTelError("span_id must be 16 hex chars")
        if self.parent_span_id is not None and not _is_hex(self.parent_span_id, 16):
            raise OTelError("parent_span_id must be 16 hex chars")


def _is_hex(value: Any, length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(c in "0123456789abcdef" for c in value.lower())
    )


def new_span_context(parent: Optional[SpanContext] = None) -> SpanContext:
    """Create a context; child reuses parent's trace_id."""
    return SpanContext(
        trace_id=parent.trace_id if parent else secrets.token_hex(16),
        span_id=secrets.token_hex(8),
        parent_span_id=parent.span_id if parent else None,
    )


@dataclass
class Span:
    """A recorded span."""

    name: str
    context: SpanContext
    attributes: Dict[str, Any] = field(default_factory=dict)
    events: List[Dict[str, Any]] = field(default_factory=list)
    status: str = "unset"  # unset | ok | error
    start_ns: int = field(default_factory=time.time_ns)
    end_ns: Optional[int] = None

    def set_attribute(self, key: str, value: Any) -> None:
        if not isinstance(key, str) or not key:
            raise OTelError("attribute key must be non-empty str")
        self.attributes[key] = value

    def add_event(self, name: str, attributes: Optional[Dict[str, Any]] = None) -> None:
        if not name:
            raise OTelError("event name required")
        self.events.append(
            {"name": name, "time_ns": time.time_ns(), "attributes": attributes or {}}
        )

    def set_status(self, status: str) -> None:
        if status not in ("unset", "ok", "error"):
            raise OTelError(f"bad status {status!r}")
        self.status = status

    def end(self) -> None:
        self.end_ns = time.time_ns()

    @property
    def duration_ns(self) -> Optional[int]:
        if self.end_ns is None:
            return None
        return self.end_ns - self.start_ns


class Tracer:
    """In-memory tracer."""

    def __init__(self, service_name: str) -> None:
        if not service_name:
            raise OTelError("service_name required")
        self._service = service_name
        self._spans: List[Span] = []

    def start_span(self, name: str, parent: Optional[SpanContext] = None) -> Span:
        if not name:
            raise OTelError("span name required")
        span = Span(name=name, context=new_span_context(parent))
        self._spans.append(span)
        return span

    def finished_spans(self) -> List[Span]:
        return [s for s in self._spans if s.end_ns is not None]

    def export_json(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": s.name,
                "trace_id": s.context.trace_id,
                "span_id": s.context.span_id,
                "parent_span_id": s.context.parent_span_id,
                "attributes": s.attributes,
                "events": s.events,
                "status": s.status,
                "duration_ns": s.duration_ns,
            }
            for s in self.finished_spans()
        ]


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "dataclasses", "pathlib", "secrets", "time", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    """Self-check."""
    tracer = Tracer("northstar")
    root = tracer.start_span("declare")
    root.set_attribute("gate", "declare")
    root.add_event("intent_received")
    child = tracer.start_span("authorize", parent=root.context)
    child.set_status("ok")
    root.end()
    child.end()
    assert child.context.trace_id == root.context.trace_id
    assert child.context.parent_span_id == root.context.span_id
    assert len(tracer.export_json()) == 2
    try:
        SpanContext(trace_id="bad", span_id="00" * 8)
        raise AssertionError("should raise")
    except OTelError:
        pass
    assert stdlib_only()
    print("monitor-01 OK: spans, parent-child, fail-closed, stdlib")


if __name__ == "__main__":
    main()
