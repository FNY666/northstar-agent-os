"""Span tree for a run: ``run -> turn[n] -> generation | tool:Name | subagent:Type``.

Two rules shape this module, and both come from bugs that were expensive to find:

**Attributes are recorded before ``end()``.** OpenTelemetry drops an attribute
written to an ended span *silently* - the cost would simply be missing from the
trace with no error anywhere. So every write goes through :class:`SpanHandle`,
which applies to the live OTel span immediately, snapshots on ``end()``, and
refuses writes afterwards (recusing itself by recording the rejected key so a
regression is visible instead of invisible).

**Prompts and tool output bodies are never recorded.** Attribute keys that name
them are refused, and string values above ``max_attribute_chars`` are refused, so
"just add the prompt to the span" fails at the seam that adds it. Traces are
expected to be shipped to systems with weaker retention than the run workspace.
"""
from __future__ import annotations

import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Iterator, Mapping, Sequence

#: Keys whose values are conversation content. Recording them is refused.
FORBIDDEN_ATTRIBUTE_KEYS: frozenset[str] = frozenset(
    {
        "prompt",
        "prompts",
        "user_prompt",
        "system",
        "system_prompt",
        "messages",
        "transcript",
        "tool.output",
        "tool_output",
        "tool.output_text",
        "tool.result",
        "tool.result_text",
        "tool.input",
        "tool_input",
        "completion",
        "response_text",
        "summary",
    }
)

#: Attributes that must be present on a generation span before it ends.
USAGE_ATTRIBUTE_KEYS: tuple[str, ...] = (
    "usage.input_tokens",
    "usage.output_tokens",
    "usage.cache_read_input_tokens",
    "usage.cache_creation_input_tokens",
    "cost.usd",
)

MAX_ATTRIBUTE_CHARS = 200
MAX_ATTRIBUTE_SEQUENCE_ITEMS = 32


@dataclass(frozen=True)
class SpanRecord:
    """Immutable snapshot of one finished span."""

    name: str = ""
    attributes: Mapping[str, Any] = field(default_factory=dict)
    span_id: str = ""
    parent_span_id: str = ""
    children: tuple[str, ...] = ()
    started_at: float = 0.0
    duration_ms: int = 0
    sequence: int = 0
    #: A list on purpose: OTel drops post-end writes silently, so this record has
    #: to stay writable after ``end()`` for the drops to be visible at all.
    dropped_after_end: list[str] = field(default_factory=list)
    rejected_attributes: tuple[str, ...] = ()
    error: str = ""

    def attribute(self, key: str, default: Any = None) -> Any:
        return self.attributes.get(key, default)

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "span_id": self.span_id,
            "parent_span_id": self.parent_span_id,
            "children": list(self.children),
            "duration_ms": self.duration_ms,
            "sequence": self.sequence,
            "attributes": dict(self.attributes),
            "dropped_after_end": list(self.dropped_after_end),
            "rejected_attributes": list(self.rejected_attributes),
            "error": self.error,
        }


class SpanHandle:
    """Live span with ordered-attribute semantics."""

    def __init__(
        self,
        tracer: "Tracer",
        name: str,
        *,
        parent: "SpanHandle | None" = None,
        attributes: Mapping[str, Any] | None = None,
    ) -> None:
        self.tracer = tracer
        self.name = name
        self.parent = parent
        self.attributes: dict[str, Any] = {}
        self.span_id = tracer._next_id("span")
        #: Creation order. A subagent run is a second "run" span that *ends*
        #: before its parent, so ordering by end time would make find() return the
        #: child when callers want the outer run.
        self.sequence = tracer._sequence
        self.parent_span_id = parent.span_id if parent is not None else ""
        self.children: list[str] = []
        self.started_at = time.monotonic()
        self.ended = False
        self.error = ""
        self.dropped_after_end: list[str] = []
        self.rejected: list[str] = []
        self._child_durations: dict[str, int] = {}
        self._otel = tracer._start_otel_span(name, self)
        if attributes:
            self.set_attributes(attributes)

    # -- attribute writing ------------------------------------------------
    def set_attribute(self, key: str, value: Any) -> bool:
        """Record one attribute. Returns ``False`` when the write was refused."""
        if self.ended:
            # Mirrors OTel's silent drop, but loudly enough for a test to catch.
            self.dropped_after_end.append(key)
            self.tracer._note_dropped(self, key)
            return False
        accepted, reason = self.tracer._accept(key, value)
        if not accepted:
            self.rejected.append(f"{key} ({reason})")
            return False
        self.attributes[key] = value
        self.tracer._set_otel_attribute(self._otel, key, value)
        return True

    def set_attributes(self, attributes: Mapping[str, Any] | None) -> dict[str, bool]:
        results: dict[str, bool] = {}
        for key, value in (attributes or {}).items():
            results[str(key)] = self.set_attribute(key, value)
        return results

    def record_usage(self, usage: Any, cost_usd: float | None = None, *, prefix: str = "usage", extra: Mapping[str, Any] | None = None) -> None:
        """Attach provider usage and cost to this span.

        Must be called while the span is open; that is the whole point of the
        wrapper. The loop calls it immediately after the provider returns, before
        the ``with`` block ends.
        """
        to_dict = getattr(usage, "as_dict", None)
        if callable(to_dict):
            mapping: Mapping[str, Any] = dict(to_dict())
        elif isinstance(usage, Mapping):
            mapping = dict(usage)
        else:
            mapping = {}
        values: dict[str, Any] = {}
        for key, value in mapping.items():
            if isinstance(value, int) and not isinstance(value, bool):
                values[f"{prefix}.{key}"] = value
        values[f"{prefix}.total_tokens"] = getattr(usage, "total_tokens", sum(values.values()))
        if cost_usd is not None:
            values["cost.usd"] = round(float(cost_usd), 10)
        values.update(extra or {})
        self.set_attributes(values)

    def record_error(self, message: str) -> None:
        self.error = message[:MAX_ATTRIBUTE_CHARS]
        self.set_attribute("error", self.error)

    # -- lifecycle ---------------------------------------------------------
    @contextmanager
    def child(self, name: str, attributes: Mapping[str, Any] | None = None) -> Iterator["SpanHandle"]:
        handle = self.tracer.start_span(name, parent=self, attributes=attributes)
        try:
            yield handle
        except Exception as error:  # noqa: BLE001 - recorded, then re-raised
            handle.record_error(f"{type(error).__name__}: {error}")
            raise
        finally:
            handle.end()

    def start_child(self, name: str, attributes: Mapping[str, Any] | None = None) -> "SpanHandle":
        return self.tracer.start_span(name, parent=self, attributes=attributes)

    def end(self) -> None:
        if self.ended:
            return
        self.ended = True
        duration_ms = int((time.monotonic() - self.started_at) * 1000)
        self.tracer._finish(self, duration_ms)
        self.tracer._end_otel_span(self._otel)
        if self.parent is not None:
            self.parent.children.append(self.span_id)
            self.parent._child_durations[self.name] = duration_ms

    @property
    def duration_ms(self) -> int:
        return int((time.monotonic() - self.started_at) * 1000)

    def usage_recorded(self) -> bool:
        return all(key in self.attributes for key in USAGE_ATTRIBUTE_KEYS)

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "ended": self.ended,
            "attributes": dict(self.attributes),
            "dropped_after_end": list(self.dropped_after_end),
            "rejected_attributes": list(self.rejected),
        }


class Tracer:
    """Owns the span tree and (optionally) mirrors it into OpenTelemetry."""

    def __init__(
        self,
        *,
        service_name: str = "northstar-agent-runtime",
        collect: bool = True,
        max_attribute_chars: int = MAX_ATTRIBUTE_CHARS,
        forbid_content: bool = True,
        otel_tracer: Any | None = None,
    ) -> None:
        self.service_name = service_name
        self.collect = collect
        self.max_attribute_chars = max_attribute_chars
        self.forbid_content = forbid_content
        self.spans: list[SpanRecord] = []
        self._records: dict[str, SpanRecord] = {}
        self.open_spans: list[SpanHandle] = []
        self._sequence = 0
        self._otel_tracer = otel_tracer if otel_tracer is not None else _default_otel_tracer(service_name)

    # -- plumbing ---------------------------------------------------------
    def _next_id(self, kind: str) -> str:
        self._sequence += 1
        return f"{kind}-{self._sequence:04d}"

    def _accept(self, key: str, value: Any) -> tuple[bool, str]:
        if self.forbid_content and key.lower() in FORBIDDEN_ATTRIBUTE_KEYS:
            return False, "conversation content is never recorded on a span"
        if isinstance(value, bool) or isinstance(value, (int, float)):
            return True, ""
        if isinstance(value, str):
            if self.max_attribute_chars > 0 and len(value) > self.max_attribute_chars:
                return False, "string value exceeds the span attribute cap"
            return True, ""
        if isinstance(value, (list, tuple, set)):
            items = list(value)
            if len(items) > MAX_ATTRIBUTE_SEQUENCE_ITEMS:
                return False, "sequence value exceeds the span attribute cap"
            if not all(isinstance(item, str) for item in items):
                return False, "sequences must hold strings"
            if any(self.max_attribute_chars > 0 and len(item) > self.max_attribute_chars for item in items):
                return False, "sequence item exceeds the span attribute cap"
            return True, ""
        return False, "value must be a scalar or a list of strings; payloads are never recorded"

    def _start_otel_span(self, name: str, handle: SpanHandle) -> Any:
        if self._otel_tracer is None:
            return None
        try:
            parent_context = None
            if handle.parent is not None and getattr(handle.parent, "_otel", None) is not None:
                from opentelemetry import trace as _trace

                parent_context = _trace.set_span_in_context(handle.parent._otel)
            return self._otel_tracer.start_span(name, context=parent_context)
        except Exception:  # noqa: BLE001 - tracing must never break a run
            return None

    def _set_otel_attribute(self, span: Any, key: str, value: Any) -> None:
        if span is None:
            return
        try:
            if isinstance(value, bool) or isinstance(value, (int, float, str)):
                span.set_attribute(key, value)
            elif isinstance(value, (list, tuple)) and all(isinstance(item, str) for item in value):
                span.set_attribute(key, tuple(value))
        except Exception:  # noqa: BLE001 - never break a run over telemetry
            return

    def _end_otel_span(self, span: Any) -> None:
        if span is None:
            return
        try:
            span.end()
        except Exception:  # noqa: BLE001
            return

    def _note_dropped(self, handle: SpanHandle, key: str) -> None:
        record = self._records.get(handle.span_id)
        if record is not None:
            record.dropped_after_end.append(key)

    def _finish(self, handle: SpanHandle, duration_ms: int) -> None:
        record = SpanRecord(
            name=handle.name,
            attributes=dict(handle.attributes),
            span_id=handle.span_id,
            parent_span_id=handle.parent_span_id,
            children=tuple(handle.children),
            started_at=handle.started_at,
            duration_ms=duration_ms,
            sequence=handle.sequence,
            dropped_after_end=list(handle.dropped_after_end),
            rejected_attributes=tuple(handle.rejected),
            error=handle.error,
        )
        if self.collect:
            self.spans.append(record)
            self._records[handle.span_id] = record
        if handle in self.open_spans:
            self.open_spans.remove(handle)

    # -- public API -------------------------------------------------------
    def start_span(
        self,
        name: str,
        *,
        parent: SpanHandle | None = None,
        attributes: Mapping[str, Any] | None = None,
    ) -> SpanHandle:
        handle = SpanHandle(self, name, parent=parent, attributes=attributes)
        self.open_spans.append(handle)
        return handle

    @contextmanager
    def span(self, name: str, *, parent: SpanHandle | None = None, attributes: Mapping[str, Any] | None = None) -> Iterator[SpanHandle]:
        handle = self.start_span(name, parent=parent, attributes=attributes)
        try:
            yield handle
        except Exception as error:  # noqa: BLE001 - record then propagate
            handle.record_error(f"{type(error).__name__}: {error}")
            raise
        finally:
            handle.end()

    def records(self) -> tuple[SpanRecord, ...]:
        return tuple(self.spans)

    def by_name(self, name: str) -> tuple[SpanRecord, ...]:
        """All spans with this name, oldest created first."""
        return tuple(sorted((record for record in self.spans if record.name == name), key=lambda item: item.sequence))

    def find(self, name: str) -> SpanRecord | None:
        """The outermost span with this name, i.e. the first one created."""
        found = self.by_name(name)
        return found[0] if found else None

    def names(self) -> tuple[str, ...]:
        return tuple(record.name for record in self.spans)

    def total_dropped_attributes(self) -> tuple[tuple[str, str], ...]:
        """Every attribute write that was dropped because a span had ended."""
        return tuple((record.name, key) for record in self.spans for key in record.dropped_after_end)

    def tree(self) -> str:
        """Indented rendering used by the CLI's ``--trace`` flag and by tests."""
        by_id = {record.span_id: record for record in self.spans}
        roots = [record for record in self.spans if not record.parent_span_id or record.parent_span_id not in by_id]

        def render(record: SpanRecord, depth: int) -> list[str]:
            lines = [f"{'  ' * depth}{record.name} ({record.duration_ms} ms)"]
            for key in sorted(record.attributes):
                lines.append(f"{'  ' * (depth + 1)}- {key}={record.attributes[key]}")
            for child_id in record.children:
                child = by_id.get(child_id)
                if child is not None:
                    lines.extend(render(child, depth + 1))
            return lines

        rendered: list[str] = []
        for root in roots:
            rendered.extend(render(root, 0))
        return "\n".join(rendered)

    def reset(self) -> None:
        self.spans.clear()
        self._records.clear()
        self.open_spans.clear()


def _default_otel_tracer(service_name: str) -> Any:
    """Return the ambient OTel tracer, or ``None`` when OTel is not installed."""
    try:
        from opentelemetry import trace
    except ImportError:
        return None
    try:
        return trace.get_tracer(service_name)
    except Exception:  # pragma: no cover - defensive: never break a run for tracing
        return None


def otel_available() -> bool:
    try:  # pragma: no cover - environment dependent
        import opentelemetry  # noqa: F401
    except ImportError:
        return False
    return True


def sdk_available() -> bool:
    try:  # pragma: no cover - environment dependent
        import opentelemetry.sdk  # noqa: F401
    except ImportError:
        return False
    return True


def _unused(items: Sequence[Any]) -> None:  # pragma: no cover
    return None


__all__ = [
    "FORBIDDEN_ATTRIBUTE_KEYS",
    "MAX_ATTRIBUTE_CHARS",
    "USAGE_ATTRIBUTE_KEYS",
    "SpanHandle",
    "SpanRecord",
    "Tracer",
    "otel_available",
    "sdk_available",
]
