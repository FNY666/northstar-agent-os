"""OpenTelemetry span tree for agent runs.

Hierarchy:

    run
    └── turn[1]
        ├── generation
        ├── tool:Read
        └── subagent:evaluator
            └── (the subagent's own run/turn tree)

Cost and usage attributes are recorded **before the span ends**: the OTel
SDK silently drops ``set_attribute`` calls made after ``end()``, so every
attribute in this project is set while the ``with`` block is still open.

Span attributes deliberately contain **no prompt text and no tool output
text** — only counts, costs, and ``tool.is_error``.
"""
from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Iterator, Mapping, Optional

from opentelemetry import trace

TRACER_NAME = "northstar.agent-runtime"


class RuntimeTracer:
    """Thin wrapper keeping span creation conventions in one place."""

    def __init__(self, tracer: Optional[Any] = None) -> None:
        self._tracer = tracer if tracer is not None else trace.get_tracer(TRACER_NAME)

    @contextmanager
    def span(self, name: str, attributes: Optional[Mapping[str, Any]] = None) -> Iterator[Any]:
        with self._tracer.start_as_current_span(name) as span:
            if attributes:
                for key, value in attributes.items():
                    span.set_attribute(key, value)
            yield span
