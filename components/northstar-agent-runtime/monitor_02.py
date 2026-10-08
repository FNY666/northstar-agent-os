"""Prometheus metrics: counter/gauge/histogram (mock), Simulated.

Implements Prometheus metric semantics without the client library:
Counter (monotonic), Gauge (set/inc/dec), Histogram (buckets).
Supports labels and renders the text exposition format.

What this IS: metric collection at gate boundaries with a
scrape-compatible text render.

What this IS NOT:
* Not the real prometheus_client -- no HTTP server. Host exposes
  the rendered text on /metrics.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

#: Module version.
MONITOR_02_VERSION = "monitor-02.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.monitor-02.v1"


class MetricsError(Exception):
    """Fail-closed."""


def _check_labels(labels: Optional[Dict[str, str]]) -> Dict[str, str]:
    labels = labels or {}
    for k, v in labels.items():
        if not isinstance(k, str) or not isinstance(v, str):
            raise MetricsError("labels must be str->str")
    return dict(labels)


@dataclass
class Counter:
    name: str
    help_text: str = ""
    _values: Dict[Tuple[Tuple[str, str], ...], float] = field(default_factory=dict)

    def inc(self, amount: float = 1.0, labels: Optional[Dict[str, str]] = None) -> None:
        if amount < 0:
            raise MetricsError("counter cannot decrease")
        key = tuple(sorted(_check_labels(labels).items()))
        self._values[key] = self._values.get(key, 0.0) + amount

    def get(self, labels: Optional[Dict[str, str]] = None) -> float:
        return self._values.get(tuple(sorted(_check_labels(labels).items())), 0.0)


@dataclass
class Gauge:
    name: str
    help_text: str = ""
    _values: Dict[Tuple[Tuple[str, str], ...], float] = field(default_factory=dict)

    def set(self, value: float, labels: Optional[Dict[str, str]] = None) -> None:
        key = tuple(sorted(_check_labels(labels).items()))
        self._values[key] = float(value)

    def inc(self, amount: float = 1.0, labels: Optional[Dict[str, str]] = None) -> None:
        key = tuple(sorted(_check_labels(labels).items()))
        self._values[key] = self._values.get(key, 0.0) + amount

    def dec(self, amount: float = 1.0, labels: Optional[Dict[str, str]] = None) -> None:
        key = tuple(sorted(_check_labels(labels).items()))
        self._values[key] = self._values.get(key, 0.0) - amount

    def get(self, labels: Optional[Dict[str, str]] = None) -> float:
        return self._values.get(tuple(sorted(_check_labels(labels).items())), 0.0)


@dataclass
class Histogram:
    name: str
    buckets: Tuple[float, ...] = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0)
    help_text: str = ""
    _counts: Dict[Tuple[Tuple[str, str], ...], List[int]] = field(default_factory=dict)
    _sums: Dict[Tuple[Tuple[str, str], ...], float] = field(default_factory=dict)

    def observe(self, value: float, labels: Optional[Dict[str, str]] = None) -> None:
        if value < 0:
            raise MetricsError("histogram value must be >= 0")
        key = tuple(sorted(_check_labels(labels).items()))
        counts = self._counts.setdefault(key, [0] * (len(self.buckets) + 1))
        placed = False
        for i, bound in enumerate(self.buckets):
            if value <= bound:
                counts[i] += 1
                placed = True
                break
        if not placed:
            counts[-1] += 1  # +Inf bucket
        self._sums[key] = self._sums.get(key, 0.0) + value

    def count(self, labels: Optional[Dict[str, str]] = None) -> int:
        key = tuple(sorted(_check_labels(labels).items()))
        return sum(self._counts.get(key, [0]))


class Registry:
    """Metric registry with exposition rendering."""

    def __init__(self) -> None:
        self._metrics: Dict[str, object] = {}

    def register(self, metric: object) -> None:
        name = getattr(metric, "name", None)
        if not name or name in self._metrics:
            raise MetricsError(f"bad or duplicate metric name {name!r}")
        self._metrics[name] = metric

    def get(self, name: str) -> object:
        if name not in self._metrics:
            raise MetricsError(f"unknown metric {name!r}")
        return self._metrics[name]

    def render(self) -> str:
        lines: List[str] = []
        for name, m in self._metrics.items():
            mtype = type(m).__name__.lower()
            lines.append(f"# HELP {name} {getattr(m, 'help_text', '')}")
            lines.append(f"# TYPE {name} {mtype}")
            if isinstance(m, Histogram):
                for key, counts in m._counts.items():
                    lab = ",".join(f'{k}="{v}"' for k, v in key)
                    lab_s = f"{{{lab}}}" if lab else ""
                    cum = 0
                    for bound, c in zip(m.buckets, counts):
                        cum += c
                        lines.append(f'{name}_bucket{{le="{bound}"{"," if lab else ""}{lab}}} {cum}')
                    lines.append(f'{name}_bucket{{le="+Inf"{"," if lab else ""}{lab}}} {sum(counts)}')
                    lines.append(f"{name}_sum{lab_s} {m._sums.get(key, 0.0)}")
                    lines.append(f"{name}_count{lab_s} {sum(counts)}")
            else:
                for key, val in m._values.items():
                    lab = ",".join(f'{k}="{v}"' for k, v in key)
                    lab_s = f"{{{lab}}}" if lab else ""
                    lines.append(f"{name}{lab_s} {val}")
        return "\n".join(lines) + "\n"


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "dataclasses", "pathlib", "typing"}
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
    reg = Registry()
    c = Counter("gate_decisions_total", "gate decisions")
    g = Gauge("active_sessions")
    h = Histogram("gate_latency_seconds")
    reg.register(c)
    reg.register(g)
    reg.register(h)
    c.inc(labels={"gate": "authorize", "decision": "deny"})
    c.inc(2)
    assert c.get({"gate": "authorize", "decision": "deny"}) == 1.0
    assert c.get() == 2.0
    g.set(5)
    g.dec(2)
    assert g.get() == 3.0
    h.observe(0.03)
    h.observe(3.0)
    assert h.count() == 2
    out = reg.render()
    assert "gate_decisions_total" in out and "gate_latency_seconds_bucket" in out
    try:
        c.inc(-1)
        raise AssertionError("should raise")
    except MetricsError:
        pass
    try:
        reg.get("nope")
        raise AssertionError("should raise")
    except MetricsError:
        pass
    assert stdlib_only()
    print("monitor-02 OK: counter/gauge/histogram, render, fail-closed, stdlib")


if __name__ == "__main__":
    main()
