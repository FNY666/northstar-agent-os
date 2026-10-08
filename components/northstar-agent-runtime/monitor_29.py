"""Timeline analysis: mock event timeline builder, Simulated.

Ingests structured events {source, kind, ts, detail}; build() returns
the chronological timeline; window(start, end) filters; gaps(min_gap_s)
finds quiet periods; offsets(anchor_kind) gives seconds relative to the
first anchor-kind event.

What this IS: deterministic timeline assembly.

What this IS NOT:
* Not log parsing -- structured events in.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Dict, List, Tuple

#: Module version.
MONITOR_29_VERSION = "monitor-29.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.monitor-29.v1"


class TimelineError(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class TEvent:
    source: str
    kind: str
    ts: float
    detail: str = ""

    def __post_init__(self) -> None:
        if not self.source or not self.kind:
            raise TimelineError("source/kind required")
        if self.ts < 0:
            raise TimelineError("ts must be >= 0")


class Timeline:
    """Event timeline builder (mock)."""

    def __init__(self) -> None:
        self._events: List[TEvent] = []

    def add(self, source: str, kind: str, ts: float, detail: str = "") -> None:
        self._events.append(TEvent(source, kind, ts, detail))

    def build(self) -> List[TEvent]:
        return sorted(self._events, key=lambda e: e.ts)

    def window(self, start: float, end: float) -> List[TEvent]:
        if start < 0 or end < start:
            raise TimelineError("bad window")
        return [e for e in self.build() if start <= e.ts <= end]

    def by_source(self, source: str) -> List[TEvent]:
        return [e for e in self.build() if e.source == source]

    def gaps(self, min_gap_s: float) -> List[Tuple[float, float]]:
        """Quiet periods >= min_gap_s between consecutive events."""
        if min_gap_s <= 0:
            raise TimelineError("min_gap_s must be positive")
        ordered = self.build()
        out: List[Tuple[float, float]] = []
        for a, b in zip(ordered, ordered[1:]):
            if b.ts - a.ts >= min_gap_s:
                out.append((a.ts, b.ts))
        return out

    def offsets(self, anchor_kind: str) -> List[Tuple[TEvent, float]]:
        """Seconds of each event relative to first anchor-kind event."""
        anchors = [e for e in self.build() if e.kind == anchor_kind]
        if not anchors:
            raise TimelineError(f"no anchor event of kind {anchor_kind!r}")
        t0 = anchors[0].ts
        return [(e, e.ts - t0) for e in self.build()]

    def summary(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for e in self._events:
            counts[e.source] = counts.get(e.source, 0) + 1
        return counts


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
    tl = Timeline()
    tl.add("edr", "malware_exec", 300.0, "evil.exe")
    tl.add("ndr", "c2", 100.0, "6.6.6.6")
    tl.add("edr", "persistence", 200.0, "Run key")
    built = tl.build()
    assert [e.ts for e in built] == [100.0, 200.0, 300.0]
    assert len(tl.window(150.0, 250.0)) == 1
    assert len(tl.by_source("edr")) == 2
    assert tl.gaps(150.0) == []  # gaps are 100s
    assert tl.gaps(100.0) == [(100.0, 200.0), (200.0, 300.0)]
    offs = tl.offsets("c2")
    assert offs[0][1] == 0.0 and offs[-1][1] == 200.0
    assert tl.summary() == {"edr": 2, "ndr": 1}
    for bad in (
        lambda: tl.add("", "k", 1.0),
        lambda: tl.add("s", "k", -1.0),
        lambda: tl.window(5.0, 1.0),
        lambda: tl.gaps(0),
        lambda: tl.offsets("nope"),
    ):
        try:
            bad()
            raise AssertionError("should raise")
        except TimelineError:
            pass
    assert stdlib_only()
    print("monitor-29 OK: build, window, gaps, offsets, fail-closed, stdlib")


if __name__ == "__main__":
    main()
