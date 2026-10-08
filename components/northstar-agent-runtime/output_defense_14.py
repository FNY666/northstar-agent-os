"""Output defense 14: source attribution, Simulated.

Tracks which sources contributed to an output: register sources, then
attribute spans of the output to them.  Produces an attribution map for
the audit trail.  Unattributed substantive spans are flagged.

What this IS: provenance ledger for output composition.
What this IS NOT: not automatic — host attributes spans at generation
boundaries; cannot infer sources from raw text.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Dict, List, Optional

OUTPUT_DEFENSE_14_VERSION = "output-defense-14.v1"
SCHEMA_PIN = "northstar.output-defense-14.v1"


class AttributionError(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class Source:
    source_id: str
    kind: str  # "user" | "tool" | "retrieval" | "model"
    uri: str = ""


@dataclass(frozen=True)
class SpanAttribution:
    start: int
    end: int
    source_id: str


class AttributionTracker:
    def __init__(self) -> None:
        self._sources: Dict[str, Source] = {}
        self._spans: List[SpanAttribution] = []

    def register(self, source: Source) -> None:
        if not source.source_id:
            raise AttributionError("source_id required")
        self._sources[source.source_id] = source

    def attribute(
        self, start: int, end: int, source_id: str
    ) -> None:
        """Attribute text[start:end] to a registered source."""
        if source_id not in self._sources:
            raise AttributionError(f"unknown source '{source_id}'")
        if not (0 <= start < end):
            raise AttributionError("invalid span")
        self._spans.append(SpanAttribution(start, end, source_id))

    def coverage(self, text_len: int) -> float:
        """Fraction of text covered by attributed spans."""
        if text_len <= 0:
            return 1.0
        covered = [False] * text_len
        for s in self._spans:
            for i in range(max(0, s.start), min(text_len, s.end)):
                covered[i] = True
        return sum(covered) / text_len

    def unattributed_gaps(
        self, text_len: int, min_gap: int = 20
    ) -> List[tuple]:
        """Return (start, end) gaps of unattributed text >= min_gap."""
        covered = [False] * text_len
        for s in self._spans:
            for i in range(max(0, s.start), min(text_len, s.end)):
                covered[i] = True
        gaps: List[tuple] = []
        i = 0
        while i < text_len:
            if not covered[i]:
                j = i
                while j < text_len and not covered[j]:
                    j += 1
                if j - i >= min_gap:
                    gaps.append((i, j))
                i = j
            else:
                i += 1
        return gaps

    @property
    def sources(self) -> Dict[str, Source]:
        return dict(self._sources)


def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "dataclasses", "pathlib", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    t = AttributionTracker()
    t.register(Source("s1", "tool", "tool://search"))
    t.register(Source("s2", "user"))
    t.attribute(0, 50, "s1")
    t.attribute(50, 100, "s2")
    assert t.coverage(100) == 1.0
    assert t.unattributed_gaps(100) == []
    t2 = AttributionTracker()
    t2.register(Source("s1", "tool"))
    t2.attribute(0, 10, "s1")
    assert t2.coverage(100) == 0.1
    assert t2.unattributed_gaps(100, min_gap=20) == [(10, 100)]
    try:
        t2.attribute(0, 5, "nope")
        raise AssertionError("should raise")
    except AttributionError:
        pass
    assert stdlib_only()
    print("output-defense-14 OK: attribution, gaps, fail-closed, stdlib")


if __name__ == "__main__":
    main()
