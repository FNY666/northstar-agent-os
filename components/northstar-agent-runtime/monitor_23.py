"""Dark-web monitoring: mock watchlist matching, Simulated.

Maintains a watchlist of terms (domain, email, keyword, brand), each
with a severity. The host ingests findings (finding_id, source, text,
ts); case-insensitive substring matches raise alerts; deduped by
(finding_id, term).

What this IS: watchlist matching + alerting.

What this IS NOT:
* Not dark-web access -- findings are host-supplied.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple

#: Module version.
MONITOR_23_VERSION = "monitor-23.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.monitor-23.v1"

_CATEGORIES = frozenset({"domain", "email", "keyword", "brand"})


class DarkWebError(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class WatchTerm:
    term: str
    category: str
    severity: int


@dataclass(frozen=True)
class DarkWebAlert:
    finding_id: str
    term: str
    category: str
    severity: int
    source: str
    ts: float


class DarkWebMonitor:
    """Mock dark-web watchlist monitor."""

    def __init__(self) -> None:
        self._terms: Dict[str, WatchTerm] = {}
        self._alerts: List[DarkWebAlert] = []
        self._seen: Set[Tuple[str, str]] = set()

    def watch(self, term: str, category: str, severity: int) -> None:
        if not term or not isinstance(term, str):
            raise DarkWebError("term required")
        if category not in _CATEGORIES:
            raise DarkWebError(f"unknown category {category!r}")
        if not 1 <= severity <= 100:
            raise DarkWebError("severity must be 1-100")
        self._terms[term.lower()] = WatchTerm(term.lower(), category, severity)

    def unwatch(self, term: str) -> None:
        if term.lower() not in self._terms:
            raise DarkWebError(f"term {term!r} not watched")
        del self._terms[term.lower()]

    def ingest(
        self, finding_id: str, source: str, text: str, ts: float = 0.0
    ) -> List[DarkWebAlert]:
        if not finding_id or not source or not isinstance(text, str):
            raise DarkWebError("finding_id/source/text required")
        if ts < 0:
            raise DarkWebError("ts must be >= 0")
        lowered = text.lower()
        fired: List[DarkWebAlert] = []
        for term, wt in self._terms.items():
            if term in lowered and (finding_id, term) not in self._seen:
                self._seen.add((finding_id, term))
                alert = DarkWebAlert(finding_id, wt.term, wt.category,
                                     wt.severity, source, ts)
                self._alerts.append(alert)
                fired.append(alert)
        return fired

    def alerts(self) -> List[DarkWebAlert]:
        return list(self._alerts)


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
    m = DarkWebMonitor()
    m.watch("acme.com", "domain", 80)
    m.watch("admin@acme.com", "email", 90)
    m.watch("project falcon", "keyword", 60)
    got = m.ingest("f1", "forum-x", "dumps for acme.com, contact admin@acme.com", ts=1.0)
    assert len(got) == 2
    assert {a.term for a in got} == {"acme.com", "admin@acme.com"}
    # Dedupe: same finding re-ingested fires nothing new.
    assert m.ingest("f1", "forum-x", "acme.com again", ts=2.0) == []
    got = m.ingest("f2", "market-y", "Project Falcon source code", ts=3.0)
    assert len(got) == 1 and got[0].category == "keyword"
    m.unwatch("acme.com")
    assert m.ingest("f3", "z", "acme.com", ts=4.0) == []
    for bad in (
        lambda: m.watch("", "domain", 50),
        lambda: m.watch("x", "bogus", 50),
        lambda: m.watch("x", "domain", 0),
        lambda: m.unwatch("ghost"),
        lambda: m.ingest("", "s", "t"),
        lambda: m.ingest("f", "s", "t", ts=-1),
    ):
        try:
            bad()
            raise AssertionError("should raise")
        except DarkWebError:
            pass
    assert stdlib_only()
    print("monitor-23 OK: watchlist, matching, dedupe, unwatch, fail-closed, stdlib")


if __name__ == "__main__":
    main()
