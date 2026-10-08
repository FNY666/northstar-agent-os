"""XDR correlation: mock cross-source alert correlation, Simulated.

Groups source alerts (ndr/edr/identity/email) into incidents:
- open incident match: same entity, alert within window of last activity
- severity: max(alert severities) + 10 per extra source, capped at 100
- dedupe: same (source, kind) within window merges, no new alert

What this IS: deterministic incident grouping and scoring.

What this IS NOT:
* Not ML correlation -- fixed rules; host validates.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

#: Module version.
MONITOR_18_VERSION = "monitor-18.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.monitor-18.v1"


class XdrError(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class XdrAlert:
    source: str  # ndr, edr, identity, email
    kind: str
    entity: str
    severity: int  # 1-100
    ts: float
    detail: str = ""

    def __post_init__(self) -> None:
        if not self.source or not self.kind or not self.entity:
            raise XdrError("source/kind/entity required")
        if not 1 <= self.severity <= 100:
            raise XdrError("severity must be 1-100")
        if self.ts < 0:
            raise XdrError("ts must be >= 0")


@dataclass
class Incident:
    incident_id: str
    entity: str
    sources: Set[str] = field(default_factory=set)
    alerts: List[XdrAlert] = field(default_factory=list)
    severity: int = 0
    first_ts: float = 0.0
    last_ts: float = 0.0
    status: str = "open"

    def _rescore(self) -> None:
        base = max((a.severity for a in self.alerts), default=0)
        self.severity = min(100, base + 10 * max(0, len(self.sources) - 1))


class Xdr:
    """Cross-source alert correlator (mock)."""

    def __init__(self, *, window_s: float = 3600.0) -> None:
        if window_s <= 0:
            raise XdrError("window_s must be positive")
        self._window = window_s
        self._incidents: Dict[str, Incident] = {}
        self._next = 1

    def ingest(self, alert: XdrAlert) -> str:
        """Ingest an alert; returns the incident id (new or merged)."""
        if not isinstance(alert, XdrAlert):
            raise XdrError("alert must be XdrAlert")
        for inc in self._incidents.values():
            if inc.status != "open" or inc.entity != alert.entity:
                continue
            if alert.ts - inc.last_ts > self._window:
                continue
            # Dedupe: same (source, kind) inside the window.
            if any(
                a.source == alert.source and a.kind == alert.kind
                for a in inc.alerts
            ):
                inc.last_ts = max(inc.last_ts, alert.ts)
                return inc.incident_id
            inc.alerts.append(alert)
            inc.sources.add(alert.source)
            inc.last_ts = max(inc.last_ts, alert.ts)
            inc._rescore()
            return inc.incident_id
        incident_id = f"INC-{self._next:04d}"
        self._next += 1
        inc = Incident(
            incident_id=incident_id,
            entity=alert.entity,
            sources={alert.source},
            alerts=[alert],
            first_ts=alert.ts,
            last_ts=alert.ts,
        )
        inc._rescore()
        self._incidents[incident_id] = inc
        return incident_id

    def get(self, incident_id: str) -> Incident:
        inc = self._incidents.get(incident_id)
        if inc is None:
            raise XdrError(f"unknown incident {incident_id!r}")
        return inc

    def close(self, incident_id: str) -> None:
        self.get(incident_id).status = "closed"

    def open_incidents(self) -> List[Incident]:
        return [i for i in self._incidents.values() if i.status == "open"]


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
    xdr = Xdr(window_s=3600.0)
    a1 = XdrAlert("ndr", "port_scan", "host1", 70, 100.0)
    a2 = XdrAlert("edr", "c2", "host1", 85, 200.0)
    i1 = xdr.ingest(a1)
    i2 = xdr.ingest(a2)
    assert i1 == i2  # correlated
    inc = xdr.get(i1)
    assert inc.sources == {"ndr", "edr"}
    assert inc.severity == 95  # 85 + 10 for extra source
    assert len(inc.alerts) == 2

    # Dedupe: same source+kind merges.
    i3 = xdr.ingest(XdrAlert("ndr", "port_scan", "host1", 70, 300.0))
    assert i3 == i1
    assert len(xdr.get(i1).alerts) == 2

    # Different entity -> new incident.
    i4 = xdr.ingest(XdrAlert("ndr", "port_scan", "host2", 70, 300.0))
    assert i4 != i1

    # Outside window -> new incident.
    i5 = xdr.ingest(XdrAlert("edr", "c2", "host1", 85, 100000.0))
    assert i5 != i1

    xdr.close(i1)
    assert xdr.get(i1).status == "closed"
    assert all(i.incident_id != i1 for i in xdr.open_incidents())

    for bad in (
        lambda: xdr.ingest("nope"),  # type: ignore
        lambda: XdrAlert("ndr", "x", "e", 0, 1.0),
        lambda: XdrAlert("ndr", "x", "e", 101, 1.0),
        lambda: xdr.get("INC-9999"),
        lambda: Xdr(window_s=0),
    ):
        try:
            bad()
            raise AssertionError("should raise")
        except XdrError:
            pass
    assert stdlib_only()
    print("monitor-18 OK: grouping, scoring, dedupe, close, fail-closed, stdlib")


if __name__ == "__main__":
    main()
