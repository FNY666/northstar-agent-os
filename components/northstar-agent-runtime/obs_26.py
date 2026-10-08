"""obs_26: Incident response (mock), Simulated.

Incident lifecycle: open -> acknowledged -> mitigated -> resolved
(open -> mitigated is also allowed).  Mock: no paging integration,
events are recorded with wall-clock timestamps locally.

Fail-closed: empty title, bad severity, or invalid transition raises.
Stdlib only.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

OBS26_VERSION = "obs-26.v1"
SCHEMA_PIN = "northstar.obs-26.v1"

VALID_SEVERITIES = ("sev1", "sev2", "sev3", "sev4")

_TRANSITIONS: Dict[str, Tuple[str, ...]] = {
    "open": ("acknowledged", "mitigated"),
    "acknowledged": ("mitigated",),
    "mitigated": ("resolved",),
    "resolved": (),
}


class Obs26Error(Exception):
    """Fail-closed."""


@dataclass
class IncidentEvent:
    at: str
    from_state: str
    to_state: str
    note: str


class Incident:
    """Mock incident with a strict state machine."""

    def __init__(self, incident_id: str, title: str, severity: str) -> None:
        if not isinstance(incident_id, str) or not incident_id:
            raise Obs26Error("incident_id must be a non-empty string")
        if not isinstance(title, str) or not title.strip():
            raise Obs26Error("title must be a non-empty string")
        if severity not in VALID_SEVERITIES:
            raise Obs26Error(f"severity must be one of {VALID_SEVERITIES}")
        self.incident_id = incident_id
        self.title = title
        self.severity = severity
        self.state = "open"
        self._events: List[IncidentEvent] = [
            self._event("none", "open", "incident created")
        ]

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    def _event(self, from_state: str, to_state: str, note: str) -> IncidentEvent:
        return IncidentEvent(at=self._now(), from_state=from_state, to_state=to_state, note=note)

    def _transition(self, to_state: str, note: str) -> None:
        if to_state not in _TRANSITIONS[self.state]:
            raise Obs26Error(f"invalid transition {self.state} -> {to_state}")
        self._events.append(self._event(self.state, to_state, note))
        self.state = to_state

    def acknowledge(self, note: str = "") -> None:
        self._transition("acknowledged", note)

    def mitigate(self, note: str = "") -> None:
        self._transition("mitigated", note)

    def resolve(self, note: str = "") -> None:
        self._transition("resolved", note)

    def timeline(self) -> List[Dict[str, Any]]:
        """Return ordered event log as plain dicts."""
        return [
            {
                "at": e.at,
                "from": e.from_state,
                "to": e.to_state,
                "note": e.note,
            }
            for e in self._events
        ]


def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "dataclasses", "datetime", "pathlib", "typing"}
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
    inc = Incident("INC-1", "db down", "sev1")
    assert inc.state == "open"
    inc.acknowledge("pager woke me")
    assert inc.state == "acknowledged"
    inc.mitigate("failover done")
    inc.resolve("confirmed healthy")
    assert inc.state == "resolved"
    tl = inc.timeline()
    assert len(tl) == 4 and tl[0]["to"] == "open" and tl[-1]["to"] == "resolved"

    inc2 = Incident("INC-2", "slow", "sev4")
    inc2.mitigate("skipped ack")
    assert inc2.state == "mitigated"

    try:
        Incident("INC-3", "", "sev2")
        raise AssertionError("should raise")
    except Obs26Error:
        pass
    try:
        Incident("INC-4", "x", "sev9")
        raise AssertionError("should raise")
    except Obs26Error:
        pass
    try:
        Incident("INC-5", "x", "sev3").resolve()
        raise AssertionError("should raise")
    except Obs26Error:
        pass
    try:
        inc2.resolve()
        inc2.acknowledge()
        raise AssertionError("should raise")
    except Obs26Error:
        pass
    try:
        inc.acknowledge()
        raise AssertionError("should raise")
    except Obs26Error:
        pass
    assert stdlib_only()
    print("obs_26 OK")


if __name__ == "__main__":
    main()
