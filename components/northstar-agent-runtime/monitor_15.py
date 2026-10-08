"""UEBA: user/entity behavior analytics (mock), Simulated.

Scores risk per entity from security-relevant events:
- failed_login (weight scales with consecutive failures)
- unusual_hour (activity outside 06:00-22:00 local)
- new_device / new_ip
- data_volume_mb (large exfil-style transfers)
- privilege_use (sensitive tool use)

Risk decays over time (half-life). score >= high_threshold flags
the entity. All weights configurable.

What this IS: entity risk scoring feeding quarantine decisions.

What this IS NOT:
* Not ML -- weighted, decaying counters only.
"""

from __future__ import annotations

import ast
import math
import time
from dataclasses import dataclass, field
from typing import Dict, Optional

#: Module version.
MONITOR_15_VERSION = "monitor-15.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.monitor-15.v1"

_VALID_EVENTS = {
    "failed_login",
    "success_login",
    "unusual_hour",
    "new_device",
    "new_ip",
    "data_volume_mb",
    "privilege_use",
}


class UebaError(Exception):
    """Fail-closed."""


@dataclass
class EntityRisk:
    entity: str
    risk: float = 0.0
    last_update_ns: int = field(default_factory=time.time_ns)
    consecutive_failures: int = 0
    known_devices: int = 0

    def decay(self, now_ns: int, half_life_s: float) -> None:
        dt_s = max(0.0, (now_ns - self.last_update_ns) / 1e9)
        self.risk *= 0.5 ** (dt_s / half_life_s)
        self.last_update_ns = now_ns


class Ueba:
    """Per-entity risk tracker."""

    def __init__(
        self,
        *,
        half_life_s: float = 3600.0,
        high_threshold: float = 70.0,
        weights: Optional[Dict[str, float]] = None,
    ) -> None:
        if half_life_s <= 0:
            raise UebaError("half_life_s must be positive")
        if high_threshold <= 0:
            raise UebaError("high_threshold must be positive")
        self._half_life = half_life_s
        self._threshold = high_threshold
        self._weights = dict(
            weights
            or {
                "failed_login": 8.0,
                "unusual_hour": 10.0,
                "new_device": 15.0,
                "new_ip": 12.0,
                "data_volume_mb": 0.5,  # per MB
                "privilege_use": 20.0,
            }
        )
        self._entities: Dict[str, EntityRisk] = {}

    def _get(self, entity: str) -> EntityRisk:
        if not entity:
            raise UebaError("entity required")
        ent = self._entities.get(entity)
        if ent is None:
            ent = EntityRisk(entity=entity)
            self._entities[entity] = ent
        ent.decay(time.time_ns(), self._half_life)
        return ent

    def ingest(
        self,
        entity: str,
        event: str,
        value: float = 1.0,
        hour: Optional[int] = None,
    ) -> float:
        """Ingest an event; returns current risk score."""
        if event not in _VALID_EVENTS:
            raise UebaError(f"unknown event {event!r}")
        ent = self._get(entity)
        if event == "success_login":
            ent.consecutive_failures = 0
            ent.last_update_ns = time.time_ns()
            return ent.risk
        w = self._weights[event]
        if event == "failed_login":
            ent.consecutive_failures += 1
            ent.risk += w * ent.consecutive_failures  # escalating
        elif event == "unusual_hour":
            h = hour if hour is not None else time.localtime().tm_hour
            if not 0 <= h <= 23:
                raise UebaError("hour must be 0-23")
            if h < 6 or h >= 22:
                ent.risk += w
        elif event == "data_volume_mb":
            if value < 0:
                raise UebaError("data volume must be >= 0")
            ent.risk += w * value
        else:
            ent.risk += w * value
        ent.last_update_ns = time.time_ns()
        return ent.risk

    def score(self, entity: str) -> float:
        return self._get(entity).risk

    def flagged(self, entity: str) -> bool:
        return self.score(entity) >= self._threshold

    def reset(self, entity: str) -> None:
        self._entities.pop(entity, None)


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "dataclasses", "math", "pathlib", "time", "typing"}
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
    ueba = Ueba(half_life_s=3600, high_threshold=70)
    assert ueba.flagged("alice") is False
    ueba.ingest("alice", "failed_login")  # +8
    ueba.ingest("alice", "failed_login")  # +16 (escalating)
    ueba.ingest("alice", "new_device")  # +15
    ueba.ingest("alice", "privilege_use")  # +20 -> 59
    assert ueba.flagged("alice") is False
    ueba.ingest("alice", "unusual_hour", hour=3)  # +10 -> 69
    ueba.ingest("alice", "new_ip")  # +12 -> 81
    assert ueba.flagged("alice") is True
    ueba.ingest("bob", "success_login")
    assert ueba.score("bob") == 0.0
    try:
        ueba.ingest("alice", "bogus_event")
        raise AssertionError("should raise")
    except UebaError:
        pass
    try:
        ueba.ingest("", "new_ip")
        raise AssertionError("should raise")
    except UebaError:
        pass
    assert stdlib_only()
    print("monitor-15 OK: risk scoring, decay, thresholds, fail-closed, stdlib")


if __name__ == "__main__":
    main()
