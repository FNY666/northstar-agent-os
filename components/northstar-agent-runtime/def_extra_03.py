"""Geofencing gate, Simulated.

Checks a (lat, lon) point against allowed circular zones and detects
impossible travel (position jumps faster than any plausible transport).

What this IS: location policy enforcement primitive.

What this IS NOT:
* Not real GPS validation -- coordinates are host-supplied.
* No zones configured -> FAIL CLOSED (deny).
"""

from __future__ import annotations

import ast
import math
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

#: Module version.
DEF_EXTRA_03_VERSION = "def-extra-03.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.def-extra-03.v1"


class GeofenceError(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class Zone:
    """Allowed circular zone."""

    name: str
    lat: float
    lon: float
    radius_km: float


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance in km."""
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


class Geofence:
    """Zone check + impossible-travel detection."""

    def __init__(
        self,
        zones: List[Zone],
        *,
        max_speed_kmh: float = 1000.0,
    ) -> None:
        if max_speed_kmh <= 0:
            raise GeofenceError("max_speed_kmh must be positive")
        self._zones = list(zones)
        self._max_speed = max_speed_kmh
        self._last: Dict[str, Tuple[float, float, float]] = {}

    def check(self, lat: float, lon: float) -> Tuple[bool, Optional[str]]:
        """Return (allowed, zone_name).  No zones -> (False, None)."""
        if not self._zones:
            return False, None
        for zone in self._zones:
            if haversine_km(lat, lon, zone.lat, zone.lon) <= zone.radius_km:
                return True, zone.name
        return False, None

    def check_travel(
        self,
        principal: str,
        lat: float,
        lon: float,
        *,
        now: Optional[float] = None,
    ) -> Tuple[bool, str]:
        """Detect impossible travel for a principal.

        Returns (ok, reason).  First sighting always ok.
        """
        ts = time.time() if now is None else now
        prev = self._last.get(principal)
        self._last[principal] = (lat, lon, ts)
        if prev is None:
            return True, "first sighting"
        plat, plon, pts = prev
        dt_h = (ts - pts) / 3600.0
        if dt_h <= 0:
            return False, "non-monotonic timestamp"
        dist = haversine_km(plat, plon, lat, lon)
        speed = dist / dt_h
        if speed > self._max_speed:
            return False, f"impossible travel: {speed:.0f} km/h"
        return True, "ok"


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
    fence = Geofence([Zone("hq", 22.54, 114.06, 50.0)])
    ok, zone = fence.check(22.55, 114.07)
    assert ok is True and zone == "hq"
    ok, zone = fence.check(40.71, -74.0)
    assert ok is False and zone is None
    # Empty zones fail closed.
    ok, _ = Geofence([]).check(22.55, 114.07)
    assert ok is False
    # Impossible travel: Shenzhen -> NYC in 60 seconds.
    ok, _ = fence.check_travel("alice", 22.54, 114.06, now=1000.0)
    assert ok is True
    ok, reason = fence.check_travel("alice", 40.71, -74.0, now=1060.0)
    assert ok is False and "impossible travel" in reason
    assert stdlib_only()
    print("def-extra-03 OK: zones, impossible travel, fail-closed")


if __name__ == "__main__":
    main()
