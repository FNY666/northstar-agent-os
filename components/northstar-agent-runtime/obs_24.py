"""obs_24: Multi-window alerts (mock), Simulated.

Pairs a long window with a short window (Google SRE multiwindow alerting)
over synthetic event samples.  ``update`` records (ts, bad, total) samples;
``evaluate`` computes the burn rate inside each trailing window and fires
only when BOTH windows exceed the burn threshold, which suppresses alerts
on already-resolved incidents.  ``reset`` clears all samples.

Fail-closed: out-of-order or duplicate timestamps, non-positive windows,
or bad > total raise.
Stdlib only.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Tuple

OBS24_VERSION = "obs-24.v1"
SCHEMA_PIN = "northstar.obs-24.v1"


class Obs24Error(Exception):
    """Fail-closed."""


class MultiWindowAlert:
    """Burn-rate alert evaluated over a long and a short trailing window."""

    def __init__(self, long_window_s: float, short_window_s: float,
                 burn_threshold: float, slo_target: float = 0.999) -> None:
        for value, label in ((long_window_s, "long_window_s"), (short_window_s, "short_window_s")):
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                raise Obs24Error(f"{label} must be a number")
            if float(value) <= 0:
                raise Obs24Error(f"{label} must be positive")
        if float(short_window_s) >= float(long_window_s):
            raise Obs24Error("short_window_s must be < long_window_s")
        if not isinstance(burn_threshold, (int, float)) or isinstance(burn_threshold, bool):
            raise Obs24Error("burn_threshold must be a number")
        if float(burn_threshold) <= 0:
            raise Obs24Error("burn_threshold must be positive")
        if not isinstance(slo_target, (int, float)) or isinstance(slo_target, bool):
            raise Obs24Error("slo_target must be a number")
        if not 0.0 < float(slo_target) < 1.0:
            raise Obs24Error("slo_target must be inside (0, 1)")
        self.long_window_s = float(long_window_s)
        self.short_window_s = float(short_window_s)
        self.burn_threshold = float(burn_threshold)
        self.slo_target = float(slo_target)
        self._samples: List[Tuple[float, int, int]] = []
        self._last_ts: float | None = None

    def update(self, ts: float, bad: int, total: int) -> None:
        """Record a (timestamp, bad, total) sample."""
        if not isinstance(ts, (int, float)) or isinstance(ts, bool):
            raise Obs24Error("ts must be a number")
        if self._last_ts is not None and float(ts) <= self._last_ts:
            raise Obs24Error("timestamps must be strictly increasing")
        for value, label in ((bad, "bad"), (total, "total")):
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise Obs24Error(f"{label} must be a non-negative int")
        if total == 0:
            raise Obs24Error("total must be > 0")
        if bad > total:
            raise Obs24Error("bad cannot exceed total")
        self._samples.append((float(ts), bad, total))
        self._last_ts = float(ts)

    def _window_burn(self, now: float, window_s: float) -> float:
        cutoff = now - window_s
        bad = sum(b for ts, b, _ in self._samples if ts > cutoff)
        total = sum(t for ts, _, t in self._samples if ts > cutoff)
        budgeted = (1.0 - self.slo_target) * total
        if budgeted <= 0:
            return 0.0
        return bad / budgeted

    def evaluate(self, now: float) -> Dict[str, object]:
        """Evaluate both windows; fires only when both exceed the threshold."""
        if not isinstance(now, (int, float)) or isinstance(now, bool):
            raise Obs24Error("now must be a number")
        if self._last_ts is not None and float(now) < self._last_ts:
            raise Obs24Error("now cannot precede the last sample")
        long_burn = self._window_burn(float(now), self.long_window_s)
        short_burn = self._window_burn(float(now), self.short_window_s)
        firing = long_burn > self.burn_threshold and short_burn > self.burn_threshold
        return {
            "long_burn": long_burn,
            "short_burn": short_burn,
            "threshold": self.burn_threshold,
            "firing": firing,
            "samples": len(self._samples),
        }

    def reset(self) -> None:
        """Clear all samples."""
        self._samples.clear()
        self._last_ts = None


def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing"}
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
    a = MultiWindowAlert(3600.0, 300.0, 2.0, 0.99)
    # Sustained 20% error rate: burn ~ 0.2/0.01 = 20x in both windows.
    for i in range(12):
        a.update(i * 300.0, 200, 1000)
    out = a.evaluate(3300.0)
    assert abs(out["long_burn"] - 20.0) < 1e-6
    assert abs(out["short_burn"] - 20.0) < 1e-6
    assert out["firing"] is True and out["samples"] == 12
    # Resolved incident: only healthy samples in the short window.
    b = MultiWindowAlert(3600.0, 300.0, 2.0, 0.99)
    b.update(0.0, 900, 1000)
    b.update(3500.0, 0, 1000)
    out2 = b.evaluate(3600.0)
    assert out2["firing"] is False
    assert out2["short_burn"] == 0.0
    b.reset()
    out3 = b.evaluate(9999.0)
    assert out3["samples"] == 0 and out3["firing"] is False
    try:
        a.update(300.0, 1, 10)  # out of order
        raise AssertionError("should raise")
    except Obs24Error:
        pass
    try:
        MultiWindowAlert(300.0, 600.0, 2.0)
        raise AssertionError("should raise")
    except Obs24Error:
        pass
    assert stdlib_only()
    print("obs_24 OK")


if __name__ == "__main__":
    main()
