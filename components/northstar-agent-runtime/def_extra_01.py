"""Behavioral biometrics gate (mock), Simulated.

Enrolls a per-principal keystroke-timing baseline (mean/std of dwell
times) and verifies new samples against it with a z-score anomaly test.

What this IS: anomaly signal for step-up auth decisions.

What this IS NOT:
* Not real biometrics -- timing stats, no sensor data.
* Unknown principal or under-enrolled profile FAILS CLOSED (deny).
"""

from __future__ import annotations

import ast
import statistics
from dataclasses import dataclass
from typing import Dict, List, Tuple

#: Module version.
DEF_EXTRA_01_VERSION = "def-extra-01.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.def-extra-01.v1"


class BehavioralError(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class BehaviorProfile:
    """Enrolled baseline for one principal."""

    principal: str
    mean_ms: float
    stdev_ms: float
    samples: int


class BehaviorStore:
    """Enroll and verify behavioral timing profiles."""

    def __init__(self, *, max_z: float = 3.0, min_samples: int = 5) -> None:
        if max_z <= 0:
            raise BehavioralError("max_z must be positive")
        if min_samples < 2:
            raise BehavioralError("min_samples must be >= 2")
        self._max_z = max_z
        self._min_samples = min_samples
        self._profiles: Dict[str, BehaviorProfile] = {}

    def enroll(self, principal: str, samples_ms: List[float]) -> BehaviorProfile:
        """Enroll a baseline.  Raises if too few samples."""
        if not principal:
            raise BehavioralError("principal required")
        if len(samples_ms) < self._min_samples:
            raise BehavioralError(
                f"need >= {self._min_samples} samples, got {len(samples_ms)}"
            )
        mean = statistics.fmean(samples_ms)
        stdev = statistics.pstdev(samples_ms) or 1e-6
        profile = BehaviorProfile(principal, mean, stdev, len(samples_ms))
        self._profiles[principal] = profile
        return profile

    def verify(
        self, principal: str, samples_ms: List[float]
    ) -> Tuple[bool, float]:
        """Verify samples against the enrolled baseline.

        Returns (ok, anomaly_score in 0..1).  Unknown principal or
        empty samples -> (False, 1.0) fail-closed.
        """
        profile = self._profiles.get(principal)
        if profile is None or not samples_ms:
            return False, 1.0
        zs = [abs((s - profile.mean_ms) / profile.stdev_ms) for s in samples_ms]
        avg_z = sum(zs) / len(zs)
        ok = avg_z <= self._max_z
        score = min(avg_z / (2.0 * self._max_z), 1.0)
        return ok, score


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "dataclasses", "pathlib", "statistics", "typing"}
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
    store = BehaviorStore(max_z=3.0, min_samples=5)
    baseline = [95.0, 102.0, 98.0, 105.0, 99.0, 101.0]
    store.enroll("alice", baseline)
    ok, score = store.verify("alice", [100.0, 97.0, 103.0])
    assert ok is True and score < 0.5
    ok, score = store.verify("alice", [900.0, 1200.0, 800.0])
    assert ok is False and score > 0.5
    # Unknown principal fails closed.
    ok, score = store.verify("mallory", [100.0])
    assert ok is False and score == 1.0
    assert stdlib_only()
    print("def-extra-01 OK: enroll, verify, fail-closed")


if __name__ == "__main__":
    main()
