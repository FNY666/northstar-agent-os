"""Phi accrual failure detection (Hayashibara et al. 2004) over caller-supplied time.

A ``PhiDetector`` watches heartbeats from remote nodes and produces a
*continuous* suspicion level -- ``phi`` -- instead of a binary up/down
verdict. ``phi(node_id, now_ms)`` answers "how surprised am I that this
node has been silent this long?", given the observed heartbeat rhythm:

* The detector keeps the last ``max_samples`` inter-arrival intervals per
  node (default 1000, per the paper's window).
* With mean and standard deviation from that window, phi is
  ``-log10(1 - CDF(t))`` under a normal model, where ``t`` is the time
  since the last heartbeat. A steady heartbeat keeps phi near 0; as the
  node goes silent past its usual rhythm, phi grows without bound.
* ``is_suspected(node_id, now_ms, threshold)`` trips when ``phi >=
  threshold`` (threshold 8.0 = one-in-100-million surprise, the paper's
  usual operating point).

House style: no wall-clock -- all timestamps are caller-supplied
monotonic milliseconds (ints). Frozen records, fail-closed validation,
stdlib-only, deterministic, version/schema pins, ``main()`` self-check.

Honest scope: suspicion is *statistical*, not proof of failure -- a node
behind a slow link is suspected even if it is alive; a node that dies
exactly on schedule is not suspected until the silence outlasts its
rhythm. The detector can only see heartbeats the host reports. A quiet
detector means "no node is anomalously silent", never "every node is
alive".

Version pin: phi-accrual-detector.v1
Schema pin: northstar.phi-accrual-detector.v1
"""

from __future__ import annotations

import math
from collections import deque
from dataclasses import dataclass, field
from typing import Optional

#: Module version.
PHI_DETECTOR_VERSION = "phi-accrual-detector.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.phi-accrual-detector.v1"

#: Maximum phi reported before capping (avoids propagating float("inf")
#: into JSON-shaped audit records).
MAX_PHI = 1_000.0

#: Smallest representable tail probability: below this, 1 - CDF(t) is
#: pinned so -log10 stays finite.
_MIN_TAIL = 1e-300

#: Phi of a node that has never sent a heartbeat: maximal suspicion,
#: fail-closed (unknown is not assumed alive).
PHI_UNKNOWN_NODE = MAX_PHI


def _require_ms(name: str, value) -> None:
    """Validate a caller-supplied millisecond timestamp."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int (ms), got {type(value).__name__}")
    if value < 0:
        raise ValueError(f"{name} must be non-negative")


def _require_positive_int(name: str, value) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int, got {type(value).__name__}")
    if value <= 0:
        raise ValueError(f"{name} must be positive")


def _normal_cdf(t: float, mean: float, stddev: float) -> float:
    """CDF of N(mean, stddev) at t, via the error function."""
    return 0.5 * (1.0 + math.erf((t - mean) / (stddev * math.sqrt(2.0))))


def _accrue(t: float, mean: float, stddev: float) -> float:
    """Phi = -log10(1 - CDF(t)); the suspicion level for silence t."""
    if t <= 0.0:
        return 0.0
    if stddev <= 0.0:
        # Zero variance: the rhythm is exact. Any overshoot is maximally
        # surprising; on-time or early is not surprising at all.
        return 0.0 if t <= mean else MAX_PHI
    tail = 1.0 - _normal_cdf(t, mean, stddev)
    if tail <= 0.0:
        return MAX_PHI
    if tail < _MIN_TAIL:
        tail = _MIN_TAIL
    return min(MAX_PHI, -math.log10(tail))


@dataclass(frozen=True)
class PhiReport:
    """One suspicion assessment (frozen record)."""

    node_id: str
    phi: float
    samples: int
    mean_interval_ms: float
    stddev_interval_ms: float
    silence_ms: int

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "node_id": self.node_id,
            "phi": self.phi,
            "samples": self.samples,
            "mean_interval_ms": self.mean_interval_ms,
            "stddev_interval_ms": self.stddev_interval_ms,
            "silence_ms": self.silence_ms,
        }


@dataclass
class _NodeState:
    """Mutable per-node heartbeat state (internal)."""

    last_ms: int = 0
    seen: bool = False
    intervals: deque = field(default_factory=deque)


class PhiDetector:
    """Phi accrual failure detector over caller-supplied timestamps."""

    def __init__(self, max_samples: int = 1000, min_samples: int = 2):
        _require_positive_int("max_samples", max_samples)
        _require_positive_int("min_samples", min_samples)
        if min_samples > max_samples:
            raise ValueError("min_samples must be <= max_samples")
        self._max_samples = max_samples
        self._min_samples = min_samples
        self._nodes: dict[str, _NodeState] = {}
        self._order: list[str] = []

    # -- ingestion --------------------------------------------------------

    def heartbeat(self, node_id: str, now_ms: int) -> None:
        """Record a heartbeat from ``node_id`` at ``now_ms``.

        The interval since the previous heartbeat joins the sample
        window; the window keeps the most recent ``max_samples``.
        Heartbeats are monotonic per node: an older timestamp is a
        programming error and raises ``TypeError`` fail-closed.
        """
        if not isinstance(node_id, str) or not node_id:
            raise TypeError("node_id must be a non-empty str")
        _require_ms("now_ms", now_ms)
        state = self._nodes.get(node_id)
        if state is None:
            state = _NodeState()
            self._nodes[node_id] = state
            self._order.append(node_id)
        if state.seen and now_ms < state.last_ms:
            raise TypeError(
                f"now_ms {now_ms} is before last heartbeat {state.last_ms}: "
                "time must not flow backwards"
            )
        if state.seen and now_ms > state.last_ms:
            state.intervals.append(now_ms - state.last_ms)
            while len(state.intervals) > self._max_samples:
                state.intervals.popleft()
        state.last_ms = now_ms
        state.seen = True

    # -- assessment -------------------------------------------------------

    def _stats(self, node_id: str) -> tuple[int, float, float]:
        state = self._nodes.get(node_id)
        if state is None or not state.seen:
            return (0, 0.0, 0.0)
        n = len(state.intervals)
        if n == 0:
            return (0, 0.0, 0.0)
        mean = sum(state.intervals) / n
        var = sum((x - mean) ** 2 for x in state.intervals) / n
        return (n, mean, math.sqrt(var))

    def report(self, node_id: str, now_ms: int) -> PhiReport:
        """Full suspicion report for ``node_id`` at ``now_ms``."""
        if not isinstance(node_id, str) or not node_id:
            raise TypeError("node_id must be a non-empty str")
        _require_ms("now_ms", now_ms)
        state = self._nodes.get(node_id)
        if state is None or not state.seen:
            return PhiReport(
                node_id=node_id,
                phi=PHI_UNKNOWN_NODE,
                samples=0,
                mean_interval_ms=0.0,
                stddev_interval_ms=0.0,
                silence_ms=0,
            )
        if now_ms < state.last_ms:
            raise TypeError(
                f"now_ms {now_ms} is before last heartbeat {state.last_ms}: "
                "time must not flow backwards"
            )
        n, mean, stddev = self._stats(node_id)
        silence = now_ms - state.last_ms
        if n < self._min_samples:
            # Too little rhythm history to model: the node just spoke, so
            # no suspicion yet -- but record the data gap honestly.
            return PhiReport(
                node_id=node_id,
                phi=0.0,
                samples=n,
                mean_interval_ms=mean,
                stddev_interval_ms=stddev,
                silence_ms=silence,
            )
        return PhiReport(
            node_id=node_id,
            phi=_accrue(float(silence), mean, stddev),
            samples=n,
            mean_interval_ms=mean,
            stddev_interval_ms=stddev,
            silence_ms=silence,
        )

    def phi(self, node_id: str, now_ms: int) -> float:
        """Suspicion level for ``node_id`` at ``now_ms`` (>= 0.0)."""
        return self.report(node_id, now_ms).phi

    def is_suspected(
        self, node_id: str, now_ms: int, threshold: float = 8.0
    ) -> bool:
        """True when phi reaches the suspicion ``threshold``."""
        if isinstance(threshold, bool) or not isinstance(
            threshold, (int, float)
        ):
            raise TypeError("threshold must be a number")
        threshold = float(threshold)
        if math.isnan(threshold) or threshold < 0.0:
            raise ValueError("threshold must be a non-negative number")
        return self.phi(node_id, now_ms) >= threshold

    # -- bookkeeping ------------------------------------------------------

    def last_heartbeat(self, node_id: str) -> Optional[int]:
        """Last recorded heartbeat ms, or None if never seen."""
        if not isinstance(node_id, str) or not node_id:
            raise TypeError("node_id must be a non-empty str")
        state = self._nodes.get(node_id)
        return state.last_ms if state and state.seen else None

    def nodes(self) -> tuple[str, ...]:
        """Node ids in first-seen order."""
        return tuple(self._order)

    def reset(self, node_id: str) -> None:
        """Forget all state for ``node_id`` (host-initiated)."""
        if not isinstance(node_id, str) or not node_id:
            raise TypeError("node_id must be a non-empty str")
        if node_id in self._nodes:
            del self._nodes[node_id]
        if node_id in self._order:
            self._order.remove(node_id)

    def clear(self) -> None:
        """Forget all nodes (host-initiated)."""
        self._nodes.clear()
        self._order.clear()


def phi_audit_event(
    report: PhiReport, seq: int, suspected: bool
) -> dict:
    """Audit-shaped record for one phi assessment."""
    if not isinstance(report, PhiReport):
        raise TypeError("report must be a PhiReport")
    if not isinstance(suspected, bool):
        raise TypeError("suspected must be a bool")
    _require_ms("seq", seq)
    event = report.as_dict()
    event["audit_seq"] = seq
    event["suspected"] = suspected
    return event


def main() -> None:
    det = PhiDetector()
    # Steady 100ms rhythm.
    for i in range(10):
        det.heartbeat("n1", i * 100)
    assert det.phi("n1", 950) < 1.0, "steady node should not be suspected"
    assert det.is_suspected("n1", 5_000, threshold=2.0), (
        "long silence should accrue suspicion"
    )
    assert det.phi("never-seen", 1_000) == PHI_UNKNOWN_NODE
    print("phi-accrual-detector OK: steady quiet, silence suspected")


if __name__ == "__main__":
    main()
