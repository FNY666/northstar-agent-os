"""Failure detector: phi-accrual (Hayashibara et al. 2004) bookkeeping.

Research motivation: a fleet of agent hosts needs a principled way to
answer "is this peer still alive?" without hard timeouts. The phi-accrual
failure detector fits a normal distribution to the heartbeat inter-arrival
history and computes ``phi = -log10(P(inter-arrival > t_now))`` -- the
longer a peer stays silent relative to its own history, the higher the
phi. A threshold (classically 8.0) turns phi into a suspicion verdict.
Unlike a fixed timeout, the detector adapts to each peer's heartbeat
cadence and to jitter.

This module pins the mechanical, network-free half:

- ``FailureDetector`` -- per-peer heartbeat ledger: ``heartbeat()``
  books an arrival and its inter-arrival delta, ``phi()`` is a pure
  read view returning the current accrual value, ``suspect()`` books
  the threshold verdict as *data*.
- Inter-arrival times are expressed in caller-supplied logical seq
  units (no wall-clock): this is the ledger's honest bookkeeping of
  *declared* arrivals, exactly like the gossip membership plane's
  ``join``/``suspect``/``alive`` records. The host owns the mapping
  from logical seqs to real time.
- Heartbeats auto-register unknown node ids (ephemeral-node semantics,
  same as the leader_election facade); reads for unknown ids refuse
  fail-closed.
- ``phi()`` is computed over a sliding window of the most recent
  inter-arrival deltas; with fewer than ``min_samples`` samples the
  detector cannot accuse -- phi is 0.0.

Public API:

- ``FailureDetector(threshold=8.0, window_size=1000, min_samples=2)``
  -- ``heartbeat(node_id, seq)`` -> ``HeartbeatRecord``,
  ``phi(node_id, seq)`` -> ``float`` (pure read),
  ``suspect(node_id, seq)`` -> ``SuspicionRecord``,
  ``nodes()``, ``last_arrival(node_id)``, ``sample_count(node_id)``,
  ``stats(seq)`` (pure read), ``audit_log()``.
- ``failure_detector_audit_event(...)`` -- ``audit.ndjson/1``-shaped
  record (``heartbeat`` / ``suspect`` / ``rejected``).

Honest scope:

- phi is computed from *host-reported* arrivals; a phi of 0.0 means
  "no evidence of staleness in the booked history", never "the peer
  is provably alive".
- A ``suspected=True`` verdict is a threshold crossing of the booked
  model, not proof of a crash -- exactly the suspicion/commit split
  in the SWIM membership plane.
- Deterministic constant-interval heartbeats have zero variance;
  a constant cadence that breaks is treated as definitive evidence
  (phi jumps to the cap), because the model has seen zero jitter.
"""

from __future__ import annotations

import hashlib
import json
import math
import threading
from collections import deque
from dataclasses import dataclass
from typing import Deque, Dict, List, Mapping, Optional, Tuple

#: Module version pin.
FAILURE_DETECTOR_VERSION = "failure-detector.v1"

#: Schema pin carried by records and audit events.
FAILURE_DETECTOR_SCHEMA = "northstar.failure-detector.v1"

#: Audit event kinds.
EVENT_HEARTBEAT = "heartbeat"
EVENT_SUSPECT = "suspect"
EVENT_REJECTED = "rejected"

#: Classic Hayashibara threshold; configurable per instance.
DEFAULT_THRESHOLD = 8.0

#: Default sliding window of inter-arrival samples.
DEFAULT_WINDOW_SIZE = 1000

#: Minimum samples before the model can accuse.
DEFAULT_MIN_SAMPLES = 2

#: Cap on the reported phi value (avoids log10(0) and unbounded floats).
MAX_PHI = 30.0


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonicalize(value: object) -> bytes:
    """Deterministic canonical JSON encoding (stdlib-only)."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _check_str(value: object, name: str) -> str:
    if not isinstance(value, str) or isinstance(value, bool):
        raise TypeError(f"{name} must be a str, got {type(value).__name__}")
    if not value:
        raise ValueError(f"{name} must be non-empty")
    if len(value) > 256:
        raise ValueError(f"{name} must be at most 256 chars")
    return value


def _check_seq(value: object, name: str = "seq") -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{name} must be an int, got {type(value).__name__}")
    if value < 0:
        raise ValueError(f"{name} must be non-negative")
    return value


def _pin(domain: str, parts: Mapping[str, object]) -> str:
    body = _canonicalize({"domain": domain, "parts": parts})
    return "sha256:" + _sha256_hex(body)


# ---------------------------------------------------------------------------
# Fail-closed taxonomy
# ---------------------------------------------------------------------------


class FailureDetectorError(Exception):
    """Base class for all failure-detector errors."""


class BadNodeError(FailureDetectorError):
    """Node id failed validation."""


class UnknownNodeError(FailureDetectorError):
    """No heartbeat has ever been booked for this node id."""


class BadThresholdError(FailureDetectorError):
    """Threshold is not a finite positive number."""


class BadWindowError(FailureDetectorError):
    """Window size / min_samples is not a positive int."""


class SeqOrderError(FailureDetectorError):
    """Caller seq is not strictly increasing."""


class AuditKindError(FailureDetectorError):
    """Unknown audit event kind."""


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HeartbeatRecord:
    """One booked heartbeat arrival."""

    node_id: str
    seq: int
    inter_arrival: Optional[int]  # None for the first heartbeat of a node
    digest: str

    def verify(self) -> bool:
        return self.digest == _pin(
            "failure-detector.heartbeat",
            {
                "node_id": self.node_id,
                "seq": self.seq,
                "inter_arrival": self.inter_arrival,
            },
        )


@dataclass(frozen=True)
class SuspicionRecord:
    """One booked suspicion verdict (verdict is data, never raised)."""

    node_id: str
    seq: int
    phi: float
    suspected: bool
    digest: str

    def verify(self) -> bool:
        return self.digest == _pin(
            "failure-detector.suspect",
            {
                "node_id": self.node_id,
                "seq": self.seq,
                "phi": self.phi,
                "suspected": self.suspected,
            },
        )


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------


def failure_detector_audit_event(
    kind: str,
    *,
    node_id: str,
    seq: int,
    detail: Optional[Mapping] = None,
) -> dict:
    """``audit.ndjson/1``-shaped record for a failure-detector event."""
    if kind not in (EVENT_HEARTBEAT, EVENT_SUSPECT, EVENT_REJECTED):
        raise AuditKindError(f"unknown failure-detector event kind: {kind}")
    _check_str(node_id, "node_id")
    _check_seq(seq, "seq")
    if detail is not None:
        if not isinstance(detail, Mapping):
            raise TypeError("detail must be a mapping")
        _canonicalize(detail)  # fail fast on non-canonical values
    return {
        "audit": "audit.ndjson/1",
        "schema": FAILURE_DETECTOR_SCHEMA,
        "version": FAILURE_DETECTOR_VERSION,
        "kind": kind,
        "node_id": node_id,
        "audit_seq": seq,
        "detail": dict(detail) if detail is not None else {},
    }


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------


class _NodeState:
    __slots__ = ("last_arrival", "samples")

    def __init__(self, last_arrival: int, window: int):
        self.last_arrival = last_arrival
        self.samples: Deque[int] = deque(maxlen=window)


class FailureDetector:
    """Phi-accrual failure detector over logical heartbeat seqs.

    Caller-supplied int seqs are the time base: every mutating call must
    carry a strictly increasing seq (batch discipline). ``phi()``,
    ``nodes()``, ``last_arrival()``, ``sample_count()`` and ``stats()``
    are pure read views -- the seq is validated but never consumed.
    """

    def __init__(
        self,
        threshold: float = DEFAULT_THRESHOLD,
        window_size: int = DEFAULT_WINDOW_SIZE,
        min_samples: int = DEFAULT_MIN_SAMPLES,
    ):
        if (
            not isinstance(threshold, (int, float))
            or isinstance(threshold, bool)
            or not math.isfinite(threshold)
            or threshold <= 0
        ):
            raise BadThresholdError("threshold must be a finite positive number")
        if not isinstance(window_size, int) or isinstance(window_size, bool):
            raise BadWindowError("window_size must be an int")
        if window_size < 1:
            raise BadWindowError("window_size must be positive")
        if not isinstance(min_samples, int) or isinstance(min_samples, bool):
            raise BadWindowError("min_samples must be an int")
        if min_samples < 1:
            raise BadWindowError("min_samples must be positive")
        self._threshold = float(threshold)
        self._window_size = window_size
        self._min_samples = min_samples
        self._lock = threading.RLock()
        self._last_seq = -1
        self._nodes: Dict[str, _NodeState] = {}
        self._audit: List[dict] = []

    # -- internals ------------------------------------------------------

    def _claim(self, seq: int) -> int:
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must be strictly increasing (got {seq}, last {self._last_seq})"
            )
        self._last_seq = seq
        return seq

    def _peek_seq(self, seq: int) -> int:
        return _check_seq(seq)  # validated, never consumed

    def _emit(self, kind: str, node_id: str, seq: int, detail: Optional[Mapping]) -> None:
        self._audit.append(
            failure_detector_audit_event(kind, node_id=node_id, seq=seq, detail=detail)
        )

    def _reject(self, node_id: str, seq: int, reason: str) -> None:
        self._emit(EVENT_REJECTED, node_id, seq, {"reason": reason})

    def _state(self, node_id: str) -> _NodeState:
        try:
            return self._nodes[node_id]
        except KeyError:
            raise UnknownNodeError(f"unknown node: {node_id!r}")

    @staticmethod
    def _accrual(t: int, samples: Tuple[int, ...], min_samples: int) -> float:
        """Phi for staleness ``t`` given the inter-arrival history."""
        n = len(samples)
        if t <= 0 or n < min_samples:
            return 0.0
        mean = sum(samples) / n
        var = sum((s - mean) ** 2 for s in samples) / n
        if var <= 0.0:
            # Constant cadence: any break in it is definitive evidence.
            return MAX_PHI if t > mean else 0.0
        std = math.sqrt(var)
        x = (t - mean) / std
        cdf = 0.5 * (1.0 + math.erf(x / math.sqrt(2.0)))
        p = 1.0 - cdf
        if p <= 0.0:
            return MAX_PHI
        phi = -math.log10(p)
        return min(phi, MAX_PHI)

    # -- mutating API ----------------------------------------------------

    def heartbeat(self, node_id: str, seq: int) -> HeartbeatRecord:
        """Book a heartbeat arrival for ``node_id`` (auto-registers)."""
        with self._lock:
            seq = _check_seq(seq)
            if seq <= self._last_seq:
                raise SeqOrderError(
                    f"seq must be strictly increasing (got {seq}, last {self._last_seq})"
                )
            try:
                node_id = _check_str(node_id, "node_id")
            except (TypeError, ValueError) as exc:
                self._last_seq = seq
                self._reject("<bad-node>", seq, str(exc))
                raise BadNodeError(str(exc)) from exc
            self._last_seq = seq
            state = self._nodes.get(node_id)
            if state is None:
                state = _NodeState(seq, self._window_size)
                self._nodes[node_id] = state
                inter_arrival: Optional[int] = None
            else:
                inter_arrival = seq - state.last_arrival
                state.samples.append(inter_arrival)
                state.last_arrival = seq
            record = HeartbeatRecord(
                node_id=node_id,
                seq=seq,
                inter_arrival=inter_arrival,
                digest=_pin(
                    "failure-detector.heartbeat",
                    {
                        "node_id": node_id,
                        "seq": seq,
                        "inter_arrival": inter_arrival,
                    },
                ),
            )
            self._emit(
                EVENT_HEARTBEAT,
                node_id,
                seq,
                {"inter_arrival": inter_arrival},
            )
            return record

    def suspect(self, node_id: str, seq: int) -> SuspicionRecord:
        """Book the threshold verdict for ``node_id``; verdict is data."""
        with self._lock:
            seq = _check_seq(seq)
            if seq <= self._last_seq:
                raise SeqOrderError(
                    f"seq must be strictly increasing (got {seq}, last {self._last_seq})"
                )
            try:
                node_id = _check_str(node_id, "node_id")
                state = self._state(node_id)
            except (FailureDetectorError, TypeError, ValueError) as exc:
                self._last_seq = seq
                name = node_id if isinstance(node_id, str) else "<bad-node>"
                self._reject(name, seq, str(exc))
                raise
            self._last_seq = seq
            value = self._accrual(
                seq - state.last_arrival, tuple(state.samples), self._min_samples
            )
            suspected = value >= self._threshold
            record = SuspicionRecord(
                node_id=node_id,
                seq=seq,
                phi=value,
                suspected=suspected,
                digest=_pin(
                    "failure-detector.suspect",
                    {
                        "node_id": node_id,
                        "seq": seq,
                        "phi": value,
                        "suspected": suspected,
                    },
                ),
            )
            self._emit(
                EVENT_SUSPECT,
                node_id,
                seq,
                {"phi": value, "suspected": suspected},
            )
            return record

    # -- pure read views (seq validated, never consumed) ------------------

    def phi(self, node_id: str, seq: int) -> float:
        """Current accrual value for ``node_id`` (pure read)."""
        with self._lock:
            self._peek_seq(seq)
            node_id = _check_str(node_id, "node_id")
            state = self._state(node_id)
            return self._accrual(
                seq - state.last_arrival, tuple(state.samples), self._min_samples
            )

    def nodes(self) -> Tuple[str, ...]:
        """Registered node ids, sorted."""
        with self._lock:
            return tuple(sorted(self._nodes))

    def last_arrival(self, node_id: str) -> int:
        """Last booked heartbeat seq for ``node_id``."""
        with self._lock:
            node_id = _check_str(node_id, "node_id")
            return self._state(node_id).last_arrival

    def sample_count(self, node_id: str) -> int:
        """Inter-arrival samples currently in the window for ``node_id``."""
        with self._lock:
            node_id = _check_str(node_id, "node_id")
            return len(self._state(node_id).samples)

    def stats(self, seq: int) -> dict:
        """Pure read view over the detector ledger."""
        with self._lock:
            self._peek_seq(seq)
            return {
                "nodes": len(self._nodes),
                "threshold": self._threshold,
                "window_size": self._window_size,
                "min_samples": self._min_samples,
                "audit_rows": len(self._audit),
                "ledger_seq": self._last_seq,
            }

    def audit_log(self) -> Tuple[dict, ...]:
        """Booked audit events, oldest first."""
        with self._lock:
            return tuple(self._audit)


def main() -> None:
    fd = FailureDetector()
    fd.heartbeat("n1", 1)
    for i in range(2, 12):
        fd.heartbeat("n1", i)
    fresh = fd.suspect("n1", 12)
    assert fresh.suspected is False, fresh
    stale = fd.suspect("n1", 10_000)
    assert stale.suspected is True and stale.phi >= DEFAULT_THRESHOLD, stale
    assert fresh.verify() and stale.verify()
    assert fd.phi("n1", 12) < fd.phi("n1", 10_000)
    print("failure-detector OK: heartbeat, phi, suspect")


if __name__ == "__main__":
    main()
