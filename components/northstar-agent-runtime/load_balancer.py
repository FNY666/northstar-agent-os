"""Load balancer: deterministic backend selection across selection algorithms.

Research note: a *load balancer* distributes work across backends to improve
utilization and fault tolerance. Classic *static* policies pick by order or
weight (round-robin originates in early time-sharing schedulers; the
*smooth weighted* variant used by nginx avoids the burst that naive
weighted RR produces). *Dynamic* policies use host-reported state:
*least-connections* routes to the backend with fewest in-flight requests
(the default for many L7 balancers), and *least-load* routes on a
host-reported cost metric (latency, CPU, queue depth).

* **Algorithms** — ``round-robin`` (cycles healthy backends in registration
  order), ``weighted-round-robin`` (nginx-style smooth WRR: each round every
  backend's current weight grows by its configured weight, the maximum is
  picked and pays down the total — producing a smooth ``a b a c a``
  pattern for weights 3:1:1 instead of an ``a a a b c`` burst),
  ``least-connections`` (fewest active connections, tracked via
  ``acquire``/``release``), ``least-load`` (lowest host-reported load).
  All ties break by registration order — identical input sequences always
  produce identical pick sequences (audit-replay exact).
* **Fail-closed selection** — :meth:`LoadBalancer.select` with no backends,
  or all backends marked unhealthy, raises :class:`NoHealthyBackendError`
  rather than returning ``None``: a silent null would be dereferenced or
  swallowed downstream, hiding an outage as a bug.
* **Health is explicit** — :meth:`LoadBalancer.health` marks a backend
  healthy/unhealthy; unhealthy backends are excluded from selection but
  retain their accounting (their connections/load are not forgotten — the
  next ``select`` after re-marking healthy sees real state).
* **Connection accounting** — :meth:`acquire` increments a backend's
  in-flight count, :meth:`release` decrements it; releasing more than held
  raises :class:`LoadBalancerError` (a leak would otherwise hide under a
  clamped zero and starve the backend from least-connections picks).
* **Load is host-reported** — :meth:`report_load` pins a caller-supplied
  finite non-negative float; the module never observes the backend itself.

Honest scope: this is the *selection* half of a balancer, not a transport —
it cannot open connections, cannot verify a backend is truly healthy (a host
that marks a dead backend healthy gets a consistent pattern of bad picks),
and ``least-load`` routes on *claimed* numbers (GIGO). A selected backend is
"this policy chose this id at this seq", never "this backend answered". For
production use, pair selection with an independent health prober and a
timeout manager.

Version pin: load-balancer.v1
Schema pin: northstar.load-balancer.v1
"""

from __future__ import annotations

import hashlib
import math
import threading
from dataclasses import dataclass
from typing import Any

#: Module version.
LOAD_BALANCER_VERSION = "load-balancer.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.load-balancer.v1"

#: Supported selection algorithms.
ALGORITHMS = (
    "round-robin",
    "weighted-round-robin",
    "least-connections",
    "least-load",
)


class LoadBalancerError(Exception):
    """Malformed use of the load balancer (programming error)."""


class NoHealthyBackendError(LoadBalancerError):
    """Selection attempted with no healthy backend available."""


class UnknownBackendError(LoadBalancerError):
    """Operation on a backend id that is not registered."""


def _check_str(value: Any, name: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise LoadBalancerError(f"{name} must be a str, got {type(value).__name__}")
    if not value:
        raise LoadBalancerError(f"{name} must be non-empty")
    return value


def _check_seq(value: Any, name: str = "seq") -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise LoadBalancerError(f"{name} must be an int, got {type(value).__name__}")
    if value < 0:
        raise LoadBalancerError(f"{name} must be non-negative, got {value}")
    return value


def _check_weight(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise LoadBalancerError(f"weight must be an int, got {type(value).__name__}")
    if value <= 0:
        raise LoadBalancerError(f"weight must be positive, got {value}")
    return value


def _check_load(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise LoadBalancerError(f"load must be a number, got {type(value).__name__}")
    value = float(value)
    if not math.isfinite(value):
        raise LoadBalancerError(f"load must be finite, got {value}")
    if value < 0.0:
        raise LoadBalancerError(f"load must be non-negative, got {value}")
    return value


def _digest(backend_id: str, algorithm: str, seq: int) -> str:
    body = f"{backend_id}\x1f{algorithm}\x1f{seq}".encode("utf-8")
    return "sha256:" + hashlib.sha256(body).hexdigest()


@dataclass(frozen=True)
class Backend:
    """One registered backend (frozen record)."""

    version: str
    backend_id: str
    weight: int
    healthy: bool
    active_connections: int
    load: float

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "version": self.version,
            "backend_id": self.backend_id,
            "weight": self.weight,
            "healthy": self.healthy,
            "active_connections": self.active_connections,
            "load": self.load,
        }


@dataclass(frozen=True)
class SelectRecord:
    """One selection decision (frozen record)."""

    version: str
    algorithm: str
    backend_id: str
    seq: int
    digest: str

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "version": self.version,
            "algorithm": self.algorithm,
            "backend_id": self.backend_id,
            "seq": self.seq,
            "digest": self.digest,
        }


class LoadBalancer:
    """Deterministic backend selector over explicit health/connection state.

    Backends are owned by registration order; all selection state advances on
    caller-supplied int seqs (no wall-clock).
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        # backend_id -> dict(weight, healthy, conns, load)
        self._backends: dict[str, dict] = {}
        self._order: list[str] = []  # registration order
        self._rr_index = 0  # round-robin cursor
        self._current_weight: dict[str, int] = {}  # smooth WRR state

    def add_backend(self, backend_id: str, seq: int, weight: int = 1) -> Backend:
        """Register a backend (healthy, zero connections, zero load)."""
        backend_id = _check_str(backend_id, "backend_id")
        seq = _check_seq(seq)
        weight = _check_weight(weight)
        with self._lock:
            if backend_id in self._backends:
                raise LoadBalancerError(f"backend already registered: {backend_id}")
            self._backends[backend_id] = {
                "weight": weight,
                "healthy": True,
                "conns": 0,
                "load": 0.0,
            }
            self._order.append(backend_id)
            self._current_weight[backend_id] = 0
            return self._record(backend_id)

    def backend(self, backend_id: str, seq: int, weight: int = 1) -> Backend:
        """Spec alias: register a backend (delegates to :meth:`add_backend`).

        Simulates the "add upstream" half of an HAProxy/Envoy backend pool:
        the backend enters the pool healthy, with zero connections and zero
        load, until :meth:`health` says otherwise.
        """
        return self.add_backend(backend_id, seq, weight=weight)

    def remove_backend(self, backend_id: str, seq: int) -> None:
        """Deregister a backend (drops its accounting state)."""
        backend_id = _check_str(backend_id, "backend_id")
        _check_seq(seq)
        with self._lock:
            if backend_id not in self._backends:
                raise UnknownBackendError(f"unknown backend: {backend_id}")
            del self._backends[backend_id]
            self._order.remove(backend_id)
            del self._current_weight[backend_id]

    def health(self, backend_id: str, healthy: bool, seq: int) -> Backend:
        """Mark a backend healthy/unhealthy; unhealthy skips selection."""
        backend_id = _check_str(backend_id, "backend_id")
        _check_seq(seq)
        if not isinstance(healthy, bool):
            raise LoadBalancerError("healthy must be a bool")
        with self._lock:
            state = self._backends.get(backend_id)
            if state is None:
                raise UnknownBackendError(f"unknown backend: {backend_id}")
            state["healthy"] = healthy
            return self._record(backend_id)

    def acquire(self, backend_id: str, seq: int) -> Backend:
        """Check out one connection on a healthy backend."""
        backend_id = _check_str(backend_id, "backend_id")
        _check_seq(seq)
        with self._lock:
            state = self._backends.get(backend_id)
            if state is None:
                raise UnknownBackendError(f"unknown backend: {backend_id}")
            if not state["healthy"]:
                raise LoadBalancerError(f"cannot acquire on unhealthy backend: {backend_id}")
            state["conns"] += 1
            return self._record(backend_id)

    def release(self, backend_id: str, seq: int) -> Backend:
        """Return one connection; over-release is a programming error."""
        backend_id = _check_str(backend_id, "backend_id")
        _check_seq(seq)
        with self._lock:
            state = self._backends.get(backend_id)
            if state is None:
                raise UnknownBackendError(f"unknown backend: {backend_id}")
            if state["conns"] <= 0:
                raise LoadBalancerError(f"release without acquire: {backend_id}")
            state["conns"] -= 1
            return self._record(backend_id)

    def report_load(self, backend_id: str, load: float, seq: int) -> Backend:
        """Pin a host-reported load value for least-load selection."""
        backend_id = _check_str(backend_id, "backend_id")
        load = _check_load(load)
        _check_seq(seq)
        with self._lock:
            state = self._backends.get(backend_id)
            if state is None:
                raise UnknownBackendError(f"unknown backend: {backend_id}")
            state["load"] = load
            return self._record(backend_id)

    def select(self, algorithm: str, seq: int) -> SelectRecord:
        """Pick one backend by algorithm; fails closed when none are healthy."""
        if isinstance(algorithm, bool) or algorithm not in ALGORITHMS:
            raise LoadBalancerError(f"unknown algorithm: {algorithm!r}")
        seq = _check_seq(seq)
        with self._lock:
            healthy = [bid for bid in self._order if self._backends[bid]["healthy"]]
            if not healthy:
                raise NoHealthyBackendError(
                    "select with no healthy backends available"
                )
            if algorithm == "round-robin":
                backend_id = healthy[self._rr_index % len(healthy)]
                self._rr_index += 1
            elif algorithm == "weighted-round-robin":
                backend_id = self._smooth_wrr(healthy)
            elif algorithm == "least-connections":
                backend_id = min(
                    healthy,
                    key=lambda bid: (self._backends[bid]["conns"], self._order.index(bid)),
                )
            else:  # least-load
                backend_id = min(
                    healthy,
                    key=lambda bid: (self._backends[bid]["load"], self._order.index(bid)),
                )
            return SelectRecord(
                version=LOAD_BALANCER_VERSION,
                algorithm=algorithm,
                backend_id=backend_id,
                seq=seq,
                digest=_digest(backend_id, algorithm, seq),
            )

    def route(self, algorithm: str, seq: int) -> SelectRecord:
        """Spec alias: pick one backend for a request (delegates to :meth:`select`).

        Simulates the HAProxy/Envoy routing decision: returns the frozen
        :class:`SelectRecord` the policy chose at ``seq``. Fails closed
        with :class:`NoHealthyBackendError` when no healthy backend exists.
        """
        return self.select(algorithm, seq)

    def _smooth_wrr(self, healthy: list[str]) -> str:
        """Nginx-style smooth weighted round robin (deterministic)."""
        total = 0
        best: str | None = None
        best_cw = None
        for bid in self._order:
            if bid not in self._backends or not self._backends[bid]["healthy"]:
                continue
            w = self._backends[bid]["weight"]
            total += w
            cw = self._current_weight[bid] + w
            self._current_weight[bid] = cw
            if best is None or cw > best_cw:
                best = bid
                best_cw = cw
        assert best is not None
        self._current_weight[best] -= total
        return best

    def _record(self, backend_id: str) -> Backend:
        state = self._backends[backend_id]
        return Backend(
            version=LOAD_BALANCER_VERSION,
            backend_id=backend_id,
            weight=state["weight"],
            healthy=state["healthy"],
            active_connections=state["conns"],
            load=state["load"],
        )

    def get(self, backend_id: str) -> Backend:
        """Frozen view of a backend; unknown id raises."""
        backend_id = _check_str(backend_id, "backend_id")
        with self._lock:
            if backend_id not in self._backends:
                raise UnknownBackendError(f"unknown backend: {backend_id}")
            return self._record(backend_id)

    def backend_ids(self) -> tuple:
        """Registered backend ids in registration order."""
        with self._lock:
            return tuple(self._order)


_AUDIT_KINDS = (
    "backend-added",
    "backend-removed",
    "health-changed",
    "connection-acquired",
    "connection-released",
    "load-reported",
    "selected",
)


def load_balancer_audit_event(kind: str, seq: int, **detail: Any) -> dict:
    """Wrap a load-balancer event as an audit event dict (audit.ndjson/1)."""
    if kind not in _AUDIT_KINDS:
        raise LoadBalancerError(f"unknown audit kind: {kind!r}")
    seq = _check_seq(seq)
    event = {
        "schema": "northstar.audit.ndjson/1",
        "module": LOAD_BALANCER_VERSION,
        "event": kind,
        "audit_seq": seq,
    }
    event.update(detail)
    return event


def main() -> None:
    """Self-check: registration, all four algorithms, fail-closed paths."""
    lb = LoadBalancer()
    assert lb.backend_ids() == ()

    lb.add_backend("a", 0, weight=3)
    lb.add_backend("b", 1, weight=1)
    lb.add_backend("c", 2, weight=1)
    assert lb.backend_ids() == ("a", "b", "c")

    # round-robin cycles registration order
    picks = [lb.select("round-robin", i).backend_id for i in range(6)]
    assert picks == ["a", "b", "c", "a", "b", "c"], picks

    # smooth weighted RR: 3:1:1 -> a b a c a over 5 picks
    lb2 = LoadBalancer()
    lb2.add_backend("a", 0, weight=3)
    lb2.add_backend("b", 1, weight=1)
    lb2.add_backend("c", 2, weight=1)
    picks = [lb2.select("weighted-round-robin", i).backend_id for i in range(5)]
    assert picks == ["a", "b", "a", "c", "a"], picks

    # least-connections
    lb.acquire("a", 0)
    lb.acquire("a", 1)
    assert lb.select("least-connections", 0).backend_id == "b"
    lb.release("a", 0)
    lb.release("a", 1)

    # least-load
    lb.report_load("a", 0.9, 0)
    lb.report_load("b", 0.1, 1)
    lb.report_load("c", 0.7, 2)
    assert lb.select("least-load", 0).backend_id == "b"

    # unhealthy backends are skipped
    lb.health("b", False, 0)
    assert lb.select("round-robin", 0).backend_id != "b"
    lb.health("b", True, 1)

    # fail-closed: unknown algorithm, empty balancer
    try:
        lb.select("magic", 0)
    except LoadBalancerError:
        pass
    else:
        raise AssertionError("unknown algorithm accepted")
    empty = LoadBalancer()
    try:
        empty.select("round-robin", 0)
    except NoHealthyBackendError:
        pass
    else:
        raise AssertionError("empty selection accepted")

    # digest determinism (two identical instances, same seq -> same pick+digest)
    lb_a = LoadBalancer()
    lb_a.add_backend("a", 0)
    lb_b = LoadBalancer()
    lb_b.add_backend("a", 0)
    r1 = lb_a.select("round-robin", 42)
    r2 = lb_b.select("round-robin", 42)
    assert r1.digest == r2.digest and r1.digest.startswith("sha256:")

    print("load-balancer OK: add, algorithms, health, acquire/release, fail-closed")


if __name__ == "__main__":
    main()
