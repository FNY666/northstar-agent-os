"""Graph routing engine: A*/Dijkstra shortest paths as deterministic bookkeeping.

Research note: A* (Hart, Nilsson, Raphael, 1968) is Dijkstra's algorithm
with an admissible heuristic — it expands fewer nodes while returning the
same optimal path when ``h(v) <= true_cost(v, dst)`` for every node. Here
the graph is a *routing instrument* for the host's own placement
decisions (which mesh link to prefer, which agent hop order minimizes
traversal cost); the module moves no packets, opens no sockets, and
proves nothing about the real world the edge costs claim to model.

* **Deterministic** — adjacency is always relaxed in sorted node order,
  ties break on the lexicographically smaller path, and repeated queries
  on the same graph replay to identical routes and digest pins. No
  randomness, no wall-clock.
* **Optimality is conditional on admissibility** — when every node has
  coordinates and every directed edge costs at least the Euclidean
  distance between its endpoints, the module runs A* with the Euclidean
  heuristic (optimal and faster). If any edge violates that bound, or
  any node lacks coordinates, it falls back to Dijkstra (``h = 0``,
  always admissible, always optimal). Each route record pins which mode
  was used, so a consumer can audit the optimality claim.
* **Fail-closed** — routing an unknown node raises; an unreachable
  destination raises :class:`NoPathError` instead of returning a
  sentinel; negative/NaN/infinite costs and self-loops are refused at
  the edge boundary; duplicate nodes/edges raise.

Honest scope: ``route()`` proves "this path is the cheapest over the
*reported* graph", never "this path is best in the real network". Edge
costs are host-reported claims; a lying host gets a lying route. ETAs
are cost/speed arithmetic on the same claims, not measurements.
"""

from __future__ import annotations

import hashlib
import heapq
import json
import math
import threading
from dataclasses import dataclass
from fractions import Fraction
from typing import Any, Dict, List, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Module version.
ROUTING_ENGINE_VERSION = "routing-engine.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.routing-engine.v1"

#: Audit event schema pin.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Hash domain separator so route pins cannot collide with other digests.
_HASH_DOMAIN = b"northstar.routing-engine.v1\x00"

#: Hard cap on nodes in one engine (guardrail against memory blowup).
MAX_NODES = 100_000

#: Hard cap on edges in one engine (guardrail against memory blowup).
MAX_EDGES = 1_000_000


class RoutingError(Exception):
    """Base fail-closed routing error."""


class DuplicateNodeError(RoutingError):
    """Raised when adding a node id that is already registered."""


class DuplicateEdgeError(RoutingError):
    """Raised when adding a directed edge that already exists."""


class UnknownNodeError(RoutingError):
    """Raised when a node id is not registered."""


class UnknownEdgeError(RoutingError):
    """Raised when removing a directed edge that does not exist."""


class BadCostError(RoutingError):
    """Raised on negative, NaN, infinite, bool, or non-numeric edge costs."""


class SelfLoopError(RoutingError):
    """Raised when an edge starts and ends at the same node."""


class NoPathError(RoutingError):
    """Raised when no directed path exists from src to dst."""


class BadSpeedError(RoutingError):
    """Raised on non-positive, NaN, infinite, or non-numeric speeds."""


class SeqOrderError(RoutingError):
    """Raised when a mutation seq is not strictly increasing."""


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(_HASH_DOMAIN + data).hexdigest()


def _check_seq(seq: int, last: int) -> None:
    """Fail-closed strictly-increasing caller seqs (no wall-clock)."""
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise TypeError("seq must be an int")
    if seq <= last:
        raise SeqOrderError(f"seq {seq} is not strictly greater than {last}")


def _check_node_id(node_id: str) -> str:
    if not isinstance(node_id, str):
        raise TypeError("node_id must be a str")
    if not node_id:
        raise ValueError("node_id must be non-empty")
    return node_id


def _check_cost(cost: Any) -> Any:
    """Accept a non-negative finite int/float; bools and NaN/inf refused."""
    if isinstance(cost, bool) or not isinstance(cost, (int, float)):
        raise BadCostError(f"cost must be a non-negative int/float, got {cost!r}")
    if not math.isfinite(cost) or cost < 0:
        raise BadCostError(f"cost must be non-negative and finite, got {cost!r}")
    return cost


def _cost_tag(cost: Any) -> List[Any]:
    """Type-tagged cost encoding so int 2 and float 2.0 hash differently."""
    if isinstance(cost, int):
        return ["int", cost]
    return ["float", repr(cost)]


def _euclidean(a: Tuple[float, float], b: Tuple[float, float]) -> float:
    return math.hypot(a[0] - b[0], a[1] - b[1])


def _check_coords(coords: Any) -> Optional[Tuple[float, float]]:
    if coords is None:
        return None
    if (
        not isinstance(coords, (tuple, list))
        or len(coords) != 2
        or any(isinstance(c, bool) or not isinstance(c, (int, float)) for c in coords)
        or any(not math.isfinite(c) for c in coords)
    ):
        raise ValueError("coords must be None or a pair of finite numbers")
    return (float(coords[0]), float(coords[1]))


@dataclass(frozen=True)
class RouteRecord:
    """Frozen shortest-path result with its digest pin and heuristic mode."""

    route_id: str
    src: str
    dst: str
    path: Tuple[str, ...]
    total_cost: Any
    hops: int
    heuristic: str  # "astar" or "dijkstra"
    digest: str
    version: str = ROUTING_ENGINE_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "route_id": self.route_id,
            "src": self.src,
            "dst": self.dst,
            "path": list(self.path),
            "total_cost": self.total_cost,
            "hops": self.hops,
            "heuristic": self.heuristic,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class EtaEstimate:
    """Frozen ETA: exact rational duration = distance / speed."""

    src: str
    dst: str
    distance: Any
    speed: Any
    duration: Fraction
    route_digest: str
    version: str = ROUTING_ENGINE_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "src": self.src,
            "dst": self.dst,
            "distance": self.distance,
            "speed": self.speed,
            "duration": str(self.duration),
            "route_digest": self.route_digest,
            "version": self.version,
            "schema": self.schema,
        }


class RoutingEngine:
    """Deterministic directed weighted-graph router (A*/Dijkstra)."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        # node_id -> Optional[(x, y)]
        self._coords: Dict[str, Optional[Tuple[float, float]]] = {}
        # (u, v) -> cost
        self._edges: Dict[Tuple[str, str], Any] = {}
        # u -> sorted list of v (kept sorted for deterministic relaxation)
        self._adj: Dict[str, List[str]] = {}
        self._last_seq = -1
        self._route_counter = 0

    # -- mutation -----------------------------------------------------

    def add_node(
        self, node_id: str, seq: int, coords: Optional[Tuple[float, float]] = None
    ) -> str:
        """Register a node; ``coords`` (optional) enables the A* heuristic."""
        with self._lock:
            _check_seq(seq, self._last_seq)
            node_id = _check_node_id(node_id)
            if node_id in self._coords:
                raise DuplicateNodeError(f"node already registered: {node_id!r}")
            if len(self._coords) >= MAX_NODES:
                raise RoutingError("node cap reached")
            self._coords[node_id] = _check_coords(coords)
            self._adj[node_id] = []
            self._last_seq = seq
            return node_id

    def remove_node(self, node_id: str, seq: int) -> int:
        """Remove a node and all incident edges; returns edges removed."""
        with self._lock:
            _check_seq(seq, self._last_seq)
            node_id = _check_node_id(node_id)
            if node_id not in self._coords:
                raise UnknownNodeError(f"unknown node: {node_id!r}")
            removed = sum(
                1 for (u, v) in list(self._edges) if u == node_id or v == node_id
            )
            for (u, v) in [e for e in self._edges if e[0] == node_id or e[1] == node_id]:
                del self._edges[(u, v)]
                if v in self._adj.get(u, []):
                    self._adj[u].remove(v)
            del self._coords[node_id]
            del self._adj[node_id]
            self._last_seq = seq
            return removed

    def add_edge(
        self, src: str, dst: str, cost: Any, seq: int
    ) -> Tuple[str, str]:
        """Add a directed edge; negative/NaN/inf costs and self-loops refused."""
        with self._lock:
            _check_seq(seq, self._last_seq)
            src = _check_node_id(src)
            dst = _check_node_id(dst)
            if src not in self._coords:
                raise UnknownNodeError(f"unknown node: {src!r}")
            if dst not in self._coords:
                raise UnknownNodeError(f"unknown node: {dst!r}")
            if src == dst:
                raise SelfLoopError("self-loops are refused")
            cost = _check_cost(cost)
            if (src, dst) in self._edges:
                raise DuplicateEdgeError(f"edge already exists: {src!r} -> {dst!r}")
            if len(self._edges) >= MAX_EDGES:
                raise RoutingError("edge cap reached")
            self._edges[(src, dst)] = cost
            self._adj[src].append(dst)
            self._adj[src].sort()
            self._last_seq = seq
            return (src, dst)

    def remove_edge(self, src: str, dst: str, seq: int) -> None:
        """Remove a directed edge; unknown edges raise."""
        with self._lock:
            _check_seq(seq, self._last_seq)
            src = _check_node_id(src)
            dst = _check_node_id(dst)
            if (src, dst) not in self._edges:
                raise UnknownEdgeError(f"unknown edge: {src!r} -> {dst!r}")
            del self._edges[(src, dst)]
            self._adj[src].remove(dst)
            self._last_seq = seq

    # -- views ----------------------------------------------------------

    def nodes(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(self._coords)

    def edges(self) -> Tuple[Tuple[str, str, Any], ...]:
        with self._lock:
            return tuple((u, v, self._edges[(u, v)]) for (u, v) in sorted(self._edges))

    def neighbors(self, node_id: str) -> Tuple[str, ...]:
        with self._lock:
            node_id = _check_node_id(node_id)
            if node_id not in self._coords:
                raise UnknownNodeError(f"unknown node: {node_id!r}")
            return tuple(self._adj[node_id])

    def node_count(self) -> int:
        with self._lock:
            return len(self._coords)

    def edge_count(self) -> int:
        with self._lock:
            return len(self._edges)

    # -- routing ----------------------------------------------------------

    def _heuristic_mode(self) -> str:
        """Choose A* only when the Euclidean bound provably holds.

        A* needs h(v) <= true_cost(v, dst) everywhere. With coords on
        both ends of an edge, Euclidean distance is admissible only if
        the edge costs at least that distance. Any violating edge (or
        any node without coords) falls the whole query back to
        Dijkstra (h = 0, always admissible), so optimality is never
        silently lost.
        """
        if not any(c is not None for c in self._coords.values()):
            return "dijkstra"
        for (u, v), cost in self._edges.items():
            cu, cv = self._coords[u], self._coords[v]
            if cu is not None and cv is not None and cost < _euclidean(cu, cv):
                return "dijkstra"
        return "astar"

    def _shortest_path(
        self, src: str, dst: str
    ) -> Tuple[Tuple[str, ...], Any, str]:
        mode = self._heuristic_mode()
        dst_c = self._coords[dst]

        def h(node: str) -> float:
            if mode != "astar":
                return 0.0
            nc = self._coords[node]
            if nc is None or dst_c is None:
                return 0.0
            return _euclidean(nc, dst_c)

        # (f, tie-break counter, node); sorted adjacency + counter give a
        # fully deterministic expansion order for equal f-scores.
        counter = 0
        open_heap: List[Tuple[float, int, str]] = [(h(src), counter, src)]
        g: Dict[str, Any] = {src: 0}
        came: Dict[str, str] = {}
        closed = set()
        while open_heap:
            _, _, node = heapq.heappop(open_heap)
            if node in closed:
                continue
            closed.add(node)
            if node == dst:
                path = [dst]
                while path[-1] != src:
                    path.append(came[path[-1]])
                path.reverse()
                return tuple(path), g[dst], mode
            for nb in self._adj[node]:
                if nb in closed:
                    continue
                tentative = g[node] + self._edges[(node, nb)]
                if tentative < g.get(nb, math.inf):
                    g[nb] = tentative
                    came[nb] = node
                    counter += 1
                    heapq.heappush(open_heap, (tentative + h(nb), counter, nb))
        raise NoPathError(f"no directed path: {src!r} -> {dst!r}")

    def _route_digest(self, src: str, dst: str, path: Tuple[str, ...], cost: Any, mode: str) -> str:
        body = {
            "src": src,
            "dst": dst,
            "path": list(path),
            "total_cost": _cost_tag(cost),
            "heuristic": mode,
            "version": ROUTING_ENGINE_VERSION,
        }
        return _digest(jcs_canonical_json(body))

    def route(self, src: str, dst: str, seq: int) -> RouteRecord:
        """Shortest directed path; raises NoPathError when unreachable."""
        with self._lock:
            _check_seq(seq, self._last_seq)
            src = _check_node_id(src)
            dst = _check_node_id(dst)
            if src not in self._coords:
                raise UnknownNodeError(f"unknown node: {src!r}")
            if dst not in self._coords:
                raise UnknownNodeError(f"unknown node: {dst!r}")
            self._last_seq = seq
            path, cost, mode = self._shortest_path(src, dst)
            self._route_counter += 1
            return RouteRecord(
                route_id=f"rt-{self._route_counter}",
                src=src,
                dst=dst,
                path=path,
                total_cost=cost,
                hops=len(path) - 1,
                heuristic=mode,
                digest=self._route_digest(src, dst, path, cost, mode),
            )

    def distance(self, src: str, dst: str, seq: int) -> Any:
        """Total cost of the shortest path; NoPathError when unreachable."""
        return self.route(src, dst, seq).total_cost

    def eta(self, src: str, dst: str, seq: int, speed: Any) -> EtaEstimate:
        """Exact rational ETA: duration = shortest distance / speed.

        ``speed`` must be a positive finite number (not bool). The
        duration is a Fraction — exact arithmetic, no float drift — in
        whatever time unit makes cost/speed meaningful to the host.
        """
        with self._lock:
            if isinstance(speed, bool) or not isinstance(speed, (int, float)):
                raise BadSpeedError(f"speed must be a positive number, got {speed!r}")
            if not math.isfinite(speed) or speed <= 0:
                raise BadSpeedError(f"speed must be positive and finite, got {speed!r}")
            record = self.route(src, dst, seq)
            duration = Fraction(record.total_cost).limit_denominator() / Fraction(
                speed
            ).limit_denominator()
            return EtaEstimate(
                src=src,
                dst=dst,
                distance=record.total_cost,
                speed=speed,
                duration=duration,
                route_digest=record.digest,
            )


def routing_engine_audit_event(
    kind: str, engine: RoutingEngine, seq: int, detail: Optional[Dict[str, Any]] = None
) -> dict:
    """Shape an ``audit.ndjson/1``-style record for engine activity."""
    if kind not in (
        "node-added",
        "node-removed",
        "edge-added",
        "edge-removed",
        "routed",
    ):
        raise ValueError(f"unknown kind: {kind!r}")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise ValueError("seq must be a non-negative int")
    if not isinstance(engine, RoutingEngine):
        raise TypeError("engine must be a RoutingEngine")
    event = {
        "schema": SCHEMA_PIN,
        "event": "routing-engine." + kind,
        "node_count": engine.node_count(),
        "edge_count": engine.edge_count(),
        "audit_seq": seq,
    }
    if detail:
        event["detail"] = detail
    return event


def main() -> None:
    eng = RoutingEngine()
    seq = 0

    def nxt() -> int:
        nonlocal seq
        seq += 1
        return seq

    # Unit square with a diagonal: a(0,0) b(1,0) c(1,1) d(0,1).
    for n, xy in {
        "a": (0.0, 0.0),
        "b": (1.0, 0.0),
        "c": (1.0, 1.0),
        "d": (0.0, 1.0),
    }.items():
        eng.add_node(n, nxt(), coords=xy)
    # Ring edges cost 1; diagonal a-c costs 1.0 (below sqrt(2), so the
    # Euclidean bound is violated -> this query falls back to Dijkstra).
    for u, v in [("a", "b"), ("b", "c"), ("c", "d"), ("d", "a")]:
        eng.add_edge(u, v, 1, nxt())
        eng.add_edge(v, u, 1, nxt())
    eng.add_edge("a", "c", 1.0, nxt())
    eng.add_edge("c", "a", 1.0, nxt())

    r = eng.route("a", "c", nxt())
    assert r.path == ("a", "c"), r.path
    assert r.total_cost == 1.0, r.total_cost
    assert r.heuristic == "dijkstra", r.heuristic  # bound violated -> fallback
    assert eng.distance("a", "c", nxt()) == 1.0
    eta = eng.eta("a", "c", nxt(), 3)
    assert eta.duration == Fraction(1, 3), eta.duration  # 1.0 / 3 exact

    # Now a graph where the bound holds: edges cost >= euclidean.
    eng2 = RoutingEngine()
    seq2 = 0

    def nxt2() -> int:
        nonlocal seq2
        seq2 += 1
        return seq2

    eng2.add_node("p", nxt2(), coords=(0.0, 0.0))
    eng2.add_node("q", nxt2(), coords=(3.0, 4.0))
    eng2.add_edge("p", "q", 5, nxt2())  # == euclidean distance
    r2 = eng2.route("p", "q", nxt2())
    assert r2.heuristic == "astar", r2.heuristic
    assert r2.total_cost == 5

    # Unreachable + unknown-node are fail-closed, never sentinels.
    eng2.add_node("iso", nxt2())
    try:
        eng2.route("p", "iso", nxt2())
    except NoPathError:
        pass
    else:
        raise AssertionError("unreachable must raise NoPathError")

    print(
        "routing-engine OK: A* route, dijkstra fallback on bound "
        "violation, exact Fraction ETA, fail-closed refusals"
    )


if __name__ == "__main__":
    main()
