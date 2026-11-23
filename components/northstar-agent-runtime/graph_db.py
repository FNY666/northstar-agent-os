"""Property-graph database interface: nodes, edges, traversal, shortest paths.

A property graph keeps labelled entities and labelled relationships with
arbitrary key/value properties -- the shape used by Neo4j-style systems for
relationship-dense data. This module is the single-host bookkeeping half of
that contract (persistence and query languages are the host's):

- :meth:`GraphDB.add_node` pins a node by a caller-supplied id with a set
  of labels and a property mapping.
- :meth:`GraphDB.add_edge` pins a directed edge (type + optional
  properties) between two existing nodes; self-loops are allowed,
  parallel edges are refused.
- :meth:`GraphDB.traverse` runs deterministic BFS/DFS from a start node
  with optional depth and edge-type/label filters, returning the visit
  order as frozen records.
- :meth:`GraphDB.shortest_path` runs BFS-based Dijkstra over uniform
  (or weight-property) edges and returns the pinned path.

All records are frozen dataclasses carrying ``sha256:`` digest pins and
the module version/schema pins. Caller-supplied integer seqs replace
wall-clock everywhere. Fail-closed: unknown nodes, duplicate ids,
non-canonicalizable properties, bad seqs, and empty graph traversals are
all refused with typed errors, never silent no-ops.

Honest scope: in-memory *interface bookkeeping*, not Neo4j. It cannot
prove a stored fact was true (the host supplied it), cannot detect
host-rewritten properties, and cannot serve concurrent writers beyond
RLock mutual exclusion. A traversal proves only that *these pinned
records* were connected by *these pinned edges* in the order visited.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Mapping, Optional, Sequence, Set, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


#: Version pin for this module's record shape.
GRAPH_DB_VERSION = "graph-db.v1"

#: Schema pin carried by records and audit events.
GRAPH_DB_SCHEMA = "northstar.graph-db.v1"

#: Domain prefix for node/edge/path digest pins.
_NODE_DOMAIN = b"northstar-graph-db.v1:node:"
_EDGE_DOMAIN = b"northstar-graph-db.v1:edge:"
_PATH_DOMAIN = b"northstar-graph-db.v1:path:"


# ---------------------------------------------------------------------------
# errors
# ---------------------------------------------------------------------------

class GraphError(Exception):
    """Base error for graph database operations."""


class DuplicateNodeError(GraphError):
    """A node id is already registered."""


class UnknownNodeError(GraphError):
    """An edge or traversal references an unregistered node."""


class DuplicateEdgeError(GraphError):
    """A parallel edge (same src, type, dst) is already registered."""


class GraphValidationError(GraphError):
    """A caller-supplied value failed validation (fail-closed)."""


# ---------------------------------------------------------------------------
# validation helpers
# ---------------------------------------------------------------------------

def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise GraphValidationError(f"seq must be a non-negative int, got {seq!r}")
    return seq


def _check_node_id(node_id: Any) -> str:
    if isinstance(node_id, bool) or not isinstance(node_id, str) or not node_id:
        raise GraphValidationError(f"node id must be a non-empty str, got {node_id!r}")
    return node_id


def _check_labels(labels: Any) -> FrozenSet[str]:
    if labels is None:
        return frozenset()
    if not isinstance(labels, (list, tuple, set, frozenset)):
        raise GraphValidationError(f"labels must be a sequence of str, got {labels!r}")
    out: Set[str] = set()
    for label in labels:
        if isinstance(label, bool) or not isinstance(label, str) or not label:
            raise GraphValidationError(f"each label must be a non-empty str, got {label!r}")
        out.add(label)
    return frozenset(sorted(out))


def _check_properties(properties: Any) -> Dict[str, Any]:
    if properties is None:
        return {}
    if not isinstance(properties, Mapping):
        raise GraphValidationError(f"properties must be a mapping, got {properties!r}")
    out: Dict[str, Any] = {}
    for key, value in properties.items():
        if isinstance(key, bool) or not isinstance(key, str) or not key:
            raise GraphValidationError(f"property keys must be non-empty str, got {key!r}")
        # canonicalizability gate: NaN/inf, bytes, >2^53 ints are refused
        if isinstance(value, float) and (value != value or value in (float("inf"), float("-inf"))):
            raise GraphValidationError(f"property {key!r}: NaN/inf not allowed")
        if isinstance(value, bool):
            out[key] = value
            continue
        if isinstance(value, int) and abs(value) > 2**53:
            raise GraphValidationError(
                f"property {key!r}: ints > 2^53 risk JCS float-loss digest mismatch")
        if isinstance(value, (str, int, float, type(None))):
            out[key] = value
            continue
        if isinstance(value, (list, tuple)):
            out[key] = _check_list(value, key)
            continue
        if isinstance(value, Mapping):
            out[key] = _check_properties(value)
            continue
        raise GraphValidationError(
            f"property {key!r}: value of type {type(value).__name__} not canonicalizable")
    return out


def _check_list(values: Sequence[Any], key: str) -> List[Any]:
    out: List[Any] = []
    for item in values:
        if isinstance(item, bool):
            out.append(item)
        elif isinstance(item, int):
            if abs(item) > 2**53:
                raise GraphValidationError(f"property {key!r}: ints > 2^53 not allowed")
            out.append(item)
        elif isinstance(item, (str, float, type(None))):
            if isinstance(item, float) and (item != item or item in (float("inf"), float("-inf"))):
                raise GraphValidationError(f"property {key!r}: NaN/inf not allowed")
            out.append(item)
        elif isinstance(item, Mapping):
            out.append(_check_properties(item))
        elif isinstance(item, (list, tuple)):
            out.append(_check_list(item, key))
        else:
            raise GraphValidationError(
                f"property {key!r}: list item of type {type(item).__name__} not canonicalizable")
    return out


def _check_edge_type(edge_type: Any) -> str:
    if isinstance(edge_type, bool) or not isinstance(edge_type, str) or not edge_type:
        raise GraphValidationError(f"edge type must be a non-empty str, got {edge_type!r}")
    return edge_type


def _pin(domain: bytes, body: Any) -> str:
    return "sha256:" + hashlib.sha256(domain + jcs_canonical_json(body)).hexdigest()


# ---------------------------------------------------------------------------
# records
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class NodeRecord:
    """A pinned node registration."""
    node_id: str
    labels: Tuple[str, ...]
    properties: Tuple[Tuple[str, Any], ...]
    digest: str
    version: str = GRAPH_DB_VERSION
    schema: str = GRAPH_DB_SCHEMA

    def as_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "labels": list(self.labels),
            "properties": dict(self.properties),
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class EdgeRecord:
    """A pinned directed edge registration."""
    edge_id: str
    src: str
    dst: str
    edge_type: str
    properties: Tuple[Tuple[str, Any], ...]
    digest: str
    version: str = GRAPH_DB_VERSION
    schema: str = GRAPH_DB_SCHEMA

    def as_dict(self) -> Dict[str, Any]:
        return {
            "edge_id": self.edge_id,
            "src": self.src,
            "dst": self.dst,
            "edge_type": self.edge_type,
            "properties": dict(self.properties),
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class TraversalVisit:
    """One visit in a traversal: node, depth, and the edge taken to get there."""
    node_id: str
    depth: int
    via_edge: Optional[str]
    via_type: Optional[str]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "depth": self.depth,
            "via_edge": self.via_edge,
            "via_type": self.via_type,
        }


@dataclass(frozen=True)
class TraversalReport:
    """A complete deterministic traversal."""
    start: str
    mode: str
    max_depth: Optional[int]
    visits: Tuple[TraversalVisit, ...]
    digest: str
    version: str = GRAPH_DB_VERSION
    schema: str = GRAPH_DB_SCHEMA

    def as_dict(self) -> Dict[str, Any]:
        return {
            "start": self.start,
            "mode": self.mode,
            "max_depth": self.max_depth,
            "visits": [v.as_dict() for v in self.visits],
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class PathResult:
    """A pinned shortest-path result."""
    src: str
    dst: str
    node_path: Tuple[str, ...]
    edge_path: Tuple[str, ...]
    total_cost: float
    digest: str
    version: str = GRAPH_DB_VERSION
    schema: str = GRAPH_DB_SCHEMA

    def as_dict(self) -> Dict[str, Any]:
        return {
            "src": self.src,
            "dst": self.dst,
            "node_path": list(self.node_path),
            "edge_path": list(self.edge_path),
            "total_cost": self.total_cost,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


# ---------------------------------------------------------------------------
# graph database
# ---------------------------------------------------------------------------

class GraphDB:
    """In-memory property-graph registry with digest pins.

    Nodes and edges are pinned by ``sha256:`` digests over their canonical
    bodies; traversals and shortest paths are deterministic for identical
    inputs (neighbors are always visited in sorted order).
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._nodes: Dict[str, NodeRecord] = {}
        self._edges: Dict[str, EdgeRecord] = {}
        self._out: Dict[str, List[str]] = {}
        self._edge_counter = 0

    # -- nodes ----------------------------------------------------------

    def add_node(self, node_id: str, seq: int,
                 labels: Optional[Sequence[str]] = None,
                 properties: Optional[Mapping[str, Any]] = None) -> NodeRecord:
        """Register a node; duplicate ids are refused fail-closed."""
        nid = _check_node_id(node_id)
        seq = _check_seq(seq)
        labels_fs = _check_labels(labels)
        props = _check_properties(properties)
        with self._lock:
            if nid in self._nodes:
                raise DuplicateNodeError(f"node {nid!r} already registered")
            body = {"node_id": nid, "labels": sorted(labels_fs),
                    "properties": props, "seq": seq}
            digest = _pin(_NODE_DOMAIN, body)
            record = NodeRecord(
                node_id=nid,
                labels=tuple(sorted(labels_fs)),
                properties=tuple(sorted(props.items())),
                digest=digest,
            )
            self._nodes[nid] = record
            self._out.setdefault(nid, [])
            return record

    def node(self, node_id: str) -> NodeRecord:
        """Return a registered node; unknown ids raise."""
        nid = _check_node_id(node_id)
        with self._lock:
            try:
                return self._nodes[nid]
            except KeyError:
                raise UnknownNodeError(f"unknown node {nid!r}") from None

    # -- edges ----------------------------------------------------------

    def add_edge(self, src: str, dst: str, edge_type: str, seq: int,
                 properties: Optional[Mapping[str, Any]] = None) -> EdgeRecord:
        """Add a directed edge between existing nodes.

        Parallel edges (same src, type, dst) are refused fail-closed;
        self-loops are allowed.
        """
        s = _check_node_id(src)
        d = _check_node_id(dst)
        etype = _check_edge_type(edge_type)
        seq = _check_seq(seq)
        props = _check_properties(properties)
        with self._lock:
            if s not in self._nodes:
                raise UnknownNodeError(f"unknown src node {s!r}")
            if d not in self._nodes:
                raise UnknownNodeError(f"unknown dst node {d!r}")
            for edge in self._edges.values():
                if edge.src == s and edge.dst == d and edge.edge_type == etype:
                    raise DuplicateEdgeError(
                        f"parallel edge {s!r}-[{etype}]->{d!r} already registered")
            self._edge_counter += 1
            edge_id = f"e-{self._edge_counter}"
            body = {"edge_id": edge_id, "src": s, "dst": d,
                    "edge_type": etype, "properties": props, "seq": seq}
            digest = _pin(_EDGE_DOMAIN, body)
            record = EdgeRecord(
                edge_id=edge_id,
                src=s,
                dst=d,
                edge_type=etype,
                properties=tuple(sorted(props.items())),
                digest=digest,
            )
            self._edges[edge_id] = record
            self._out.setdefault(s, []).append(edge_id)
            self._out[s].sort()
            return record

    def edge(self, edge_id: str) -> EdgeRecord:
        """Return a registered edge; unknown ids raise."""
        if isinstance(edge_id, bool) or not isinstance(edge_id, str) or not edge_id:
            raise GraphValidationError(f"edge id must be a non-empty str, got {edge_id!r}")
        with self._lock:
            try:
                return self._edges[edge_id]
            except KeyError:
                raise GraphError(f"unknown edge {edge_id!r}") from None

    # -- queries ----------------------------------------------------------

    def neighbors(self, node_id: str,
                  edge_types: Optional[Sequence[str]] = None) -> List[EdgeRecord]:
        """Out-edges of a node, sorted by edge id; unknown node raises."""
        nid = _check_node_id(node_id)
        type_set: Optional[Set[str]] = None
        if edge_types is not None:
            type_set = {_check_edge_type(t) for t in edge_types}
        with self._lock:
            if nid not in self._nodes:
                raise UnknownNodeError(f"unknown node {nid!r}")
            out = [self._edges[eid] for eid in self._out.get(nid, [])]
            if type_set is not None:
                out = [e for e in out if e.edge_type in type_set]
            return out

    def traverse(self, start: str, seq: int, mode: str = "bfs",
                 max_depth: Optional[int] = None,
                 edge_types: Optional[Sequence[str]] = None,
                 label_filter: Optional[Sequence[str]] = None) -> TraversalReport:
        """Deterministic BFS/DFS traversal from ``start``.

        ``max_depth`` bounds edge distance (None = unbounded).
        ``edge_types`` restricts which edges are followed. ``label_filter``
        restricts which nodes are *visited* (start is always visited).
        """
        nid = _check_node_id(start)
        seq = _check_seq(seq)
        if mode not in ("bfs", "dfs"):
            raise GraphValidationError(f"mode must be 'bfs' or 'dfs', got {mode!r}")
        if max_depth is not None:
            if isinstance(max_depth, bool) or not isinstance(max_depth, int) or max_depth < 0:
                raise GraphValidationError(
                    f"max_depth must be a non-negative int or None, got {max_depth!r}")
        type_set: Optional[Set[str]] = None
        if edge_types is not None:
            type_set = {_check_edge_type(t) for t in edge_types}
        label_set: Optional[Set[str]] = None
        if label_filter is not None:
            label_set = set(_check_labels(label_filter))

        with self._lock:
            if nid not in self._nodes:
                raise UnknownNodeError(f"unknown node {nid!r}")

            def accepted(node: str) -> bool:
                if label_set is None:
                    return True
                return bool(label_set.intersection(self._nodes[node].labels))

            visits: List[TraversalVisit] = [
                TraversalVisit(node_id=nid, depth=0, via_edge=None, via_type=None)
            ]
            seen = {nid}
            if mode == "bfs":
                from collections import deque
                queue: deque = deque([(nid, 0)])
                while queue:
                    node, depth = queue.popleft()
                    if max_depth is not None and depth >= max_depth:
                        continue
                    for edge in sorted(self._out.get(node, [])):
                        rec = self._edges[edge]
                        if type_set is not None and rec.edge_type not in type_set:
                            continue
                        nxt = rec.dst
                        if nxt in seen:
                            continue
                        seen.add(nxt)
                        if accepted(nxt):
                            visits.append(TraversalVisit(
                                node_id=nxt, depth=depth + 1,
                                via_edge=rec.edge_id, via_type=rec.edge_type))
                        queue.append((nxt, depth + 1))
            else:  # dfs
                stack = [(nid, 0)]
                while stack:
                    node, depth = stack.pop()
                    if max_depth is not None and depth >= max_depth:
                        continue
                    children = []
                    for edge in sorted(self._out.get(node, []), reverse=True):
                        rec = self._edges[edge]
                        if type_set is not None and rec.edge_type not in type_set:
                            continue
                        nxt = rec.dst
                        if nxt in seen:
                            continue
                        seen.add(nxt)
                        children.append((nxt, rec))
                    for nxt, rec in children:
                        if accepted(nxt):
                            visits.append(TraversalVisit(
                                node_id=nxt, depth=depth + 1,
                                via_edge=rec.edge_id, via_type=rec.edge_type))
                        stack.append((nxt, depth + 1))

            digest = _pin(_PATH_DOMAIN, {
                "kind": "traversal", "start": nid, "mode": mode,
                "max_depth": max_depth,
                "visits": [v.as_dict() for v in visits], "seq": seq,
            })
            return TraversalReport(
                start=nid, mode=mode, max_depth=max_depth,
                visits=tuple(visits), digest=digest)

    def shortest_path(self, src: str, dst: str, seq: int,
                      edge_types: Optional[Sequence[str]] = None,
                      weight_property: Optional[str] = None) -> PathResult:
        """Shortest path by BFS (uniform cost) or Dijkstra over ``weight_property``.

        Unknown nodes, disconnected pairs, and non-numeric/negative weights
        are refused fail-closed. Non-finite total costs are refused.
        """
        s = _check_node_id(src)
        d = _check_node_id(dst)
        seq = _check_seq(seq)
        type_set: Optional[Set[str]] = None
        if edge_types is not None:
            type_set = {_check_edge_type(t) for t in edge_types}
        if weight_property is not None:
            if isinstance(weight_property, bool) or not isinstance(weight_property, str) \
                    or not weight_property:
                raise GraphValidationError(
                    f"weight_property must be a non-empty str or None, got {weight_property!r}")

        with self._lock:
            if s not in self._nodes:
                raise UnknownNodeError(f"unknown src node {s!r}")
            if d not in self._nodes:
                raise UnknownNodeError(f"unknown dst node {d!r}")
            if s == d:
                digest = _pin(_PATH_DOMAIN, {
                    "kind": "path", "src": s, "dst": d,
                    "node_path": [s], "edge_path": [],
                    "total_cost": 0.0, "seq": seq,
                })
                return PathResult(src=s, dst=d, node_path=(s,), edge_path=(),
                                  total_cost=0.0, digest=digest)

            def edge_cost(rec: EdgeRecord) -> float:
                if weight_property is None:
                    return 1.0
                props = dict(rec.properties)
                if weight_property not in props:
                    raise GraphValidationError(
                        f"edge {rec.edge_id}: missing weight property {weight_property!r}")
                w = props[weight_property]
                if isinstance(w, bool) or not isinstance(w, (int, float)):
                    raise GraphValidationError(
                        f"edge {rec.edge_id}: weight must be numeric, got {w!r}")
                w = float(w)
                if w != w or w in (float("inf"), float("-inf")) or w < 0:
                    raise GraphValidationError(
                        f"edge {rec.edge_id}: weight must be finite non-negative, got {w!r}")
                return w

            import heapq
            # Dijkstra with deterministic tie-breaks (sorted neighbors).
            dist: Dict[str, float] = {s: 0.0}
            prev: Dict[str, Tuple[str, str]] = {}
            heap: List[Tuple[float, str]] = [(0.0, s)]
            visited: Set[str] = set()
            while heap:
                cost, node = heapq.heappop(heap)
                if node in visited:
                    continue
                visited.add(node)
                if node == d:
                    break
                for eid in sorted(self._out.get(node, [])):
                    rec = self._edges[eid]
                    if type_set is not None and rec.edge_type not in type_set:
                        continue
                    nxt = rec.dst
                    if nxt in visited:
                        continue
                    w = edge_cost(rec)
                    new_cost = cost + w
                    if new_cost != new_cost or new_cost in (float("inf"), float("-inf")):
                        raise GraphValidationError(
                            f"edge {eid}: total cost overflowed to non-finite")
                    if nxt not in dist or new_cost < dist[nxt] - 1e-12:
                        dist[nxt] = new_cost
                        prev[nxt] = (node, eid)
                        heapq.heappush(heap, (new_cost, nxt))

            if d not in dist:
                raise GraphError(f"no path from {s!r} to {d!r}")

            node_path: List[str] = [d]
            edge_path: List[str] = []
            cur = d
            while cur != s:
                p, eid = prev[cur]
                node_path.append(p)
                edge_path.append(eid)
                cur = p
            node_path.reverse()
            edge_path.reverse()
            total = dist[d]
            digest = _pin(_PATH_DOMAIN, {
                "kind": "path", "src": s, "dst": d,
                "node_path": node_path, "edge_path": edge_path,
                "total_cost": total, "seq": seq,
            })
            return PathResult(src=s, dst=d, node_path=tuple(node_path),
                              edge_path=tuple(edge_path),
                              total_cost=total, digest=digest)

    # -- views ------------------------------------------------------------

    def node_count(self) -> int:
        with self._lock:
            return len(self._nodes)

    def edge_count(self) -> int:
        with self._lock:
            return len(self._edges)

    def node_ids(self) -> List[str]:
        with self._lock:
            return sorted(self._nodes)


# ---------------------------------------------------------------------------
# audit events
# ---------------------------------------------------------------------------

def graph_db_audit_event(kind: str, seq: int, digest: str = "") -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for graph events."""
    seq = _check_seq(seq)
    allowed = {"node-added", "edge-added", "traversed", "path-found", "rejected"}
    if kind not in allowed:
        raise GraphValidationError(f"unknown audit kind {kind!r}")
    event: Dict[str, Any] = {
        "kind": kind,
        "seq": seq,
        "schema": GRAPH_DB_SCHEMA,
        "version": GRAPH_DB_VERSION,
    }
    if digest:
        if not (isinstance(digest, str) and digest.startswith("sha256:")):
            raise GraphValidationError(f"digest must be a 'sha256:' pin, got {digest!r}")
        event["digest"] = digest
    return event


def main() -> None:
    g = GraphDB()
    g.add_node("a", 1, labels=["city"], properties={"pop": 1000})
    g.add_node("b", 2, labels=["city"], properties={"pop": 2000})
    g.add_node("c", 3, labels=["town"])
    g.add_edge("a", "b", "ROAD", 4, {"km": 5})
    g.add_edge("b", "c", "ROAD", 5, {"km": 7})
    g.add_edge("a", "c", "RAIL", 6, {"km": 20})
    trav = g.traverse("a", 7)
    assert [v.node_id for v in trav.visits] == ["a", "b", "c"], trav.visits
    path = g.shortest_path("a", "c", 8, weight_property="km")
    assert path.node_path == ("a", "b", "c") and path.total_cost == 12.0, path
    direct = g.shortest_path("a", "c", 9)
    assert direct.node_path == ("a", "c") and direct.total_cost == 1.0, direct
    print("graph-db OK: nodes, edges, traversal, shortest paths")


if __name__ == "__main__":
    main()
