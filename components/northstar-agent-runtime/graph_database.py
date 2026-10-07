"""Graph database: named property-graph database bookkeeping.

Research motivation: in Neo4j (and Neo4j Fabric / multi-database setups),
one database server hosts *multiple named graphs* -- each a property
graph of labelled nodes joined by typed, directed relationships with
arbitrary key/value properties. This module books that contract
deterministically: create named graphs, pin labelled nodes and typed
edges inside them, traverse them, and drop graphs. It stores no engine,
plans no queries, speaks no Cypher -- the host owns persistence, query
planning, and execution.

Deliberately distinct from the sibling ``graph_db.py`` (one global graph,
verb API ``add_node``/``add_edge``/``traverse``/``shortest_path``): this
module is the *multi-database* layer with the noun API
``graph()``/``node()``/``edge()``/``traverse()`` -- the database-server
half where one host manages many named property graphs.

Public API:

- ``GraphDatabase()`` -- mutable, RLock-guarded ledger.
  - ``graph(graph_name, seq)`` -> frozen ``GraphRecord``: creates a
    named graph. Duplicate and retired ids are refused fail-closed.
  - ``drop(graph_name, seq, reason="")`` -> frozen ``DropRecord``:
    terminally removes a named graph; the id is retired and may never
    be re-created.
  - ``node(graph_name, node_id, seq, labels=(), properties=None)`` ->
    frozen ``NodeRecord``: pins a labelled node with a canonical
    property mapping. Unknown graphs, duplicate node ids, and
    non-canonicalizable properties are refused fail-closed.
  - ``edge(graph_name, edge_id, from_id, to_id, edge_type, seq,
    properties=None)`` -> frozen ``EdgeRecord``: pins a directed typed
    edge between two existing nodes. Unknown graphs/endpoints,
    duplicate edge ids, and parallel edges (same ``from``/``to``/type)
    are refused fail-closed. Self-loops are allowed.
  - ``traverse(graph_name, start_id, seq, mode="bfs", max_depth=0,
    edge_types=(), labels=())`` -> frozen ``TraverseReport``: pure read
    view (seq shape validated, never consumed, no audit row) of the
    deterministic visit order from ``start_id``. ``mode`` is ``"bfs"``
    or ``"dfs"``; ``max_depth=0`` means unlimited; ``edge_types``
    restricts which edges are followed; ``labels`` restricts which
    reached nodes are visited (the start node is always visited).
  - ``node_view(graph_name, node_id)`` / ``edge_view(graph_name,
    edge_id)`` / ``graph_names()`` / ``node_ids(graph_name)`` /
    ``edge_ids(graph_name)`` / ``neighbors(graph_name, node_id)`` /
    ``stats()`` / ``audit_log()`` -- pure read views; consume no seq.
- ``graph_database_audit_event(kind, detail, seq)`` --
  ``audit.ndjson/1`` records: ``"graph-database.graph-created"``,
  ``"graph-database.node-pinned"``, ``"graph-database.edge-pinned"``,
  ``"graph-database.graph-dropped"``, ``"graph-database.rejected"``.

Properties are pinned by digest: raw property values never enter a
record's digest payload and never cross the audit boundary. Time is
caller-supplied logical seqs; the module cannot prove a traversal was
executed against real storage.

House discipline: caller int seqs strictly increasing on mutations
(failed mutations consume their seq; bool/negative/rewind refused),
RLock-guarded, fail-closed taxonomy, stdlib-only (``canonical_json``
sibling helper behind the standard try/except fallback).

Honest scope:

- This module books *declared* graphs, nodes, edges, and traversals; it
  observes no storage engine and cannot prove a stored fact was true --
  the host supplied it.
- A ``TraverseReport`` proves only that *these pinned records* were
  connected by *these pinned edges* in the visited order; it is a
  decision, not a query result from a real graph engine.
- Raw property values never cross the audit boundary; digests are pins,
  not proofs of provenance.

Version pin: ``graph-database.v1`` / schema pin
``northstar.graph-database.v1``.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Tuple

try:  # stdlib-first; canonical_json is the sibling JCS helper
    import canonical_json as _cj  # type: ignore
except Exception:  # pragma: no cover - fallback keeps stdlib-only promise
    _cj = None  # type: ignore

#: Version pin for this module's record shape.
GRAPH_DATABASE_VERSION = "graph-database.v1"

#: Schema pin carried by records and audit events.
GRAPH_DATABASE_SCHEMA = "northstar.graph-database.v1"

#: Wire format of audit records.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Fixed vocabulary for audit event kinds.
KIND_GRAPH_CREATED = "graph-database.graph-created"
KIND_NODE_PINNED = "graph-database.node-pinned"
KIND_EDGE_PINNED = "graph-database.edge-pinned"
KIND_GRAPH_DROPPED = "graph-database.graph-dropped"
KIND_REJECTED = "graph-database.rejected"
_KINDS = frozenset(
    {
        KIND_GRAPH_CREATED,
        KIND_NODE_PINNED,
        KIND_EDGE_PINNED,
        KIND_GRAPH_DROPPED,
        KIND_REJECTED,
    }
)

_MAX_INT = 2**53 - 1
_MAX_ID_LEN = 256
_MAX_LABEL_LEN = 128
_MAX_STR_VALUE = 4 * 1024
_MAX_PROP_DEPTH = 8
_DIGEST_PREFIX = "sha256:"
_DIGEST_LEN = len(_DIGEST_PREFIX) + 64

_MODES = frozenset({"bfs", "dfs"})


# ---------------------------------------------------------------------------
# Error taxonomy (fail-closed)
# ---------------------------------------------------------------------------


class GraphDatabaseError(Exception):
    """Base class for all graph-database errors."""


class BadGraphError(GraphDatabaseError):
    """graph_name is not a non-empty str."""


class DuplicateGraphError(GraphDatabaseError):
    """graph_name is already booked (created or retired)."""


class UnknownGraphError(GraphDatabaseError):
    """graph_name is not an active graph."""


class BadIdError(GraphDatabaseError):
    """node_id / edge_id is not a non-empty str."""


class DuplicateNodeError(GraphDatabaseError):
    """node_id is already pinned in this graph."""


class UnknownNodeError(GraphDatabaseError):
    """node_id is not pinned in this graph."""


class DuplicateEdgeError(GraphDatabaseError):
    """edge_id is already pinned in this graph."""


class UnknownEdgeError(GraphDatabaseError):
    """edge_id is not pinned in this graph."""


class ParallelEdgeError(GraphDatabaseError):
    """An edge with the same (from, to, type) is already pinned."""


class BadLabelError(GraphDatabaseError):
    """A label is not a non-empty str, or a filter tuple is malformed."""


class BadPropertyError(GraphDatabaseError):
    """properties is not a canonicalizable mapping."""


class BadEdgeTypeError(GraphDatabaseError):
    """edge_type is not a non-empty str."""


class BadModeError(GraphDatabaseError):
    """mode is not one of "bfs" / "dfs"."""


class BadDepthError(GraphDatabaseError):
    """max_depth is not a non-negative int."""


class SeqOrderError(GraphDatabaseError):
    """Caller seq did not strictly increase."""


class AuditKindError(GraphDatabaseError):
    """Unknown audit kind for graph_database_audit_event."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_id(value: Any, what: str = "id") -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadIdError(f"{what} must be str, got {type(value).__name__}")
    if not value.strip():
        raise BadIdError(f"{what} must be non-empty")
    if len(value) > _MAX_ID_LEN:
        raise BadIdError(f"{what} exceeds {_MAX_ID_LEN} chars")
    return value


def _check_graph_name(name: Any) -> str:
    if isinstance(name, bool) or not isinstance(name, str):
        raise BadGraphError(
            f"graph_name must be str, got {type(name).__name__}"
        )
    if not name.strip():
        raise BadGraphError("graph_name must be non-empty")
    if len(name) > _MAX_ID_LEN:
        raise BadGraphError(f"graph_name exceeds {_MAX_ID_LEN} chars")
    return name


def _check_label(label: Any) -> str:
    if isinstance(label, bool) or not isinstance(label, str):
        raise BadLabelError(
            f"label must be str, got {type(label).__name__}"
        )
    if not label.strip():
        raise BadLabelError("label must be non-empty")
    if len(label) > _MAX_LABEL_LEN:
        raise BadLabelError(f"label exceeds {_MAX_LABEL_LEN} chars")
    return label


def _check_labels(labels: Any) -> Tuple[str, ...]:
    if isinstance(labels, bool) or not isinstance(labels, (tuple, list)):
        raise BadLabelError("labels must be a tuple/list of str")
    seen = []
    for item in labels:
        label = _check_label(item)
        if label not in seen:
            seen.append(label)
    return tuple(sorted(seen))


def _check_edge_type(edge_type: Any) -> str:
    if isinstance(edge_type, bool) or not isinstance(edge_type, str):
        raise BadEdgeTypeError(
            f"edge_type must be str, got {type(edge_type).__name__}"
        )
    if not edge_type.strip():
        raise BadEdgeTypeError("edge_type must be non-empty")
    if len(edge_type) > _MAX_LABEL_LEN:
        raise BadEdgeTypeError(f"edge_type exceeds {_MAX_LABEL_LEN} chars")
    return edge_type


def _check_mode(mode: Any) -> str:
    if isinstance(mode, bool) or not isinstance(mode, str):
        raise BadModeError(f"mode must be str, got {type(mode).__name__}")
    if mode not in _MODES:
        raise BadModeError('mode must be one of "bfs" / "dfs"')
    return mode


def _check_depth(depth: Any) -> int:
    if isinstance(depth, bool) or not isinstance(depth, int):
        raise BadDepthError(
            f"max_depth must be int, got {type(depth).__name__}"
        )
    if depth < 0:
        raise BadDepthError("max_depth must be non-negative")
    return depth


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError(f"seq must be int, got {type(seq).__name__}")
    if seq < 0:
        raise SeqOrderError("seq must be non-negative")
    return seq


def _check_properties(properties: Any, depth: int = 0) -> Mapping[str, Any]:
    if properties is None:
        return {}
    if isinstance(properties, bool) or not isinstance(properties, Mapping):
        raise BadPropertyError("properties must be a mapping or None")
    if depth > _MAX_PROP_DEPTH:
        raise BadPropertyError("properties nesting exceeds depth cap")
    checked: Dict[str, Any] = {}
    for key, value in properties.items():
        if isinstance(key, bool) or not isinstance(key, str):
            raise BadPropertyError("property keys must be str")
        checked[key] = _check_value(value, depth + 1)
    return checked


def _check_value(value: Any, depth: int = 0) -> Any:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        if abs(value) >= 2**53:
            raise BadPropertyError("integer outside safe range")
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise BadPropertyError("non-finite float refused")
        return value
    if isinstance(value, str):
        if len(value) > _MAX_STR_VALUE:
            raise BadPropertyError("string value exceeds 4 KiB")
        return value
    if value is None:
        return value
    if isinstance(value, (list, tuple)):
        if depth > _MAX_PROP_DEPTH:
            raise BadPropertyError("properties nesting exceeds depth cap")
        return tuple(_check_value(v, depth + 1) for v in value)
    if isinstance(value, Mapping):
        if depth > _MAX_PROP_DEPTH:
            raise BadPropertyError("properties nesting exceeds depth cap")
        nested: Dict[str, Any] = {}
        for key, item in value.items():
            if isinstance(key, bool) or not isinstance(key, str):
                raise BadPropertyError("property keys must be str")
            nested[key] = _check_value(item, depth + 1)
        return nested
    raise BadPropertyError(f"unencodable type: {type(value).__name__}")


# ---------------------------------------------------------------------------
# Canonical encoding and digest pins
# ---------------------------------------------------------------------------


def _canonical(payload: Any) -> bytes:
    if _cj is not None:
        return _cj.jcs_dumps(payload).encode("utf-8")  # type: ignore

    def _tag(v: Any) -> Any:
        if isinstance(v, bool):
            return {"t": "bool", "v": v}
        if isinstance(v, int):
            if abs(v) >= 2**53:
                raise GraphDatabaseError("integer outside safe range")
            return {"t": "int", "v": v}
        if isinstance(v, float):
            if v != v or v in (float("inf"), float("-inf")):
                raise GraphDatabaseError("non-finite float refused")
            return {"t": "float", "v": repr(v)}
        if isinstance(v, str):
            return {"t": "str", "v": v}
        if isinstance(v, (list, tuple)):
            return {"t": "list", "v": [_tag(i) for i in v]}
        if isinstance(v, dict):
            return {"t": "dict", "v": [[k, _tag(v[k])] for k in sorted(v)]}
        if v is None:
            return {"t": "null"}
        raise GraphDatabaseError(f"unencodable type: {type(v).__name__}")

    import json

    return json.dumps(
        _tag(payload), sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _pin(*parts: Any) -> str:
    digest = hashlib.sha256(
        _canonical([GRAPH_DATABASE_VERSION, *parts])
    ).hexdigest()
    return f"sha256:{digest}"


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GraphRecord:
    """A named graph pinned by this ledger."""

    graph_name: str
    digest: str
    seq: int
    schema: str = GRAPH_DATABASE_SCHEMA

    def verify(self) -> bool:
        try:
            recomputed = _pin("graph", self.graph_name, self.seq)
        except GraphDatabaseError:
            return False
        return recomputed == self.digest and (
            self.schema == GRAPH_DATABASE_SCHEMA
        )


@dataclass(frozen=True)
class DropRecord:
    """Terminal removal of a named graph.

    The ``graph_name`` is retired by this record and may never be
    re-created -- a reappearing graph is a new graph with a new name.
    """

    graph_name: str
    reason: str
    digest: str
    seq: int
    schema: str = GRAPH_DATABASE_SCHEMA

    def verify(self) -> bool:
        try:
            recomputed = _pin(
                "drop", self.graph_name, self.reason, self.seq
            )
        except GraphDatabaseError:
            return False
        return recomputed == self.digest and (
            self.schema == GRAPH_DATABASE_SCHEMA
        )


@dataclass(frozen=True)
class NodeRecord:
    """A labelled node pinned in one named graph.

    Property values are pinned by digest: raw values never cross the
    audit boundary, and this record carries only the digest.
    """

    graph_name: str
    node_id: str
    labels: Tuple[str, ...]
    properties_digest: str
    digest: str
    seq: int
    schema: str = GRAPH_DATABASE_SCHEMA

    def verify(self) -> bool:
        try:
            recomputed = _pin(
                "node",
                self.graph_name,
                self.node_id,
                self.labels,
                self.properties_digest,
                self.seq,
            )
        except GraphDatabaseError:
            return False
        return recomputed == self.digest and (
            self.schema == GRAPH_DATABASE_SCHEMA
        )


@dataclass(frozen=True)
class EdgeRecord:
    """A directed typed edge pinned between two nodes of one graph.

    Parallel edges (same ``from_node``/``to_node``/``edge_type``) are
    refused by the ledger; this record is the booking of a legal edge.
    Self-loops are allowed.
    """

    graph_name: str
    edge_id: str
    from_node: str
    to_node: str
    edge_type: str
    properties_digest: str
    digest: str
    seq: int
    schema: str = GRAPH_DATABASE_SCHEMA

    def verify(self) -> bool:
        try:
            recomputed = _pin(
                "edge",
                self.graph_name,
                self.edge_id,
                self.from_node,
                self.to_node,
                self.edge_type,
                self.properties_digest,
                self.seq,
            )
        except GraphDatabaseError:
            return False
        return recomputed == self.digest and (
            self.schema == GRAPH_DATABASE_SCHEMA
        )


@dataclass(frozen=True)
class TraverseReport:
    """Pure read view: deterministic visit order from a start node.

    ``visited`` holds node ids in visit order (start first). Booking
    nothing -- the report is a view, not a claim.
    """

    graph_name: str
    start_id: str
    mode: str
    max_depth: int
    visited: Tuple[str, ...]
    edge_count: int
    seq: int
    schema: str = GRAPH_DATABASE_SCHEMA


@dataclass(frozen=True)
class NodeView:
    """Pure read view of one pinned node's labels."""

    graph_name: str
    node_id: str
    labels: Tuple[str, ...]
    schema: str = GRAPH_DATABASE_SCHEMA


@dataclass(frozen=True)
class EdgeView:
    """Pure read view of one pinned edge's endpoints and type."""

    graph_name: str
    edge_id: str
    from_node: str
    to_node: str
    edge_type: str
    schema: str = GRAPH_DATABASE_SCHEMA


@dataclass(frozen=True)
class DbStats:
    """Pure read view of ledger counters."""

    graphs: int
    dropped: int
    nodes: int
    edges: int
    schema: str = GRAPH_DATABASE_SCHEMA


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def graph_database_audit_event(
    kind: str, detail: Mapping[str, Any], seq: int
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the graph database.

    Raw property values never cross the audit boundary: ``detail`` may
    carry digests, ids, labels, edge types, reasons and counts -- never
    ``properties``, ``payload``, ``value`` or ``raw``.
    """
    if not isinstance(kind, str) or kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    if not isinstance(detail, Mapping):
        raise AuditKindError("detail must be a mapping")
    banned = {"properties", "payload", "value", "raw"}
    if any(k in detail for k in banned):
        raise AuditKindError("detail carries banned keys")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": GRAPH_DATABASE_VERSION,
        "detail": dict(detail),
        "seq": seq,
    }


# ---------------------------------------------------------------------------
# The ledger
# ---------------------------------------------------------------------------


class GraphDatabase:
    """Neo4j-shaped multi-graph bookkeeping as a deterministic ledger.

    One instance hosts many *named* property graphs. All mutations take
    a caller-supplied int ``seq`` that must strictly increase; failed
    mutations consume their seq and book a ``rejected`` audit row, while
    rewinds (seq <= last seq) raise ``SeqOrderError`` bare, without
    consuming the seq or booking a row.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = -1
        # graph_name -> {"nodes": {id: (labels, properties_digest)},
        #                "edges": {id: (from, to, type, properties_digest)},
        #                "out": {node_id: [edge_id, ...]}}
        self._graphs: Dict[str, Dict[str, Any]] = {}
        self._retired: set = set()
        self._dropped: list = []
        self._audit: list = []

    # -- seq discipline -------------------------------------------------

    def _claim(self, seq: int) -> int:
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq {seq} did not exceed last seq {self._last_seq}"
            )
        self._last_seq = seq
        return seq

    def _reject(
        self, seq: int, reason: str, graph_name: str = ""
    ) -> Dict[str, Any]:
        row = graph_database_audit_event(
            KIND_REJECTED,
            {"reason": reason, "graph_name": graph_name},
            seq,
        )
        self._audit.append(row)
        return row

    def _active_graph(self, graph_name: str) -> Dict[str, Any]:
        graph_name = _check_graph_name(graph_name)
        graph = self._graphs.get(graph_name)
        if graph is None:
            raise UnknownGraphError(f"unknown graph: {graph_name}")
        return graph

    # -- graph lifecycle ------------------------------------------------

    def graph(self, graph_name: str, seq: int) -> GraphRecord:
        """Create a named graph.

        Duplicate and retired names are refused fail-closed.
        """
        with self._lock:
            self._claim(seq)
            try:
                graph_name = _check_graph_name(graph_name)
                if graph_name in self._graphs:
                    raise DuplicateGraphError(
                        f"graph already exists: {graph_name}"
                    )
                if graph_name in self._retired:
                    raise DuplicateGraphError(
                        f"graph name retired: {graph_name}"
                    )
            except GraphDatabaseError as exc:
                self._reject(seq, type(exc).__name__, graph_name)
                raise
            record = GraphRecord(
                graph_name=graph_name,
                digest=_pin("graph", graph_name, seq),
                seq=seq,
            )
            self._graphs[graph_name] = {
                "nodes": {},
                "edges": {},
                "out": {},
            }
            self._audit.append(
                graph_database_audit_event(
                    KIND_GRAPH_CREATED, {"graph_name": graph_name}, seq
                )
            )
            return record

    def drop(self, graph_name: str, seq: int, reason: str = "") -> DropRecord:
        """Terminally remove a named graph.

        The name is retired and may never be re-created. Unknown names
        fail closed with ``UnknownGraphError``.
        """
        with self._lock:
            self._claim(seq)
            try:
                if isinstance(reason, bool) or not isinstance(reason, str):
                    raise BadGraphError("reason must be str")
                graph = self._active_graph(graph_name)
            except GraphDatabaseError as exc:
                name = graph_name if isinstance(graph_name, str) else ""
                self._reject(seq, type(exc).__name__, name)
                raise
            record = DropRecord(
                graph_name=graph_name,
                reason=reason,
                digest=_pin("drop", graph_name, reason, seq),
                seq=seq,
            )
            nodes = len(graph["nodes"])
            edges = len(graph["edges"])
            del self._graphs[graph_name]
            self._retired.add(graph_name)
            self._dropped.append(record)
            self._audit.append(
                graph_database_audit_event(
                    KIND_GRAPH_DROPPED,
                    {
                        "graph_name": graph_name,
                        "reason": reason,
                        "nodes": nodes,
                        "edges": edges,
                    },
                    seq,
                )
            )
            return record

    # -- nodes ----------------------------------------------------------

    def node(
        self,
        graph_name: str,
        node_id: str,
        seq: int,
        labels: Tuple[str, ...] = (),
        properties: Optional[Mapping[str, Any]] = None,
    ) -> NodeRecord:
        """Pin a labelled node in one named graph.

        Property values are digest-pinned: raw values never enter the
        record or cross the audit boundary.
        """
        with self._lock:
            self._claim(seq)
            try:
                graph = self._active_graph(graph_name)
                node_id = _check_id(node_id, "node_id")
                checked_labels = _check_labels(labels)
                checked_props = _check_properties(properties)
                if node_id in graph["nodes"]:
                    raise DuplicateNodeError(
                        f"node already pinned: {node_id}"
                    )
            except GraphDatabaseError as exc:
                name = graph_name if isinstance(graph_name, str) else ""
                self._reject(seq, type(exc).__name__, name)
                raise
            properties_digest = _pin("properties", checked_props)
            record = NodeRecord(
                graph_name=graph_name,
                node_id=node_id,
                labels=checked_labels,
                properties_digest=properties_digest,
                digest=_pin(
                    "node",
                    graph_name,
                    node_id,
                    checked_labels,
                    properties_digest,
                    seq,
                ),
                seq=seq,
            )
            graph["nodes"][node_id] = (
                checked_labels,
                properties_digest,
            )
            graph["out"].setdefault(node_id, [])
            self._audit.append(
                graph_database_audit_event(
                    KIND_NODE_PINNED,
                    {
                        "graph_name": graph_name,
                        "node_id": node_id,
                        "labels": list(checked_labels),
                        "properties_digest": properties_digest,
                    },
                    seq,
                )
            )
            return record

    # -- edges ----------------------------------------------------------

    def edge(
        self,
        graph_name: str,
        edge_id: str,
        from_id: str,
        to_id: str,
        edge_type: str,
        seq: int,
        properties: Optional[Mapping[str, Any]] = None,
    ) -> EdgeRecord:
        """Pin a directed typed edge between two existing nodes.

        Both endpoints must be pinned nodes of the graph. Parallel edges
        (same ``from``/``to``/type) are refused; self-loops are allowed.
        """
        with self._lock:
            self._claim(seq)
            try:
                graph = self._active_graph(graph_name)
                edge_id = _check_id(edge_id, "edge_id")
                from_id = _check_id(from_id, "from_id")
                to_id = _check_id(to_id, "to_id")
                edge_type = _check_edge_type(edge_type)
                checked_props = _check_properties(properties)
                if edge_id in graph["edges"]:
                    raise DuplicateEdgeError(
                        f"edge already pinned: {edge_id}"
                    )
                if from_id not in graph["nodes"]:
                    raise UnknownNodeError(
                        f"unknown from node: {from_id}"
                    )
                if to_id not in graph["nodes"]:
                    raise UnknownNodeError(
                        f"unknown to node: {to_id}"
                    )
                for existing in graph["edges"].values():
                    if (
                        existing[0] == from_id
                        and existing[1] == to_id
                        and existing[2] == edge_type
                    ):
                        raise ParallelEdgeError(
                            f"parallel edge {from_id}->{to_id}"
                            f" [{edge_type}] already pinned"
                        )
            except GraphDatabaseError as exc:
                name = graph_name if isinstance(graph_name, str) else ""
                self._reject(seq, type(exc).__name__, name)
                raise
            properties_digest = _pin("properties", checked_props)
            record = EdgeRecord(
                graph_name=graph_name,
                edge_id=edge_id,
                from_node=from_id,
                to_node=to_id,
                edge_type=edge_type,
                properties_digest=properties_digest,
                digest=_pin(
                    "edge",
                    graph_name,
                    edge_id,
                    from_id,
                    to_id,
                    edge_type,
                    properties_digest,
                    seq,
                ),
                seq=seq,
            )
            graph["edges"][edge_id] = (
                from_id,
                to_id,
                edge_type,
                properties_digest,
            )
            graph["out"].setdefault(from_id, []).append(edge_id)
            self._audit.append(
                graph_database_audit_event(
                    KIND_EDGE_PINNED,
                    {
                        "graph_name": graph_name,
                        "edge_id": edge_id,
                        "from_node": from_id,
                        "to_node": to_id,
                        "edge_type": edge_type,
                        "properties_digest": properties_digest,
                    },
                    seq,
                )
            )
            return record

    # -- traversal --------------------------------------------------------

    def traverse(
        self,
        graph_name: str,
        start_id: str,
        seq: int,
        mode: str = "bfs",
        max_depth: int = 0,
        edge_types: Tuple[str, ...] = (),
        labels: Tuple[str, ...] = (),
    ) -> TraverseReport:
        """Deterministic visit order from ``start_id``.

        Pure read view: validates the seq shape, never consumes it, and
        writes no audit row. ``max_depth=0`` means unlimited depth.
        """
        _check_seq(seq)
        with self._lock:
            graph = self._active_graph(graph_name)
            start_id = _check_id(start_id, "start_id")
            mode = _check_mode(mode)
            max_depth = _check_depth(max_depth)
            edge_types = _check_labels(edge_types)
            label_filter = _check_labels(labels)
            if start_id not in graph["nodes"]:
                raise UnknownNodeError(
                    f"unknown start node: {start_id}"
                )
            visited: list = [start_id]
            seen = {start_id}
            frontier = [(start_id, 0)]
            while frontier:
                current, depth = (
                    frontier.pop() if mode == "dfs" else frontier.pop(0)
                )
                if max_depth and depth >= max_depth:
                    continue
                edge_ids = sorted(graph["out"].get(current, ()))
                neighbors = []
                for edge_id in edge_ids:
                    src, dst, etype, _ = graph["edges"][edge_id]
                    if edge_types and etype not in edge_types:
                        continue
                    if dst in seen:
                        continue
                    node_labels, _ = graph["nodes"][dst]
                    if label_filter and not set(label_filter) & set(
                        node_labels
                    ):
                        seen.add(dst)
                        continue
                    seen.add(dst)
                    neighbors.append(dst)
                for node_id in neighbors:
                    visited.append(node_id)
                frontier.extend((n, depth + 1) for n in neighbors)
            return TraverseReport(
                graph_name=graph_name,
                start_id=start_id,
                mode=mode,
                max_depth=max_depth,
                visited=tuple(visited),
                edge_count=len(graph["edges"]),
                seq=seq,
                schema=GRAPH_DATABASE_SCHEMA,
            )

    # -- pure views -------------------------------------------------------

    def node_view(
        self, graph_name: str, node_id: str
    ) -> Optional[NodeView]:
        """Labels of one pinned node, or None."""
        with self._lock:
            graph_name = _check_graph_name(graph_name)
            node_id = _check_id(node_id, "node_id")
            graph = self._graphs.get(graph_name)
            if graph is None:
                return None
            entry = graph["nodes"].get(node_id)
            if entry is None:
                return None
            return NodeView(
                graph_name=graph_name,
                node_id=node_id,
                labels=entry[0],
                schema=GRAPH_DATABASE_SCHEMA,
            )

    def edge_view(
        self, graph_name: str, edge_id: str
    ) -> Optional[EdgeView]:
        """Endpoints and type of one pinned edge, or None."""
        with self._lock:
            graph_name = _check_graph_name(graph_name)
            edge_id = _check_id(edge_id, "edge_id")
            graph = self._graphs.get(graph_name)
            if graph is None:
                return None
            entry = graph["edges"].get(edge_id)
            if entry is None:
                return None
            return EdgeView(
                graph_name=graph_name,
                edge_id=edge_id,
                from_node=entry[0],
                to_node=entry[1],
                edge_type=entry[2],
                schema=GRAPH_DATABASE_SCHEMA,
            )

    def graph_names(self) -> Tuple[str, ...]:
        """Active graph names, sorted."""
        with self._lock:
            return tuple(sorted(self._graphs.keys()))

    def node_ids(self, graph_name: str) -> Tuple[str, ...]:
        """Pinned node ids of one graph, sorted."""
        with self._lock:
            graph = self._active_graph(graph_name)
            return tuple(sorted(graph["nodes"].keys()))

    def edge_ids(self, graph_name: str) -> Tuple[str, ...]:
        """Pinned edge ids of one graph, sorted."""
        with self._lock:
            graph = self._active_graph(graph_name)
            return tuple(sorted(graph["edges"].keys()))

    def neighbors(
        self, graph_name: str, node_id: str
    ) -> Tuple[str, ...]:
        """Sorted ids reachable by one outgoing edge."""
        with self._lock:
            graph = self._active_graph(graph_name)
            node_id = _check_id(node_id, "node_id")
            if node_id not in graph["nodes"]:
                raise UnknownNodeError(f"unknown node: {node_id}")
            return tuple(
                sorted(
                    graph["edges"][edge_id][1]
                    for edge_id in graph["out"].get(node_id, ())
                )
            )

    def stats(self) -> DbStats:
        """Ledger counters."""
        with self._lock:
            return DbStats(
                graphs=len(self._graphs),
                dropped=len(self._dropped),
                nodes=sum(len(g["nodes"]) for g in self._graphs.values()),
                edges=sum(len(g["edges"]) for g in self._graphs.values()),
                schema=GRAPH_DATABASE_SCHEMA,
            )

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        """All audit rows in booking order."""
        with self._lock:
            return tuple(self._audit)


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------


def main() -> None:
    """Deterministic self-check: graph, node, edge, traverse, drop."""
    db = GraphDatabase()
    digest = "sha256:" + "cd" * 32
    rec = db.graph("movies", 1)
    assert rec.verify() and rec.schema == GRAPH_DATABASE_SCHEMA
    db.node("movies", "keanu", 2, labels=("Person",),
            properties={"born": 1964})
    db.node("movies", "matrix", 3, labels=("Movie",),
            properties={"year": 1999})
    db.node("movies", "johnwick", 4, labels=("Movie",))
    edge = db.edge("movies", "e1", "keanu", "matrix", "ACTED_IN", 5)
    assert edge.verify()
    # parallel edge refused
    try:
        db.edge("movies", "eX", "keanu", "matrix", "ACTED_IN", 6)
        raise AssertionError("expected ParallelEdgeError")
    except ParallelEdgeError:
        pass
    # self-loop allowed
    db.edge("movies", "e2", "keanu", "keanu", "KNOWS", 7)
    # bfs visit order is deterministic (self-loop skips seen nodes)
    report = db.traverse("movies", "keanu", 8)
    assert report.visited == ("keanu", "matrix"), report.visited
    # dfs from matrix with only ACTED_IN edges
    db.edge("movies", "e3", "keanu", "johnwick", "ACTED_IN", 9)
    filtered = db.traverse("movies", "keanu", 10, mode="dfs",
                           edge_types=("ACTED_IN",))
    assert "matrix" in filtered.visited and "johnwick" in filtered.visited
    # label filter restricts reached nodes
    only_movies = db.traverse("movies", "keanu", 11,
                              labels=("Movie",))
    assert only_movies.visited[0] == "keanu"
    assert set(only_movies.visited) == {"keanu", "matrix", "johnwick"}
    # stats + drop
    stats = db.stats()
    assert (stats.graphs, stats.nodes, stats.edges) == (1, 3, 3)
    dropped = db.drop("movies", 12, "test cleanup")
    assert dropped.verify()
    assert db.stats().graphs == 0
    try:
        db.node("movies", "neo", 13)
        raise AssertionError("expected UnknownGraphError")
    except UnknownGraphError:
        pass
    print("graph-database OK: graph, node, edge, traverse, drop, pins, audit")


if __name__ == "__main__":
    main()
