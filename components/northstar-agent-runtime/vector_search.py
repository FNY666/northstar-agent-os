"""HNSW-shaped approximate nearest-neighbor index bookkeeping.

Research note: vector search is the retrieval backbone of RAG pipelines
and memory-augmented agents (Lewis et al., 2020, "Retrieval-Augmented
Generation"). Production systems approximate nearest-neighbor search with
index structures -- IVF (Jegou et al., 2011), HNSW (Malkov & Yashunin,
2018), PQ quantization -- trading exactness for sub-linear query cost.

This module is deliberately distinct from ``vector_db.py``. That module is
the *exact brute-force oracle* (``upsert`` / ``search`` / ``delete`` over
every stored vector). This module books the *approximate index layer* that
sits above such an oracle:

* **Levels** -- each inserted vector is assigned a layer level by the HNSW
  rule ``floor(-ln(u) * ml)`` with ``ml = 1 / ln(m)``, but the uniform draw
  ``u`` is derived deterministically from ``sha256("hnsw-level:" +
  vector_id)``. No RNG anywhere: identical insert sequences build
  byte-identical graphs on every replica, so index construction is
  replay-auditable.
* **Graph** -- multi-layer neighbor links, capped at ``m`` per layer
  (``2 * m`` at layer 0, the HNSW convention), pruned by distance with
  deterministic id tie-breaks. Links are bidirectional bookings; deleting
  a vector tombstones it and prunes its links, and the id is retired
  forever (never recycled).
* **Query** -- ``nearest()`` runs the HNSW beam search: greedy 1-best
  descent from the entry point through the upper layers, then an
  ``ef``-width beam at layer 0. The returned :class:`QueryReport` carries
  the approximate top-k *and* ``recall_at_k`` measured against the exact
  top-k computed in-module -- the same oracle relationship the
  ``vector_db`` docstring describes. Recall is data, never a gate: a low
  recall books honestly instead of raising.
* **Fail-closed vectors** -- zero vectors are rejected for cosine (no
  direction, similarity undefined); NaN/inf, bool elements, wrong
  dimension, and non-sequence vectors are rejected as programming errors.
  Bool ids and bool seqs are rejected everywhere.

House discipline: frozen dataclasses, caller int seqs strictly increasing
on mutations (failed mutations consume their seq and book
``vector-search.rejected``; rewinds raise bare without consuming),
no wall-clock, RLock-guarded, fail-closed taxonomy, stdlib-only
(``canonical_json`` sibling helper behind the standard try/except
fallback), ``sha256:`` digest pins, ``audit.ndjson/1`` events.

Honest scope: this is single-host index bookkeeping, not a production
ANN engine. It cannot prove a vector is a faithful embedding of any text
(stores host-reported floats), it cannot bound query latency (the beam
search is a faithful *simulation* of HNSW traversal, not a tuned
implementation), and it persists nothing across processes. A booked
``inserted`` row means the graph links were recorded, not that any
external index acknowledged them. ``recall_at_k`` measures this index
against exact search over *reported* embeddings, never ground-truth
similarity. Pair with a durable audit writer for crash recovery.

Version pin: vector-search.v1
Schema pin: northstar.vector-search.v1
"""

from __future__ import annotations

import hashlib
import heapq
import math
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Set, Tuple

try:  # stdlib-first; canonical_json is the sibling JCS helper
    import canonical_json as _cj  # type: ignore
except Exception:  # pragma: no cover - fallback keeps stdlib-only promise
    _cj = None  # type: ignore

#: Module version pin. Bump on any semantic change.
VECTOR_SEARCH_VERSION = "vector-search.v1"

#: Schema pin for records produced by this module.
VECTOR_SEARCH_SCHEMA = "northstar.vector-search.v1"

#: Supported distance metrics (lower is closer for both).
METRICS = ("euclidean", "cosine")

#: Audit event kinds.
_AUDIT_KINDS = ("inserted", "queried", "deleted", "rejected")

#: Hard cap on HNSW layer levels (prevents degenerate deep graphs).
MAX_LEVEL = 16


class VectorSearchError(Exception):
    """Base error for vector-search misuse."""


class BadIdError(VectorSearchError):
    """A vector id failed validation (empty or non-string)."""


class DuplicateVectorError(VectorSearchError):
    """An insert named an id that is already booked (live or retired)."""


class UnknownVectorError(VectorSearchError):
    """A lookup named an id that is not booked."""


class BadVectorError(VectorSearchError):
    """A vector failed validation (dimension, NaN/inf, bool, zero)."""


class BadParamError(VectorSearchError):
    """An index/query parameter failed validation (m, ef, k, level)."""


class BadMetricError(VectorSearchError):
    """An unknown distance metric was requested."""


class SeqOrderError(VectorSearchError):
    """A caller seq was malformed or not strictly increasing."""


class AuditKindError(VectorSearchError):
    """An unknown audit kind was requested."""


def _check_seq_shape(seq: Any) -> int:
    """Validate seq shape only; never consumes."""
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError(f"seq must be an int, got {type(seq).__name__}")
    if seq < 0:
        raise SeqOrderError(f"seq must be non-negative, got {seq}")
    return seq


def _check_id(vector_id: Any) -> str:
    """Validate a vector id; fail closed."""
    if isinstance(vector_id, bool) or not isinstance(vector_id, str):
        raise BadIdError(f"id must be a str, got {type(vector_id).__name__}")
    if not vector_id:
        raise BadIdError("id must be non-empty")
    if len(vector_id) > 256:
        raise BadIdError("id must be at most 256 chars")
    return vector_id


def _check_dim(dim: Any) -> int:
    """Validate the space dimension; fail closed."""
    if isinstance(dim, bool) or not isinstance(dim, int):
        raise VectorSearchError(f"dim must be an int, got {type(dim).__name__}")
    if dim <= 0:
        raise VectorSearchError(f"dim must be positive, got {dim}")
    return dim


def _check_m(m: Any) -> int:
    """Validate the HNSW max-neighbor parameter; fail closed."""
    if isinstance(m, bool) or not isinstance(m, int):
        raise BadParamError(f"m must be an int, got {type(m).__name__}")
    if m < 2 or m > 128:
        raise BadParamError(f"m must be in [2, 128], got {m}")
    return m


def _check_k(k: Any) -> int:
    """Validate top-k; fail closed."""
    if isinstance(k, bool) or not isinstance(k, int):
        raise BadParamError(f"k must be an int, got {type(k).__name__}")
    if k <= 0:
        raise BadParamError(f"k must be positive, got {k}")
    return k


def _check_ef(ef: Any, k: int) -> int:
    """Validate the beam width; fail closed (HNSW requires ef >= k)."""
    if isinstance(ef, bool) or not isinstance(ef, int):
        raise BadParamError(f"ef must be an int, got {type(ef).__name__}")
    if ef < k:
        raise BadParamError(f"ef ({ef}) must be >= k ({k})")
    if ef > 4096:
        raise BadParamError(f"ef must be <= 4096, got {ef}")
    return ef


def _check_vector(values: Any, dim: int, *, metric: str) -> Tuple[float, ...]:
    """Validate and normalize a vector; fail closed.

    Rejects: non-sequences, wrong dimension, NaN/inf, bool elements,
    non-numeric elements. The zero vector is rejected for cosine (no
    direction, similarity undefined) and allowed for euclidean.
    """
    if isinstance(values, (str, bytes)):
        raise BadVectorError("vector must be a sequence of numbers, not str/bytes")
    try:
        items = tuple(values)
    except TypeError:
        raise BadVectorError(
            f"vector must be a sequence, got {type(values).__name__}"
        ) from None
    if len(items) != dim:
        raise BadVectorError(f"vector has dimension {len(items)}, expected {dim}")
    out: List[float] = []
    for i, v in enumerate(items):
        if isinstance(v, bool):
            raise BadVectorError(f"vector[{i}]: bool is not a valid component")
        if not isinstance(v, (int, float)):
            raise BadVectorError(
                f"vector[{i}]: expected a number, got {type(v).__name__}"
            )
        f = float(v)
        if not math.isfinite(f):
            raise BadVectorError(f"vector[{i}]: NaN/inf not allowed")
        out.append(f)
    if metric == "cosine" and all(f == 0.0 for f in out):
        raise BadVectorError("zero vector has no direction (cosine undefined)")
    return tuple(out)


def _canonical_bytes(obj: Any) -> bytes:
    """Canonical-encode for digest pinning (JCS when available)."""
    if _cj is not None:
        dumped = _cj.jcs_dumps(obj)
        return dumped.encode("utf-8") if isinstance(dumped, str) else bytes(dumped)
    import json

    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _pin(*parts: Any) -> str:
    """Domain-separated sha256 pin over canonical parts."""
    h = hashlib.sha256()
    h.update(b"northstar.vector-search.v1\x1f")
    for p in parts:
        h.update(_canonical_bytes(p))
        h.update(b"\x1f")
    return "sha256:" + h.hexdigest()


def _vector_digest(vector_id: str, dim: int, vector: Tuple[float, ...]) -> str:
    """Pin a stored vector (floats canonicalized with repr, exact for IEEE)."""
    return _pin({"id": vector_id, "dim": dim, "v": [repr(f) for f in vector]})


def _distance(metric: str, a: Tuple[float, ...], b: Tuple[float, ...]) -> float:
    """Distance between two validated vectors (lower is closer)."""
    if metric == "euclidean":
        return math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b)))
    # cosine distance = 1 - cosine similarity; zero vectors rejected at input
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0.0 or nb == 0.0:  # pragma: no cover - rejected at input
        raise BadVectorError("zero vector has no direction (cosine undefined)")
    return 1.0 - dot / (na * nb)


def _assign_level(vector_id: str, m: int) -> int:
    """Deterministic HNSW level: floor(-ln(u) * ml), u from sha256 (no RNG)."""
    digest = hashlib.sha256(f"hnsw-level:{vector_id}".encode("utf-8")).digest()
    u = int.from_bytes(digest, "big") / 2**256
    if u <= 0.0:
        u = 2**-256
    if u >= 1.0:  # pragma: no cover - sha256 output < 2**256 always
        u = 1.0 - 2**-256
    ml = 1.0 / math.log(m)
    level = int(math.floor(-math.log(u) * ml))
    return min(max(level, 0), MAX_LEVEL)


@dataclass(frozen=True)
class VectorRecord:
    """One booked vector: id, validated components, HNSW level, digest pin."""

    version: str
    vector_id: str
    dim: int
    vector: Tuple[float, ...]
    level: int
    digest: str
    seq: int

    def verify(self) -> bool:
        """Recompute the digest pin; True iff the record is untampered."""
        return self.digest == _vector_digest(self.vector_id, self.dim, self.vector)


@dataclass(frozen=True)
class NeighborRecord:
    """One nearest-neighbor hit: id, distance (lower is closer), rank."""

    version: str
    vector_id: str
    distance: float
    rank: int


@dataclass(frozen=True)
class InsertRecord:
    """Booking of one insert: level, per-layer neighbor lists, digest."""

    version: str
    vector_id: str
    level: int
    layer_neighbors: Tuple[Tuple[str, ...], ...]  # index i = layer i, closest-first
    digest: str
    seq: int


@dataclass(frozen=True)
class QueryReport:
    """Booking of one approximate query: top-k, beam stats, recall vs exact."""

    version: str
    metric: str
    k: int
    ef: int
    neighbors: Tuple[NeighborRecord, ...]
    recall_at_k: float
    candidates_visited: int
    digest: str
    seq: int


@dataclass(frozen=True)
class DeleteRecord:
    """Tombstone booking: id retired forever, digest of the removed vector."""

    version: str
    vector_id: str
    digest: str
    seq: int


class VectorSearch:
    """HNSW-shaped approximate nearest-neighbor index (bookkeeping layer).

    Owns one fixed-dimension space (``dim`` set at construction). ``m``
    caps neighbor links per layer (``2 * m`` at layer 0, the HNSW
    convention); ``metric`` is ``euclidean`` or ``cosine`` and never
    changes for the life of the index.
    """

    def __init__(self, dim: int, m: int = 16, metric: str = "euclidean") -> None:
        self._dim = _check_dim(dim)
        self._m = _check_m(m)
        if metric not in METRICS:
            raise BadMetricError(f"unknown metric {metric!r}; expected one of {METRICS}")
        self._metric = metric
        self._lock = threading.RLock()
        self._seq = -1
        # vector_id -> {"vector": tuple, "level": int, "links": {layer: [ids]}, "deleted": bool, "seq": int}
        self._nodes: Dict[str, Dict[str, Any]] = {}
        self._retired: Set[str] = set()
        self._entry_id: Optional[str] = None  # highest-level live node
        self._audit: List[Dict[str, Any]] = []

    # -- internal helpers -------------------------------------------------

    def _audit_row(self, kind: str, seq: int, **detail: Any) -> None:
        self._audit.append(
            {
                "schema": "audit.ndjson/1",
                "kind": f"vector-search.{kind}",
                "module": VECTOR_SEARCH_SCHEMA,
                "version": VECTOR_SEARCH_VERSION,
                "seq": seq,
                **detail,
            }
        )

    def _claim(self, seq: int) -> int:
        """Claim a mutation seq: rewinds raise bare; callers burn on failure."""
        _check_seq_shape(seq)
        if seq <= self._seq:
            raise SeqOrderError(
                f"seq must be strictly increasing; got {seq} after {self._seq}"
            )
        return seq

    def _reject(self, seq: int, error: VectorSearchError) -> VectorSearchError:
        """Burn the seq and book a rejection audit row, then raise."""
        self._seq = seq
        self._audit_row("rejected", seq, error=type(error).__name__)
        return error

    def _live_ids(self) -> List[str]:
        return sorted(vid for vid, n in self._nodes.items() if not n["deleted"])

    def _max_live_level(self) -> int:
        levels = [n["level"] for n in self._nodes.values() if not n["deleted"]]
        return max(levels) if levels else -1

    def _dist_to(self, query: Tuple[float, ...], vector_id: str) -> float:
        return _distance(self._metric, query, self._nodes[vector_id]["vector"])

    def _search_layer(
        self,
        query: Tuple[float, ...],
        entry_ids: List[str],
        ef: int,
        layer: int,
    ) -> List[Tuple[float, str]]:
        """HNSW beam search over one layer's booked graph (Algorithm 2).

        Returns up to ``ef`` (distance, vector_id) pairs, distance-ascending,
        id tie-broken. Tombstoned nodes are never returned.
        """
        live = {vid for vid in self._live_ids()}
        entries = [vid for vid in entry_ids if vid in live]
        if not entries:
            return []
        visited = set(entries)
        # candidates: min-heap of (dist, vid) to expand
        candidates = [(self._dist_to(query, vid), vid) for vid in entries]
        heapq.heapify(candidates)
        # results: max-heap via negative dist of the ef best so far
        best: List[Tuple[float, str]] = []  # (-dist, vid)
        for dist, vid in candidates:
            if len(best) < ef:
                heapq.heappush(best, (-dist, vid))
            elif dist < -best[0][0]:
                heapq.heapreplace(best, (-dist, vid))
        while candidates:
            dist_c, c = heapq.heappop(candidates)
            if best and dist_c > -best[0][0]:
                break
            for nb in self._nodes[c]["links"].get(layer, []):
                if nb in visited or nb not in live:
                    continue
                visited.add(nb)
                dist_nb = self._dist_to(query, nb)
                if len(best) < ef:
                    heapq.heappush(best, (-dist_nb, nb))
                    heapq.heappush(candidates, (dist_nb, nb))
                elif dist_nb < -best[0][0] or (
                    dist_nb == -best[0][0] and nb < best[0][1]
                ):
                    heapq.heapreplace(best, (-dist_nb, nb))
                    heapq.heappush(candidates, (dist_nb, nb))
        out = sorted(((-neg, vid) for neg, vid in best), key=lambda t: (t[0], t[1]))
        return out

    def _refresh_entry(self) -> None:
        """Recompute the entry point: highest level, id tie-break."""
        best: Optional[str] = None
        best_level = -1
        for vid in self._live_ids():
            lvl = self._nodes[vid]["level"]
            if lvl > best_level or (lvl == best_level and (best is None or vid < best)):
                best, best_level = vid, lvl
        self._entry_id = best

    # -- mutations ----------------------------------------------------------

    def insert(self, vector_id: str, vector: Any, seq: int) -> InsertRecord:
        """Book one vector into the HNSW-shaped index.

        Assigns the deterministic level, descends the upper layers to
        find the entry layer, then books bidirectional neighbor links per
        layer (capped at ``m``, ``2 * m`` at layer 0, distance-pruned).
        Duplicate or retired ids are refused fail-closed.
        """
        seq = self._claim(seq)
        with self._lock:
            try:
                vid = _check_id(vector_id)
                if vid in self._nodes or vid in self._retired:
                    raise DuplicateVectorError(f"vector id {vid!r} already booked")
                vec = _check_vector(vector, self._dim, metric=self._metric)
            except VectorSearchError as exc:
                raise self._reject(seq, exc) from None
            level = _assign_level(vid, self._m)
            old_top = self._max_live_level()  # before the new node joins
            old_entry = self._entry_id
            self._nodes[vid] = {
                "vector": vec,
                "level": level,
                "links": {},
                "deleted": False,
                "seq": seq,
            }
            layer_map: Dict[int, Tuple[str, ...]] = {}
            if old_entry is None:
                # First node: entry point, no links.
                self._entry_id = vid
            else:
                entry = old_entry
                # Greedy 1-best descent through layers above the new level.
                for layer in range(old_top, level, -1):
                    found = self._search_layer(vec, [entry], 1, layer)
                    if found:
                        entry = found[0][1]
                # Book neighbors on each populated layer up to the new level.
                for layer in range(min(level, old_top), -1, -1):
                    cap = 2 * self._m if layer == 0 else self._m
                    cands = self._search_layer(vec, [entry], self._m * 4, layer)
                    chosen = [cvid for _, cvid in cands[:cap]]
                    self._nodes[vid]["links"][layer] = chosen
                    for cvid in chosen:
                        links = self._nodes[cvid]["links"].setdefault(layer, [])
                        if vid not in links:
                            links.append(vid)
                        # Prune to cap by distance, id tie-break.
                        if len(links) > cap:
                            scored = sorted(
                                (
                                    self._dist_to(
                                        self._nodes[cvid]["vector"], other
                                    ),
                                    other,
                                )
                                for other in links
                            )
                            self._nodes[cvid]["links"][layer] = [
                                other for _, other in scored[:cap]
                            ]
                    layer_map[layer] = tuple(chosen)
                    if cands:
                        entry = cands[0][1]
                if level > old_top:
                    self._entry_id = vid
            per_layer = tuple(layer_map.get(layer, ()) for layer in range(level + 1))
            digest = _vector_digest(vid, self._dim, vec)
            self._seq = seq
            self._audit_row(
                "inserted",
                seq,
                vector_id=vid,
                level=level,
                digest=digest,
            )
            return InsertRecord(
                version=VECTOR_SEARCH_VERSION,
                vector_id=vid,
                level=level,
                layer_neighbors=tuple(per_layer),
                digest=digest,
                seq=seq,
            )

    def delete(self, vector_id: str, seq: int) -> DeleteRecord:
        """Tombstone a vector: prune its links, retire the id forever.

        Unknown ids raise :class:`UnknownVectorError` fail-closed. A
        retired id can never be re-inserted (re-insertion is refused as
        a duplicate).
        """
        seq = self._claim(seq)
        with self._lock:
            try:
                vid = _check_id(vector_id)
                node = self._nodes.get(vid)
                if node is None or node["deleted"]:
                    raise UnknownVectorError(f"unknown vector id {vid!r}")
            except VectorSearchError as exc:
                raise self._reject(seq, exc) from None
            digest = _vector_digest(vid, self._dim, node["vector"])
            # Prune links pointing at the tombstoned node.
            for other_id, other in self._nodes.items():
                if other_id == vid or other["deleted"]:
                    continue
                for layer, links in other["links"].items():
                    if vid in links:
                        links.remove(vid)
            node["links"] = {}
            node["deleted"] = True
            self._retired.add(vid)
            self._refresh_entry()
            self._seq = seq
            self._audit_row("deleted", seq, vector_id=vid, digest=digest)
            return DeleteRecord(
                version=VECTOR_SEARCH_VERSION,
                vector_id=vid,
                digest=digest,
                seq=seq,
            )

    # -- reads ----------------------------------------------------------------

    def nearest(
        self, query: Any, k: int, seq: int, ef: int = 50
    ) -> QueryReport:
        """Approximate top-k via HNSW beam search (pure read).

        Runs greedy 1-best descent from the entry point through the upper
        layers, then an ``ef``-width beam at layer 0. ``recall_at_k`` is
        measured against the exact top-k computed in-module and returned
        as data. An empty index yields zero neighbors (valid state, not
        an error). The seq is validated but never consumed.
        """
        _check_seq_shape(seq)
        if self._metric not in METRICS:  # pragma: no cover - fixed at init
            raise BadMetricError(f"unknown metric {self._metric!r}")
        vec = _check_vector(query, self._dim, metric=self._metric)
        k = _check_k(k)
        ef = _check_ef(ef, k)
        with self._lock:
            live = self._live_ids()
            if not live or self._entry_id is None:
                neighbors: Tuple[NeighborRecord, ...] = ()
                visited = 0
            else:
                entry = self._entry_id
                top = self._max_live_level()
                for layer in range(top, 0, -1):
                    found = self._search_layer(vec, [entry], 1, layer)
                    if found:
                        entry = found[0][1]
                beam = self._search_layer(vec, [entry], ef, 0)
                visited = len(beam)
                neighbors = tuple(
                    NeighborRecord(
                        version=VECTOR_SEARCH_VERSION,
                        vector_id=cvid,
                        distance=dist,
                        rank=rank,
                    )
                    for rank, (dist, cvid) in enumerate(beam[:k])
                )
            # Exact oracle for recall measurement (same metric, id tie-break).
            exact = sorted(
                ((self._dist_to(vec, vid), vid) for vid in live),
                key=lambda t: (t[0], t[1]),
            )
            exact_ids = {vid for _, vid in exact[:k]}
            approx_ids = {n.vector_id for n in neighbors}
            denom = min(k, len(live))
            recall = len(approx_ids & exact_ids) / denom if denom else 1.0
            digest = _pin(
                {
                    "query": [repr(f) for f in vec],
                    "k": k,
                    "ef": ef,
                    "hits": [n.vector_id for n in neighbors],
                    "recall": recall,
                }
            )
            return QueryReport(
                version=VECTOR_SEARCH_VERSION,
                metric=self._metric,
                k=k,
                ef=ef,
                neighbors=neighbors,
                recall_at_k=recall,
                candidates_visited=visited,
                digest=digest,
                seq=seq,
            )

    def vector_record(self, vector_id: str) -> VectorRecord:
        """Fetch one booked vector (tombstoned ids raise UnknownVectorError)."""
        vid = _check_id(vector_id)
        with self._lock:
            node = self._nodes.get(vid)
            if node is None or node["deleted"]:
                raise UnknownVectorError(f"unknown vector id {vid!r}")
            return VectorRecord(
                version=VECTOR_SEARCH_VERSION,
                vector_id=vid,
                dim=self._dim,
                vector=node["vector"],
                level=node["level"],
                digest=_vector_digest(vid, self._dim, node["vector"]),
                seq=node["seq"],
            )

    def ids(self) -> Tuple[str, ...]:
        """Sorted ids of live (non-tombstoned) vectors."""
        with self._lock:
            return tuple(self._live_ids())

    def size(self) -> int:
        """Count of live vectors."""
        with self._lock:
            return len(self._live_ids())

    def links(self, vector_id: str, layer: int) -> Tuple[str, ...]:
        """Booked neighbor links of one vector on one layer (pure read)."""
        vid = _check_id(vector_id)
        if isinstance(layer, bool) or not isinstance(layer, int) or layer < 0:
            raise BadParamError(f"layer must be a non-negative int, got {layer!r}")
        with self._lock:
            node = self._nodes.get(vid)
            if node is None or node["deleted"]:
                raise UnknownVectorError(f"unknown vector id {vid!r}")
            return tuple(node["links"].get(layer, ()))

    def stats(self, seq: int) -> Mapping[str, Any]:
        """Pure read view: size, max level, entry point, ledger seq."""
        _check_seq_shape(seq)
        with self._lock:
            return {
                "version": VECTOR_SEARCH_VERSION,
                "dim": self._dim,
                "m": self._m,
                "metric": self._metric,
                "size": len(self._live_ids()),
                "max_level": self._max_live_level(),
                "entry_id": self._entry_id,
                "ledger_seq": self._seq,
            }

    def audit_log(self) -> Tuple[Mapping[str, Any], ...]:
        """Booked audit rows (oldest first)."""
        with self._lock:
            return tuple(dict(row) for row in self._audit)


def vector_search_audit_event(kind: str, index: VectorSearch, seq: int) -> dict:
    """Shape a vector-search lifecycle event as an ``audit.ndjson/1`` record.

    Raw vector components never cross the audit boundary: only ids,
    counts, levels, and digest pins are reported.
    """
    if kind not in _AUDIT_KINDS:
        raise AuditKindError(f"kind must be one of {sorted(_AUDIT_KINDS)}")
    if not isinstance(index, VectorSearch):
        raise TypeError("index must be a VectorSearch")
    _check_seq_shape(seq)
    return {
        "schema": "audit.ndjson/1",
        "kind": f"vector-search.{kind}",
        "module": VECTOR_SEARCH_SCHEMA,
        "version": VECTOR_SEARCH_VERSION,
        "seq": seq,
        "size": index.size(),
        "dim": index._dim,
        "max_level": index._max_live_level(),
    }


def main() -> None:
    """Self-check: insert graph, approximate query with recall, delete."""
    idx = VectorSearch(2)
    assert idx.size() == 0 and idx.ids() == ()

    r1 = idx.insert("a", (1.0, 0.0), 0)
    assert r1.level == _assign_level("a", 16) and r1.digest.startswith("sha256:")
    assert len(r1.layer_neighbors) == r1.level + 1
    assert all(n == () for n in r1.layer_neighbors)  # first node: no links yet
    r2 = idx.insert("b", (0.0, 1.0), 1)
    assert r2.digest.startswith("sha256:")
    # Second node links back to the first on layer 0.
    assert "a" in r2.layer_neighbors[0]
    assert "b" in idx.links("a", 0)

    got = idx.vector_record("a")
    assert got.vector == (1.0, 0.0) and got.verify()

    rep = idx.nearest((1.0, 0.1), 2, 2)
    assert rep.k == 2 and len(rep.neighbors) == 2
    assert rep.neighbors[0].vector_id == "a" and rep.neighbors[0].rank == 0
    assert 0.0 <= rep.recall_at_k <= 1.0
    assert rep.digest.startswith("sha256:")
    # Deterministic: a fresh index with the same inserts answers identically.
    idx2 = VectorSearch(2)
    idx2.insert("a", (1.0, 0.0), 0)
    idx2.insert("b", (0.0, 1.0), 1)
    rep2 = idx2.nearest((1.0, 0.1), 2, 2)
    assert [n.vector_id for n in rep2.neighbors] == [
        n.vector_id for n in rep.neighbors
    ]

    empty = VectorSearch(3)
    assert empty.nearest((1.0, 0.0, 0.0), 5, 0).neighbors == ()

    d = idx.delete("a", 3)
    assert d.digest.startswith("sha256:") and idx.size() == 1
    assert idx.ids() == ("b",)
    # Tombstoned id is retired: re-insert refused, lookup refused.
    for bad, exc in [
        (lambda: idx.insert("a", (1.0, 0.0), 4), DuplicateVectorError),
        (lambda: idx.delete("a", 4), SeqOrderError),  # seq 4 burned above
        (lambda: idx.delete("zz", 4), SeqOrderError),  # rewind, bare
        (lambda: idx.vector_record("a"), UnknownVectorError),
    ]:
        try:
            bad()
        except exc:
            pass
        else:  # pragma: no cover
            raise AssertionError(f"expected {exc.__name__}")
    # Failed delete consumed its seq: next valid seq must exceed 4.
    try:
        idx.insert("c", (0.5, 0.5), 4)
    except SeqOrderError:
        pass
    else:  # pragma: no cover
        raise AssertionError("expected SeqOrderError after burned seq")
    idx.insert("c", (0.5, 0.5), 5)
    assert idx.size() == 2

    # Refusals (fresh seq per case: failed mutations burn their seq).
    seq = 6
    refusal_cases = [
        (lambda s: idx.insert("", (1.0, 0.0), s), BadIdError),
        (lambda s: idx.insert(True, (1.0, 0.0), s), BadIdError),
        (lambda s: idx.insert("x", (1.0,), s), BadVectorError),
        (lambda s: idx.insert("x", (1.0, float("nan")), s), BadVectorError),
        (lambda s: idx.insert("x", (1.0, True), s), BadVectorError),
        (lambda s: idx.insert("x", (1.0, 0.0), True), SeqOrderError),
        (lambda s: idx.nearest((1.0, 0.0), 0, s), BadParamError),
        (lambda s: idx.nearest((1.0, 0.0), 2, s, ef=1), BadParamError),
        (lambda s: idx.nearest((1.0,), 2, s), BadVectorError),
        (lambda s: idx.links("b", -1), BadParamError),
    ]
    for bad, exc in refusal_cases:
        try:
            bad(seq)
        except exc:
            pass
        else:  # pragma: no cover
            raise AssertionError(f"expected {exc.__name__}")
        seq += 1
    for bad, exc in [
        (lambda: VectorSearch(0), VectorSearchError),
        (lambda: VectorSearch(True), VectorSearchError),
        (lambda: VectorSearch(2, m=1), BadParamError),
        (lambda: VectorSearch(2, metric="manhattan"), BadMetricError),
        (
            lambda: vector_search_audit_event("bogus", idx, seq),
            AuditKindError,
        ),
    ]:
        try:
            bad()
        except exc:
            pass
        else:  # pragma: no cover
            raise AssertionError(f"expected {exc.__name__}")

    # Cosine index rejects the zero vector.
    cidx = VectorSearch(2, metric="cosine")
    try:
        cidx.insert("z", (0.0, 0.0), 0)
    except BadVectorError:
        pass
    else:  # pragma: no cover
        raise AssertionError("expected BadVectorError for zero vector")
    cidx.insert("p", (1.0, 0.0), 1)  # seq 0 burned by the refused zero vector
    crep = cidx.nearest((1.0, 0.0), 1, 2)
    assert crep.neighbors[0].vector_id == "p"
    assert crep.neighbors[0].distance == 0.0

    ev = vector_search_audit_event("inserted", idx, 5)
    assert ev["kind"] == "vector-search.inserted"
    assert ev["schema"] == "audit.ndjson/1"
    assert "vector" not in ev and "payload" not in ev

    print("vector-search OK: insert graph, beam query, recall, delete, refusals")


if __name__ == "__main__":
    main()
