"""Brute-force vector database interface for embedding search.

Research note: vector search is the retrieval backbone of RAG pipelines and
memory-augmented agents (Lewis et al., 2020, "Retrieval-Augmented
Generation"). Production systems approximate nearest-neighbor search with
index structures -- IVF (Jegou et al., 2011), HNSW (Malkov & Yashunin,
2018), PQ quantization -- trading exactness for sub-linear query cost. This
module deliberately implements the *exact* baseline those structures
approximate: brute-force scan over every stored vector. That makes it the
reference oracle an ANN index is validated against (recall@k is measured
against exact top-k), and the honest choice for small corpora where an
approximate index would only add recall risk.

* **Embeddings** -- :class:`VectorDB` owns one fixed-dimension space
  (``dim`` is set at construction and never changes). ``upsert()`` stores
  or replaces a vector under a string id; ids are names, not proofs of
  ownership.
* **Search** -- ``search()`` scans every stored vector and returns the
  exact top-k by the requested metric (``cosine`` / ``euclidean`` /
  ``dot``). Ties break deterministically by id, so identical inputs
  produce byte-identical result order -- audit replay is exact.
* **Delete** -- ``delete()`` removes a vector by id. Deleting an unknown
  id raises :class:`UnknownVectorError` fail-closed: a silent no-op would
  let a caller believe data was removed when it was not.
* **Fail-closed vectors** -- zero vectors are rejected at ``upsert()``
  (a zero embedding has no direction, so cosine similarity is
  undefined); NaN/inf, bool elements, wrong dimension, and non-sequence
  vectors are rejected as programming errors. Bool ids and bool seqs are
  rejected everywhere (``True`` must never alias ``1``).
* **Digest pins** -- every record carries a ``sha256:`` pin over the
  canonical (id, dim, vector) body, so an audit consumer can re-derive
  and verify what was stored. Floats are canonicalized with ``repr()``,
  which round-trips IEEE doubles exactly.

Honest scope: this is an in-memory exact index, not a production vector
store. It cannot prove a vector is a faithful embedding of any text (it
stores host-reported floats), it cannot bound query latency (brute-force
is O(n) per query by design -- the cost an ANN index buys down), and it
persists nothing across processes. ``search()`` ranks *reported*
embeddings, never ground-truth similarity. Pair with a durable audit
writer for crash recovery; pair with ``dp_interface`` if stored
embeddings need privacy treatment.

Version pin: vector-db.v1
Schema pin: northstar.vector-db.v1
"""

from __future__ import annotations

import copy
import hashlib
import math
import threading
from dataclasses import dataclass
from typing import Any, Mapping, Optional, Tuple

#: Module version pin. Bump on any semantic change.
VECTOR_DB_VERSION = "vector-db.v1"

#: Schema pin for records produced by this module.
VECTOR_DB_SCHEMA = "northstar.vector-db.v1"

#: Supported similarity/distance metrics.
METRICS = ("cosine", "euclidean", "dot")

_AUDIT_KINDS = ("upserted", "deleted", "searched")


class VectorDBError(Exception):
    """Base error for vector-db misuse."""


class InvalidVectorError(VectorDBError):
    """A vector failed validation (dimension, NaN/inf, bool element, zero)."""


class InvalidIdError(VectorDBError):
    """A vector id failed validation (empty or non-string)."""


class InvalidMetricError(VectorDBError):
    """An unknown search metric was requested."""


class UnknownVectorError(VectorDBError):
    """A ``get()`` or ``delete()`` named an id that is not stored."""


def _check_seq(seq: Any) -> int:
    """Validate a caller-supplied audit seq; fail closed."""
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise VectorDBError(f"seq must be an int, got {type(seq).__name__}")
    if seq < 0:
        raise VectorDBError(f"seq must be non-negative, got {seq}")
    return seq


def _check_id(vector_id: Any) -> str:
    """Validate a vector id; fail closed."""
    if isinstance(vector_id, bool) or not isinstance(vector_id, str):
        raise InvalidIdError(
            f"id must be a str, got {type(vector_id).__name__}"
        )
    if not vector_id:
        raise InvalidIdError("id must be non-empty")
    return vector_id


def _check_dim(dim: Any) -> int:
    """Validate the space dimension; fail closed."""
    if isinstance(dim, bool) or not isinstance(dim, int):
        raise VectorDBError(f"dim must be an int, got {type(dim).__name__}")
    if dim <= 0:
        raise VectorDBError(f"dim must be positive, got {dim}")
    return dim


def _check_k(k: Any) -> int:
    """Validate top-k; fail closed."""
    if isinstance(k, bool) or not isinstance(k, int):
        raise VectorDBError(f"k must be an int, got {type(k).__name__}")
    if k <= 0:
        raise VectorDBError(f"k must be positive, got {k}")
    return k


def _check_vector(values: Any, dim: int, *, allow_zero: bool = False) -> Tuple[float, ...]:
    """Validate and normalize a vector; fail closed.

    Returns a tuple of plain floats. Rejects: non-sequences, wrong
    dimension, NaN/inf, bool elements, non-numeric elements. The zero
    vector is rejected unless ``allow_zero`` (a zero embedding has no
    direction, so cosine similarity is undefined on it).
    """
    if isinstance(values, (str, bytes)):
        raise InvalidVectorError("vector must be a sequence of numbers, not str/bytes")
    try:
        items = tuple(values)
    except TypeError:
        raise InvalidVectorError(
            f"vector must be a sequence, got {type(values).__name__}"
        ) from None
    if len(items) != dim:
        raise InvalidVectorError(
            f"vector has dimension {len(items)}, expected {dim}"
        )
    out = []
    for i, v in enumerate(items):
        if isinstance(v, bool):
            raise InvalidVectorError(f"vector[{i}]: bool is not a valid component")
        if isinstance(v, int):
            out.append(float(v))
        elif isinstance(v, float):
            if not math.isfinite(v):
                raise InvalidVectorError(f"vector[{i}]: non-finite component {v!r}")
            out.append(v)
        else:
            raise InvalidVectorError(
                f"vector[{i}]: expected int/float, got {type(v).__name__}"
            )
    if not allow_zero and all(c == 0.0 for c in out):
        raise InvalidVectorError("zero vector rejected: cosine similarity is undefined")
    return tuple(out)


def _check_metadata(metadata: Any) -> Optional[dict]:
    """Validate optional metadata; fail closed. Returns a deep copy or None."""
    if metadata is None:
        return None
    if not isinstance(metadata, Mapping):
        raise VectorDBError(
            f"metadata must be a mapping or None, got {type(metadata).__name__}"
        )
    for key, value in metadata.items():
        if isinstance(key, bool) or not isinstance(key, str) or not key:
            raise VectorDBError(f"metadata keys must be non-empty str, got {key!r}")
        _check_metadata_value(value, f"metadata[{key!r}]")
    return copy.deepcopy(dict(metadata))


def _check_metadata_value(value: Any, where: str) -> None:
    """Recursive validation of metadata leaf values."""
    if value is None:
        return
    if isinstance(value, bool):
        raise VectorDBError(f"{where}: bool is not allowed (must not alias 0/1)")
    if isinstance(value, int):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise VectorDBError(f"{where}: non-finite float {value!r}")
        return
    if isinstance(value, str):
        return
    if isinstance(value, (list, tuple)):
        for i, item in enumerate(value):
            _check_metadata_value(item, f"{where}[{i}]")
        return
    if isinstance(value, Mapping):
        for k, v in value.items():
            if isinstance(k, bool) or not isinstance(k, str) or not k:
                raise VectorDBError(f"{where}: nested keys must be non-empty str")
            _check_metadata_value(v, f"{where}[{k!r}]")
        return
    raise VectorDBError(
        f"{where}: unsupported metadata type {type(value).__name__}"
    )


def _vector_digest(vector_id: str, dim: int, vector: Tuple[float, ...]) -> str:
    """Content pin over the canonical (id, dim, vector) body."""
    body = "|".join(
        [vector_id, str(dim)] + [repr(c) for c in vector]
    )
    return "sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest()


def _dot(a: Tuple[float, ...], b: Tuple[float, ...]) -> float:
    return math.fsum(x * y for x, y in zip(a, b))


def _norm(a: Tuple[float, ...]) -> float:
    return math.sqrt(_dot(a, a))


def _score(metric: str, query: Tuple[float, ...], stored: Tuple[float, ...]) -> float:
    """Similarity score; higher means more similar, for every metric."""
    if metric == "cosine":
        denom = _norm(query) * _norm(stored)
        # denom cannot be zero: zero vectors are rejected at upsert, and a
        # zero query is rejected for cosine at search time.
        return _dot(query, stored) / denom
    if metric == "euclidean":
        diff = tuple(q - s for q, s in zip(query, stored))
        return -math.sqrt(_dot(diff, diff))
    # metric == "dot"
    return _dot(query, stored)


@dataclass(frozen=True)
class StoredVector:
    """One stored vector (frozen record)."""

    version: str
    vector_id: str
    dim: int
    vector: Tuple[float, ...]
    metadata: Optional[dict]
    digest: str

    def as_dict(self) -> dict:
        return {
            "schema": VECTOR_DB_SCHEMA,
            "version": self.version,
            "id": self.vector_id,
            "dim": self.dim,
            "vector": list(self.vector),
            "metadata": copy.deepcopy(self.metadata),
            "digest": self.digest,
        }


@dataclass(frozen=True)
class UpsertRecord:
    """Outcome of one ``upsert()`` (frozen record)."""

    version: str
    vector_id: str
    dim: int
    digest: str
    replaced: bool
    seq: int

    def as_dict(self) -> dict:
        return {
            "schema": VECTOR_DB_SCHEMA,
            "version": self.version,
            "id": self.vector_id,
            "dim": self.dim,
            "digest": self.digest,
            "replaced": self.replaced,
            "seq": self.seq,
        }


@dataclass(frozen=True)
class SearchHit:
    """One top-k hit (frozen record). Higher ``score`` = more similar."""

    version: str
    vector_id: str
    score: float
    metric: str
    rank: int

    def as_dict(self) -> dict:
        return {
            "schema": VECTOR_DB_SCHEMA,
            "version": self.version,
            "id": self.vector_id,
            "score": self.score,
            "metric": self.metric,
            "rank": self.rank,
        }


@dataclass(frozen=True)
class SearchResult:
    """Outcome of one ``search()`` (frozen record)."""

    version: str
    metric: str
    k: int
    hits: Tuple[SearchHit, ...]
    seq: int

    def as_dict(self) -> dict:
        return {
            "schema": VECTOR_DB_SCHEMA,
            "version": self.version,
            "metric": self.metric,
            "k": self.k,
            "hits": [h.as_dict() for h in self.hits],
            "seq": self.seq,
        }


@dataclass(frozen=True)
class DeleteRecord:
    """Outcome of one ``delete()`` (frozen record)."""

    version: str
    vector_id: str
    digest: str
    seq: int

    def as_dict(self) -> dict:
        return {
            "schema": VECTOR_DB_SCHEMA,
            "version": self.version,
            "id": self.vector_id,
            "digest": self.digest,
            "seq": self.seq,
        }


class VectorDB:
    """Exact brute-force vector database over one fixed-dimension space.

    ``upsert()`` stores or replaces vectors by id; ``search()`` scans
    every stored vector and returns the exact top-k; ``delete()`` removes
    by id. All state changes take a caller-supplied int ``seq`` (no
    wall-clock) so audit replay is exact. Thread-safe via an RLock.
    """

    def __init__(self, dim: int) -> None:
        self._dim = _check_dim(dim)
        self._lock = threading.RLock()
        self._vectors: dict[str, Tuple[Tuple[float, ...], Optional[dict]]] = {}

    @property
    def dim(self) -> int:
        """The fixed space dimension."""
        return self._dim

    def size(self) -> int:
        """Number of stored vectors."""
        with self._lock:
            return len(self._vectors)

    def ids(self) -> Tuple[str, ...]:
        """Stored ids in sorted order."""
        with self._lock:
            return tuple(sorted(self._vectors))

    def upsert(
        self,
        vector_id: str,
        vector: Any,
        seq: int,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> UpsertRecord:
        """Store or replace a vector under ``vector_id``.

        Returns a frozen :class:`UpsertRecord` with ``replaced=True``
        when an existing id was overwritten.
        """
        vid = _check_id(vector_id)
        vec = _check_vector(vector, self._dim)
        meta = _check_metadata(metadata)
        seq = _check_seq(seq)
        digest = _vector_digest(vid, self._dim, vec)
        with self._lock:
            replaced = vid in self._vectors
            self._vectors[vid] = (vec, meta)
        return UpsertRecord(
            version=VECTOR_DB_VERSION,
            vector_id=vid,
            dim=self._dim,
            digest=digest,
            replaced=replaced,
            seq=seq,
        )

    def get(self, vector_id: str) -> StoredVector:
        """Fetch one stored vector (deep copy; caller cannot alias state)."""
        vid = _check_id(vector_id)
        with self._lock:
            try:
                vec, meta = self._vectors[vid]
            except KeyError:
                raise UnknownVectorError(f"unknown vector id {vid!r}") from None
        return StoredVector(
            version=VECTOR_DB_VERSION,
            vector_id=vid,
            dim=self._dim,
            vector=tuple(vec),
            metadata=copy.deepcopy(meta),
            digest=_vector_digest(vid, self._dim, vec),
        )

    def delete(self, vector_id: str, seq: int) -> DeleteRecord:
        """Remove the vector stored under ``vector_id``.

        Unknown ids raise :class:`UnknownVectorError` fail-closed: a
        silent no-op would misreport data as removed.
        """
        vid = _check_id(vector_id)
        seq = _check_seq(seq)
        with self._lock:
            try:
                vec, _meta = self._vectors.pop(vid)
            except KeyError:
                raise UnknownVectorError(f"unknown vector id {vid!r}") from None
        return DeleteRecord(
            version=VECTOR_DB_VERSION,
            vector_id=vid,
            digest=_vector_digest(vid, self._dim, vec),
            seq=seq,
        )

    def search(
        self,
        query: Any,
        k: int,
        seq: int,
        metric: str = "cosine",
    ) -> SearchResult:
        """Exact brute-force top-k search over all stored vectors.

        ``metric`` is one of ``cosine`` / ``euclidean`` / ``dot``.
        Scores are ordered higher-is-more-similar for every metric
        (euclidean uses negative distance). Ties break by id ascending,
        so results are deterministic. An empty database yields zero hits
        (valid state, not an error).
        """
        if metric not in METRICS:
            raise InvalidMetricError(
                f"unknown metric {metric!r}; expected one of {METRICS}"
            )
        vec = _check_vector(query, self._dim, allow_zero=(metric != "cosine"))
        k = _check_k(k)
        seq = _check_seq(seq)
        with self._lock:
            scored = [
                (vid, _score(metric, vec, stored))
                for vid, (stored, _meta) in self._vectors.items()
            ]
        scored.sort(key=lambda item: (-item[1], item[0]))
        hits = tuple(
            SearchHit(
                version=VECTOR_DB_VERSION,
                vector_id=vid,
                score=score,
                metric=metric,
                rank=rank,
            )
            for rank, (vid, score) in enumerate(scored[:k])
        )
        return SearchResult(
            version=VECTOR_DB_VERSION,
            metric=metric,
            k=k,
            hits=hits,
            seq=seq,
        )


def vector_db_audit_event(kind: str, db: VectorDB, seq: int) -> dict:
    """Shape a vector-db lifecycle event as an ``audit.ndjson/1`` record."""
    if kind not in _AUDIT_KINDS:
        raise ValueError(f"kind must be one of {sorted(_AUDIT_KINDS)}")
    if not isinstance(db, VectorDB):
        raise TypeError("db must be a VectorDB")
    _check_seq(seq)
    return {
        "schema": "audit.ndjson/1",
        "kind": f"vector-db.{kind}",
        "module": VECTOR_DB_SCHEMA,
        "version": VECTOR_DB_VERSION,
        "seq": seq,
        "size": db.size(),
        "dim": db.dim,
    }


def main() -> None:
    """Self-check: upsert/replace, exact search, delete, refusals."""
    db = VectorDB(2)
    assert db.dim == 2 and db.size() == 0 and db.ids() == ()

    r1 = db.upsert("a", (1.0, 0.0), 0)
    assert not r1.replaced and r1.digest.startswith("sha256:")
    r2 = db.upsert("b", (0.0, 1.0), 1, metadata={"source": "test"})
    assert not r2.replaced
    r3 = db.upsert("a", (1.0, 1.0), 2)
    assert r3.replaced and db.size() == 2

    got = db.get("b")
    assert got.vector == (0.0, 1.0) and got.metadata == {"source": "test"}

    # exact cosine top-2: a=(1,1) scores 1/sqrt(2), b=(0,1) scores 1/sqrt(2)
    # tie -> id order: a before b.
    res = db.search((1.0, 1.0), 2, 3)
    assert len(res.hits) == 2
    assert [h.vector_id for h in res.hits] == ["a", "b"]
    assert res.hits[0].rank == 0 and res.hits[1].rank == 1

    res_e = db.search((1.0, 0.0), 1, 4, metric="euclidean")
    assert res_e.hits[0].vector_id == "a"  # dist 1.0 vs b dist sqrt(2)

    # dot: a=(1,1).(0,2)=2.0, b=(0,1).(0,2)=2.0 -> tie, "a" wins by id order.
    res_d = db.search((0.0, 2.0), 1, 5, metric="dot")
    assert res_d.hits[0].vector_id == "a"
    assert res_d.hits[0].score == 2.0
    res_d2 = db.search((0.0, 2.0), 2, 6, metric="dot")
    assert [h.vector_id for h in res_d2.hits] == ["a", "b"]

    empty = VectorDB(3)
    assert empty.search((1.0, 0.0, 0.0), 5, 0).hits == ()

    d = db.delete("a", 7)
    assert d.digest.startswith("sha256:") and db.size() == 1
    try:
        db.delete("a", 8)
    except UnknownVectorError:
        pass
    else:  # pragma: no cover
        raise AssertionError("expected UnknownVectorError")
    try:
        db.get("a")
    except UnknownVectorError:
        pass
    else:  # pragma: no cover
        raise AssertionError("expected UnknownVectorError")

    # refusals
    for bad, exc in [
        (lambda: db.upsert("", (1.0, 0.0), 9), InvalidIdError),
        (lambda: db.upsert(True, (1.0, 0.0), 9), InvalidIdError),
        (lambda: db.upsert("x", (1.0,), 9), InvalidVectorError),
        (lambda: db.upsert("x", (0.0, 0.0), 9), InvalidVectorError),
        (lambda: db.upsert("x", (1.0, float("nan")), 9), InvalidVectorError),
        (lambda: db.upsert("x", (1.0, True), 9), InvalidVectorError),
        (lambda: db.upsert("x", (1.0, 0.0), True), VectorDBError),
        (lambda: db.search((1.0, 0.0), 0, 9), VectorDBError),
        (lambda: db.search((1.0, 0.0), 1, 9, metric="manhattan"), InvalidMetricError),
        (lambda: db.search((0.0, 0.0), 1, 9, metric="cosine"), InvalidVectorError),
        (lambda: VectorDB(0), VectorDBError),
        (lambda: VectorDB(True), VectorDBError),
    ]:
        try:
            bad()
        except exc:
            pass
        else:  # pragma: no cover
            raise AssertionError(f"expected {exc.__name__}")

    print("vector-db OK: upsert/replace, exact search, delete, refusals")


if __name__ == "__main__":
    main()
