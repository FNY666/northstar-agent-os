"""Flat vs graph memory retrieval: empirical comparison, not a slogan.

P0 question: should long-term memory be a flat vector store or a graph
with traversal? The Selective Forgetting paper (Rusu/Khanzadeh/Alalfi,
arXiv:2608.28978v1) reported a **negative result against graph memory**
on LongMemEval: graph memory F1 0.417 vs flat vector retrieval F1 0.468,
with the "what the assistant said before" split collapsing 0.911 -> 0.607.
Importance-score pruning cut 27,021 nodes (9.8%) with zero accuracy loss.

This module lets Northstar test the claim on its own corpora instead of
quoting it:

* ``FlatMemory`` — documents as TF vectors over hashed token buckets;
  retrieval is pure cosine similarity, top-k.
* ``GraphMemory`` — the same documents as nodes plus edges; retrieval
  scores a node by its own cosine similarity *plus* a boost from its
  1-hop neighbors (traversal), so well-connected relevant context can
  surface even when the query lexically matches weakly.
* ``benchmark_both`` — builds both stores from the same documents,
  runs the same queries, scores F1 at k against ground-truth relevant
  document sets.
* ``recommend`` — returns ``'flat'`` or ``'graph'`` from the numbers.
  Exact ties go to ``'flat'``: the simpler system wins until the data
  says otherwise (the Selective Forgetting doctrine).

Embeddings are deterministic hash-bucket TF vectors (no network, no
model, no wall-clock): tokenize lowercase alphanumerics, hash each token
into one of ``N_BUCKETS`` buckets, L2-normalize. Cosine similarity is the
only similarity. Everything here is lexical, not semantic.

Honest scope: this is a *synthetic proxy*, not LongMemEval. It measures
which retrieval topology wins on a given corpus under lexical matching;
it does not prove anything about semantic embeddings, learned graph
encoders, or production-scale corpora. The graph boost parameter is
illustrative, not tuned. Run it, read the F1s, then decide.
"""
from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence


#: Schema pin for records minted by this module.
MEMORY_FLAT_VS_GRAPH_VERSION = "memory-flat-vs-graph.v1"

#: Cross-module schema pin (mirrors sibling convention).
SCHEMA_PIN = "northstar.memory-flat-vs-graph.v1"

#: Token buckets for the deterministic pseudo-embedding.
N_BUCKETS = 128

#: Weight of 1-hop neighbor evidence in graph retrieval scores.
GRAPH_NEIGHBOR_BOOST = 0.5

#: Lexical threshold below which a belief-strength retrieval is discarded.
_TOKEN_RE = re.compile(r"[a-z0-9]+")


def _check_seq(name: str, value: Any) -> int:
    """Validate a sequence number: int, not bool, non-negative."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int, got {type(value).__name__}")
    if value < 0:
        raise ValueError(f"{name} must be non-negative, got {value}")
    return value


def embed(text: str) -> tuple[float, ...]:
    """Deterministic pseudo-embedding: hashed TF vector, L2-normalized.

    Pure function of the text. An all-unknown/empty text yields the zero
    vector (cosine against it is defined as 0.0).
    """
    if not isinstance(text, str):
        raise TypeError(f"text must be str, got {type(text).__name__}")
    counts = [0.0] * N_BUCKETS
    for token in _TOKEN_RE.findall(text.lower()):
        bucket = int(hashlib.sha256(token.encode("utf-8")).hexdigest(), 16)
        counts[bucket % N_BUCKETS] += 1.0
    norm = math.sqrt(sum(c * c for c in counts))
    if norm == 0.0:
        return tuple(counts)
    return tuple(c / norm for c in counts)


def cosine(a: Sequence[float], b: Sequence[float]) -> float:
    """Cosine similarity. Zero vectors score 0.0 (defined, not NaN)."""
    if len(a) != len(b):
        raise ValueError(f"vector length mismatch: {len(a)} != {len(b)}")
    num = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0.0 or nb == 0.0:
        return 0.0
    return num / (na * nb)


@dataclass(frozen=True)
class ScoredDoc:
    """One retrieval hit: document index plus its score."""

    doc_index: int
    score: float

    def as_dict(self) -> dict[str, Any]:
        return {"doc_index": self.doc_index, "score": self.score}


class FlatMemory:
    """Flat vector store: documents as vectors, retrieval by cosine."""

    def __init__(self) -> None:
        self._docs: list[tuple[str, tuple[float, ...]]] = []

    def __len__(self) -> int:
        return len(self._docs)

    def add(self, text: str) -> int:
        """Store a document; returns its index. Empty text is rejected."""
        if not isinstance(text, str) or not text.strip():
            raise ValueError("document text must be a non-empty string")
        idx = len(self._docs)
        self._docs.append((text, embed(text)))
        return idx

    def retrieve(self, query: str, top_k: int) -> list[ScoredDoc]:
        """Top-k documents by cosine similarity, score desc, index asc."""
        if not isinstance(query, str):
            raise TypeError(f"query must be str, got {type(query).__name__}")
        if isinstance(top_k, bool) or not isinstance(top_k, int) or top_k <= 0:
            raise ValueError(f"top_k must be a positive int, got {top_k!r}")
        qv = embed(query)
        scored = [
            ScoredDoc(doc_index=i, score=cosine(qv, vec))
            for i, (_, vec) in enumerate(self._docs)
        ]
        scored.sort(key=lambda s: (-s.score, s.doc_index))
        return scored[:top_k]


class GraphMemory:
    """Graph store: same documents as nodes; edges add neighbor evidence.

    Retrieval score for a node = its own cosine similarity + ``boost``
    times the sum of 1-hop neighbor cosine similarities. A node whose
    neighbors match the query can outrank a lexically closer node, which
    is the whole point of traversal-based retrieval.
    """

    def __init__(self, boost: float = GRAPH_NEIGHBOR_BOOST) -> None:
        if isinstance(boost, bool) or not isinstance(boost, (int, float)):
            raise TypeError(f"boost must be a number, got {type(boost).__name__}")
        if boost < 0:
            raise ValueError(f"boost must be non-negative, got {boost}")
        self._boost = float(boost)
        self._docs: list[tuple[str, tuple[float, ...]]] = []
        self._edges: dict[int, set[int]] = {}

    def __len__(self) -> int:
        return len(self._docs)

    def add(self, text: str) -> int:
        """Store a node; returns its index. Empty text is rejected."""
        if not isinstance(text, str) or not text.strip():
            raise ValueError("node text must be a non-empty string")
        idx = len(self._docs)
        self._docs.append((text, embed(text)))
        self._edges[idx] = set()
        return idx

    def add_edge(self, a: int, b: int) -> None:
        """Add an undirected edge between two existing, distinct nodes."""
        for name, v in (("a", a), ("b", b)):
            if isinstance(v, bool) or not isinstance(v, int):
                raise TypeError(f"{name} must be an int, got {type(v).__name__}")
            if not 0 <= v < len(self._docs):
                raise ValueError(f"{name}={v} is not a known node index")
        if a == b:
            raise ValueError("self-loops are not allowed")
        self._edges[a].add(b)
        self._edges[b].add(a)

    def retrieve(self, query: str, top_k: int) -> list[ScoredDoc]:
        """Top-k nodes by own cosine + boost * neighbor cosine sum."""
        if not isinstance(query, str):
            raise TypeError(f"query must be str, got {type(query).__name__}")
        if isinstance(top_k, bool) or not isinstance(top_k, int) or top_k <= 0:
            raise ValueError(f"top_k must be a positive int, got {top_k!r}")
        qv = embed(query)
        own = [cosine(qv, vec) for _, vec in self._docs]
        scored = []
        for i in range(len(self._docs)):
            neighbor_sum = sum(own[j] for j in self._edges[i])
            scored.append(ScoredDoc(doc_index=i, score=own[i] + self._boost * neighbor_sum))
        scored.sort(key=lambda s: (-s.score, s.doc_index))
        return scored[:top_k]


def f1_at_k(retrieved: Sequence[int], relevant: Sequence[int] | set[int]) -> tuple[float, float, float]:
    """(precision, recall, f1) of retrieved indices against relevant ones.

    Empty relevant set: precision is defined against retrieved (0.0 when
    anything is retrieved), recall and f1 are 0.0 — you cannot recall what
    was never specified.
    """
    rel = set(relevant)
    ret = list(retrieved)
    if not ret:
        return (0.0, 0.0, 0.0)
    hits = sum(1 for i in ret if i in rel)
    precision = hits / len(ret)
    recall = hits / len(rel) if rel else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    return (precision, recall, f1)


@dataclass(frozen=True)
class BenchmarkResult:
    """Outcome of one flat-vs-graph benchmark run."""

    flat_f1: float
    graph_f1: float
    flat_precision: float
    flat_recall: float
    graph_precision: float
    graph_recall: float
    num_queries: int
    top_k: int
    version: str = MEMORY_FLAT_VS_GRAPH_VERSION

    def as_dict(self) -> dict[str, Any]:
        return {
            "flat_f1": self.flat_f1,
            "graph_f1": self.graph_f1,
            "flat_precision": self.flat_precision,
            "flat_recall": self.flat_recall,
            "graph_precision": self.graph_precision,
            "graph_recall": self.graph_recall,
            "num_queries": self.num_queries,
            "top_k": self.top_k,
            "version": self.version,
            "schema": SCHEMA_PIN,
        }


def benchmark_both(
    documents: Sequence[str],
    edges: Sequence[tuple[int, int]],
    queries: Sequence[str],
    relevant: Sequence[set[int]],
    top_k: int = 3,
) -> BenchmarkResult:
    """Build both stores from the same corpus, run queries, score F1@k.

    * ``documents`` — texts; index i is the shared document id.
    * ``edges`` — (i, j) index pairs for the graph store only.
    * ``queries`` — query texts, one per entry in ``relevant``.
    * ``relevant`` — per-query sets of relevant document *indices*.
    * ``top_k`` — retrieval depth for both stores.

    Scores are macro-averaged over queries. Raises on empty documents,
    empty queries, length mismatches, or out-of-range indices (fail-closed:
    a benchmark with a broken fixture proves nothing).
    """
    if not documents:
        raise ValueError("documents must be non-empty")
    if not queries:
        raise ValueError("queries must be non-empty")
    if len(queries) != len(relevant):
        raise ValueError(
            f"queries ({len(queries)}) and relevant ({len(relevant)}) length mismatch"
        )
    if isinstance(top_k, bool) or not isinstance(top_k, int) or top_k <= 0:
        raise ValueError(f"top_k must be a positive int, got {top_k!r}")

    flat = FlatMemory()
    graph = GraphMemory()
    for text in documents:
        flat.add(text)
        graph.add(text)
    for a, b in edges:
        graph.add_edge(a, b)
    for q_idx, rel in enumerate(relevant):
        for i in rel:
            if isinstance(i, bool) or not isinstance(i, int) or not 0 <= i < len(documents):
                raise ValueError(f"relevant[{q_idx}] has out-of-range index {i!r}")

    fp = fr = ff = gp = gr = gf = 0.0
    for query, rel in zip(queries, relevant):
        f_hits = [s.doc_index for s in flat.retrieve(query, top_k)]
        g_hits = [s.doc_index for s in graph.retrieve(query, top_k)]
        p, r, f = f1_at_k(f_hits, rel)
        fp += p
        fr += r
        ff += f
        p, r, f = f1_at_k(g_hits, rel)
        gp += p
        gr += r
        gf += f
    n = len(queries)
    return BenchmarkResult(
        flat_f1=ff / n,
        graph_f1=gf / n,
        flat_precision=fp / n,
        flat_recall=fr / n,
        graph_precision=gp / n,
        graph_recall=gr / n,
        num_queries=n,
        top_k=top_k,
    )


def recommend(result: BenchmarkResult) -> str:
    """'flat' or 'graph' from a benchmark result.

    The higher F1 wins. Exact ties go to 'flat': the simpler system is
    the default until the data favors the graph (the Selective Forgetting
    doctrine — graph memory lost on LongMemEval, so it carries the burden
    of proof here too).
    """
    if not isinstance(result, BenchmarkResult):
        raise TypeError(f"result must be BenchmarkResult, got {type(result).__name__}")
    if result.graph_f1 > result.flat_f1:
        return "graph"
    return "flat"


def main() -> None:
    documents = [
        "the cat sat on the mat",
        "nutrition guidelines for pets",
        "mat cleaning instructions",
        "feline vaccination schedule",
    ]
    # The answer lives in doc 1 ("nutrition"), which only doc 0 links to.
    edges = [(0, 1)]
    queries = ["cat food", "mat"]
    relevant = [{1}, {0, 2}]
    result = benchmark_both(documents, edges, queries, relevant, top_k=2)
    print(
        f"memory-flat-vs-graph OK: flat_f1={result.flat_f1:.3f} "
        f"graph_f1={result.graph_f1:.3f} recommend={recommend(result)} "
        f"queries={result.num_queries}"
    )


if __name__ == "__main__":
    main()
