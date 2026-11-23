"""RAG pipeline: retrieval-augmented generation bookkeeping.

Research motivation: in retrieval-augmented generation (Lewis et al.,
2020), a retriever first fetches passages relevant to a query from a
corpus, then a generator produces an answer conditioned on the
retrieved passages, and the answer's claims are cited against the
passages they came from. This module books that pipeline as a
deterministic single-host ledger: declared chunks are ingested,
retrievals are scored by a pinned term-overlap scorer, generations are
host-declared drafts grounded on a retrieval's ranked set, and citations
bind individual claims to the chunks that ground them. It runs no
embeddings, no vector index, and no language model -- "generation"
here means a host-declared draft, never proof that a model produced
it.

Public API:

- ``RAGPipeline()`` -- mutable, RLock-guarded ledger.
  - ``ingest(chunk_id, text, seq, source="")`` -> frozen
    ``ChunkRecord``: books a text chunk (a passage) with a ``sha256:``
    digest pin; duplicate ids refused; retired ids never recycled.
  - ``retrieve(query, seq, top_k=10)`` -> frozen
    ``RetrievalRecord``: scores live chunks by deterministic
    term-overlap (``coverage * (1 + ln(1 + total_tf))`` over lowercase
    word tokens), sorts by descending score with ``chunk_id``
    tiebreaks, books the ranked ``(chunk_id, score)`` pairs. A
    pipeline step, so it consumes seq and books an audit row; an
    empty corpus or a no-match query yields zero hits as data, never
    raised.
  - ``generate(query, retrieval_id, seq, draft,
    grounded_chunks=())`` -> frozen ``GenerationRecord``: books a
    host-declared answer draft grounded on chunk ids drawn from that
    retrieval's ranked set. The query must equal the retrieval's
    query; every grounded chunk must be live and present in the
    retrieval's ranked set (``UncitedChunkError`` otherwise).
  - ``cite(generation_id, claim, chunk_id, seq)`` -> frozen
    ``CitationRecord``: binds one claim (pinned by digest) to a chunk
    grounded in that generation.
  - ``retire(chunk_id, seq, reason="")`` -> frozen ``RetireRecord``:
    terminal tombstone; the id is retired and may never be re-ingested.
  - ``chunk()`` / ``chunk_ids()`` / ``retrieval()`` / ``generation()``
    / ``citations_for()`` / ``stats()`` / ``audit_log()`` -- pure read
    views; validate seq shape, consume no seq, write no audit rows.
- ``rag_pipeline_audit_event(kind, detail, seq)`` --
  ``audit.ndjson/1`` records: ``"rag-pipeline.ingested"``,
  ``"rag-pipeline.retrieved"``, ``"rag-pipeline.generated"``,
  ``"rag-pipeline.cited"``, ``"rag-pipeline.retired"``,
  ``"rag-pipeline.rejected"``.

Raw text never crosses the audit boundary: ``detail`` may carry chunk
ids, retrieval/generation/citation ids, term counts, scores, digests
and counts -- never ``text``, ``draft``, ``claim``, ``payload``,
``value``, ``raw``, ``body`` or ``fields``.

House discipline: caller int seqs strictly increasing on mutations
(failed mutations consume their seq and book ``rejected``;
bool/negative/rewind refused), RLock-guarded, fail-closed taxonomy,
stdlib-only (``canonical_json`` sibling helper behind the standard
try/except fallback).

Honest scope:

- This module books *declared* chunks, retrievals, generations and
  citations; it embeds nothing, runs no language model, and cannot
  prove that a draft was actually produced by any model or that a
  cited chunk actually supports the claim.
- Retrieval scores are term-overlap bookkeeping (lowercase word
  tokens, no stemming, no stop-word removal): a high score says
  "these tokens overlap", never "this passage answers the query".
- A ``GenerationRecord`` is a host-declared draft (GIGO boundary on
  the host's text); ``cite()`` books that the host *declared* a
  claim-to-chunk binding, never that the binding is factually valid.
- ``retire()`` drops a chunk from future retrievals; it cannot prove
  any model will forget the chunk.

Version pin: ``rag-pipeline.v1`` / schema pin
``northstar.rag-pipeline.v1``.
"""

from __future__ import annotations

import hashlib
import math
import re
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Tuple

try:  # stdlib-first; canonical_json is the sibling JCS helper
    from canonical_json import jcs_dumps as _jcs_dumps  # type: ignore

    def _encode(value: object) -> bytes:
        out = _jcs_dumps(value)
        return out.encode("utf-8") if isinstance(out, str) else bytes(out)

except Exception:  # pragma: no cover - fallback keeps stdlib-only promise
    def _encode(value: object) -> bytes:  # type: ignore
        return _fallback_encode(value)


def _fallback_encode(value: object) -> bytes:
    """Minimal deterministic encoder (JCS-flavoured) used only when the
    sibling ``canonical_json`` helper is unavailable."""
    if value is None or isinstance(value, bool):
        return b"true" if value else (b"null" if value is None else b"false")
    if isinstance(value, int):
        return str(value).encode("ascii")
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("non-finite float")
        return repr(value).encode("ascii")
    if isinstance(value, str):
        return b'"' + value.encode("utf-8").replace(b"\\", b"\\\\").replace(
            b'"', b'\\"'
        ) + b'"'
    if isinstance(value, (tuple, list)):
        return b"[" + b",".join(_fallback_encode(v) for v in value) + b"]"
    if isinstance(value, Mapping):
        items = sorted(value.items(), key=lambda kv: str(kv[0]))
        body = b",".join(
            _fallback_encode(str(k)) + b":" + _fallback_encode(v)
            for k, v in items
        )
        return b"{" + body + b"}"
    raise TypeError(f"cannot canonicalize {type(value).__name__}")


#: Version pin for this module's record shape.
RAG_PIPELINE_VERSION = "rag-pipeline.v1"

#: Schema pin carried by records and audit events.
RAG_PIPELINE_SCHEMA = "northstar.rag-pipeline.v1"

#: Wire format of audit records.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Fixed vocabulary for audit event kinds.
KIND_INGESTED = "rag-pipeline.ingested"
KIND_RETRIEVED = "rag-pipeline.retrieved"
KIND_GENERATED = "rag-pipeline.generated"
KIND_CITED = "rag-pipeline.cited"
KIND_RETIRED = "rag-pipeline.retired"
KIND_REJECTED = "rag-pipeline.rejected"
_KINDS = frozenset(
    {
        KIND_INGESTED,
        KIND_RETRIEVED,
        KIND_GENERATED,
        KIND_CITED,
        KIND_RETIRED,
        KIND_REJECTED,
    }
)

_TOKEN_RE = re.compile(r"[a-z0-9_]+")

_DIGEST_PREFIX = "sha256:"
_MAX_ID_LEN = 256
_MAX_TEXT_LEN = 64 * 1024
_MAX_SOURCE_LEN = 512
_MAX_TOP_K = 1000


# ---------------------------------------------------------------------------
# Error taxonomy (fail-closed)
# ---------------------------------------------------------------------------


class RAGPipelineError(Exception):
    """Base class for all rag-pipeline errors."""


class BadChunkError(RAGPipelineError):
    """Chunk id, text or source failed validation."""


class DuplicateChunkError(RAGPipelineError):
    """A chunk id is already live in the corpus."""


class RetiredChunkError(RAGPipelineError):
    """A chunk id was retired and may never be reused."""


class UnknownChunkError(RAGPipelineError):
    """A chunk id is neither live nor retired."""


class BadQueryError(RAGPipelineError):
    """Query failed validation or mismatched a retrieval's query."""


class BadTopKError(RAGPipelineError):
    """top_k failed validation."""


class UnknownRetrievalError(RAGPipelineError):
    """A retrieval id is unknown."""


class UnknownGenerationError(RAGPipelineError):
    """A generation id is unknown."""


class BadDraftError(RAGPipelineError):
    """Draft failed validation."""


class BadClaimError(RAGPipelineError):
    """Citation claim failed validation."""


class UncitedChunkError(RAGPipelineError):
    """A chunk was not part of the retrieval/generation being cited."""


class SeqOrderError(RAGPipelineError):
    """Seq was malformed or did not strictly increase."""


class AuditKindError(RAGPipelineError):
    """Audit event kind unknown or detail carries banned keys."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_seq(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SeqOrderError(f"seq must be a non-negative int, got {value!r}")
    return value


def _check_chunk_id(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > _MAX_ID_LEN:
        raise BadChunkError(
            f"chunk_id must be a non-empty str <= {_MAX_ID_LEN} chars"
        )
    return value


def _check_text(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > _MAX_TEXT_LEN:
        raise BadChunkError("text must be a non-empty str")
    return value


def _check_source(value: object) -> str:
    if not isinstance(value, str) or len(value) > _MAX_SOURCE_LEN:
        raise BadChunkError("source must be a str")
    return value


def _check_query(value: object) -> Tuple[str, ...]:
    if not isinstance(value, str) or not value.strip():
        raise BadQueryError("query must be a non-empty str")
    terms = tuple(dict.fromkeys(_TOKEN_RE.findall(value.lower())))
    if not terms:
        raise BadQueryError("query has no indexable terms")
    return terms


def _check_top_k(value: object) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < 1
        or value > _MAX_TOP_K
    ):
        raise BadTopKError(f"top_k must be an int in [1, {_MAX_TOP_K}]")
    return value


def _check_draft(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > _MAX_TEXT_LEN:
        raise BadDraftError("draft must be a non-empty str")
    return value


def _check_claim(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > _MAX_TEXT_LEN:
        raise BadClaimError("claim must be a non-empty str")
    return value


def _check_id_list(value: object, name: str) -> Tuple[str, ...]:
    if isinstance(value, str) or not isinstance(value, (tuple, list)):
        raise BadChunkError(f"{name} must be a tuple/list of chunk id strings")
    ids: list = []
    for item in value:
        ids.append(_check_chunk_id(item))
    return tuple(ids)


def _digest_pin(parts: object) -> str:
    return _DIGEST_PREFIX + hashlib.sha256(_encode(parts)).hexdigest()


def _score(matched_terms: int, total_tf: int, query_terms: int) -> float:
    coverage = matched_terms / query_terms
    return round(coverage * (1.0 + math.log1p(total_tf)), 12)


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ChunkRecord:
    """Booked passage chunk."""

    chunk_id: str
    source: str
    term_count: int
    unique_terms: int
    digest: str
    seq: int

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": RAG_PIPELINE_SCHEMA,
            "chunk_id": self.chunk_id,
            "source": self.source,
            "term_count": self.term_count,
            "unique_terms": self.unique_terms,
            "digest": self.digest,
            "seq": self.seq,
        }

    def verify(self, chunk_id: str, text: str) -> bool:
        return self.digest == _digest_pin([chunk_id, text])


@dataclass(frozen=True)
class ScoredChunk:
    """One ranked hit: chunk id plus its overlap score."""

    chunk_id: str
    score: float


@dataclass(frozen=True)
class RetrievalRecord:
    """Booked retrieval: ranked chunk ids over a pinned query."""

    retrieval_id: str
    query: str
    query_terms: Tuple[str, ...]
    hits: Tuple[ScoredChunk, ...]
    total_matched: int
    digest: str
    seq: int

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": RAG_PIPELINE_SCHEMA,
            "retrieval_id": self.retrieval_id,
            "query": self.query,
            "query_terms": list(self.query_terms),
            "hits": [
                {"chunk_id": h.chunk_id, "score": h.score} for h in self.hits
            ],
            "total_matched": self.total_matched,
            "digest": self.digest,
            "seq": self.seq,
        }

    def hit_ids(self) -> Tuple[str, ...]:
        return tuple(h.chunk_id for h in self.hits)

    def verify(self, query: str, hits: List[Tuple[str, float]]) -> bool:
        return self.digest == _digest_pin([self.retrieval_id, query, hits])


@dataclass(frozen=True)
class GenerationRecord:
    """Booked generation: host-declared draft grounded on a retrieval."""

    generation_id: str
    query: str
    retrieval_id: str
    grounded_chunks: Tuple[str, ...]
    draft_digest: str
    digest: str
    seq: int

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": RAG_PIPELINE_SCHEMA,
            "generation_id": self.generation_id,
            "query": self.query,
            "retrieval_id": self.retrieval_id,
            "grounded_chunks": list(self.grounded_chunks),
            "draft_digest": self.draft_digest,
            "digest": self.digest,
            "seq": self.seq,
        }

    def verify(
        self,
        query: str,
        retrieval_id: str,
        grounded_chunks: List[str],
        draft: str,
    ) -> bool:
        draft_digest = _digest_pin(["draft", draft])
        return self.digest == _digest_pin(
            [self.generation_id, query, retrieval_id, grounded_chunks, draft_digest]
        )


@dataclass(frozen=True)
class CitationRecord:
    """Booked citation: one claim bound to one grounded chunk."""

    citation_id: str
    generation_id: str
    claim_digest: str
    chunk_id: str
    digest: str
    seq: int

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": RAG_PIPELINE_SCHEMA,
            "citation_id": self.citation_id,
            "generation_id": self.generation_id,
            "claim_digest": self.claim_digest,
            "chunk_id": self.chunk_id,
            "digest": self.digest,
            "seq": self.seq,
        }

    def verify(self, generation_id: str, claim: str, chunk_id: str) -> bool:
        return self.digest == _digest_pin(
            [
                self.citation_id,
                generation_id,
                _digest_pin(["claim", claim]),
                chunk_id,
            ]
        )


@dataclass(frozen=True)
class RetireRecord:
    """Terminal tombstone for a chunk id."""

    chunk_id: str
    reason: str
    seq: int

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": RAG_PIPELINE_SCHEMA,
            "chunk_id": self.chunk_id,
            "reason": self.reason,
            "seq": self.seq,
        }


# ---------------------------------------------------------------------------
# Audit event builder
# ---------------------------------------------------------------------------


def rag_pipeline_audit_event(
    kind: str, detail: Mapping[str, Any], seq: int
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the RAG pipeline.

    Raw text never crosses the audit boundary: ``detail`` may carry
    chunk ids, retrieval/generation/citation ids, term counts, scores,
    digests and counts -- never ``text``, ``draft``, ``claim``,
    ``payload``, ``value``, ``raw``, ``body`` or ``fields``.
    """
    if not isinstance(kind, str) or kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    if not isinstance(detail, Mapping):
        raise AuditKindError("detail must be a mapping")
    banned = {
        "text",
        "draft",
        "claim",
        "payload",
        "value",
        "raw",
        "body",
        "fields",
    }
    if any(k in detail for k in banned):
        raise AuditKindError("detail carries banned keys")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": RAG_PIPELINE_VERSION,
        "detail": dict(detail),
        "seq": seq,
    }


# ---------------------------------------------------------------------------
# The ledger
# ---------------------------------------------------------------------------


class RAGPipeline:
    """Deterministic retrieval-augmented generation pipeline ledger.

    Books declared chunks, term-overlap retrievals, host-declared
    generations grounded on retrievals, and claim-to-chunk citations
    as frozen records over caller-supplied logical seqs.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = -1
        # chunk_id -> {"terms": {term: tf}, "term_count": int,
        #              "digest": str, "source": str}
        self._chunks: Dict[str, Dict[str, Any]] = {}
        self._retired: set = set()
        # term -> {chunk_id: tf} over live chunks
        self._postings: Dict[str, Dict[str, int]] = {}
        self._retrievals: Dict[str, RetrievalRecord] = {}
        self._generations: Dict[str, GenerationRecord] = {}
        self._citations: Dict[str, CitationRecord] = {}
        self._next_retrieval = 0
        self._next_generation = 0
        self._next_citation = 0
        self._audit: list = []

    # -- seq discipline ----------------------------------------------------

    def _claim(self, seq: int) -> int:
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq {seq} did not exceed last seq {self._last_seq}"
            )
        self._last_seq = seq
        return seq

    def _reject(self, seq: int, reason: str, ref_id: str = "") -> Dict[str, Any]:
        row = rag_pipeline_audit_event(
            KIND_REJECTED, {"reason": reason, "ref_id": ref_id}, seq
        )
        self._audit.append(row)
        return row

    # -- internal chunk maintenance ----------------------------------------

    def _remove_postings(self, chunk_id: str) -> None:
        entry = self._chunks.get(chunk_id)
        if entry is None:
            return
        for term, tf in entry["terms"].items():
            post = self._postings.get(term)
            if post is not None and chunk_id in post:
                del post[chunk_id]
                if not post:
                    del self._postings[term]

    # -- mutations ----------------------------------------------------------

    def ingest(
        self, chunk_id: str, text: str, seq: int, source: str = ""
    ) -> ChunkRecord:
        """Book a text chunk (passage) into the corpus.

        Duplicate live ids refused; retired ids refused fail-closed.
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                chunk_id = _check_chunk_id(chunk_id)
                text = _check_text(text)
                source = _check_source(source)
            except RAGPipelineError as exc:
                self._reject(seq, type(exc).__name__, str(chunk_id))
                raise
            if chunk_id in self._retired:
                self._reject(seq, "RetiredChunkError", chunk_id)
                raise RetiredChunkError(
                    f"chunk_id {chunk_id!r} was retired"
                )
            if chunk_id in self._chunks:
                self._reject(seq, "DuplicateChunkError", chunk_id)
                raise DuplicateChunkError(
                    f"chunk_id {chunk_id!r} already ingested"
                )
            terms: Dict[str, int] = {}
            for tok in _TOKEN_RE.findall(text.lower()):
                terms[tok] = terms.get(tok, 0) + 1
            term_count = sum(terms.values())
            digest = _digest_pin([chunk_id, text])
            self._chunks[chunk_id] = {
                "terms": terms,
                "term_count": term_count,
                "digest": digest,
                "source": source,
            }
            for term, tf in terms.items():
                self._postings.setdefault(term, {})[chunk_id] = tf
            record = ChunkRecord(
                chunk_id=chunk_id,
                source=source,
                term_count=term_count,
                unique_terms=len(terms),
                digest=digest,
                seq=seq,
            )
            self._audit.append(
                rag_pipeline_audit_event(
                    KIND_INGESTED,
                    {
                        "chunk_id": chunk_id,
                        "term_count": term_count,
                        "unique_terms": len(terms),
                        "digest": digest,
                    },
                    seq,
                )
            )
            return record

    def retrieve(self, query: str, seq: int, top_k: int = 10) -> RetrievalRecord:
        """Score live chunks by term overlap and book the ranked hits.

        A pipeline step: consumes seq and books an audit row. Empty
        results are data, never raised.
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                terms = _check_query(query)
                top_k = _check_top_k(top_k)
            except RAGPipelineError as exc:
                self._reject(seq, type(exc).__name__)
                raise
            scored: List[Tuple[str, float]] = []
            if self._chunks:
                chunk_scores: Dict[str, Tuple[int, int]] = {}
                for term in terms:
                    post = self._postings.get(term)
                    if not post:
                        continue
                    for chunk_id, tf in post.items():
                        matched, total = chunk_scores.get(chunk_id, (0, 0))
                        chunk_scores[chunk_id] = (matched + 1, total + tf)
                ranked: List[Tuple[str, float]] = []
                for chunk_id, (matched, total) in chunk_scores.items():
                    ranked.append(
                        (chunk_id, _score(matched, total, len(terms)))
                    )
                ranked.sort(key=lambda item: (-item[1], item[0]))
                scored = ranked[:top_k]
            retrieval_id = f"ret-{self._next_retrieval}"
            self._next_retrieval += 1
            digest = _digest_pin([retrieval_id, query, scored])
            record = RetrievalRecord(
                retrieval_id=retrieval_id,
                query=query,
                query_terms=terms,
                hits=tuple(
                    ScoredChunk(chunk_id=c, score=s) for c, s in scored
                ),
                total_matched=len(scored),
                digest=digest,
                seq=seq,
            )
            self._retrievals[retrieval_id] = record
            self._audit.append(
                rag_pipeline_audit_event(
                    KIND_RETRIEVED,
                    {
                        "retrieval_id": retrieval_id,
                        "query_terms": len(terms),
                        "total_matched": len(scored),
                        "digest": digest,
                    },
                    seq,
                )
            )
            return record

    def generate(
        self,
        query: str,
        retrieval_id: str,
        seq: int,
        draft: str,
        grounded_chunks: Tuple[str, ...] = (),
    ) -> GenerationRecord:
        """Book a host-declared answer draft grounded on a retrieval.

        The query must equal the retrieval's query; every grounded
        chunk must be live and present in the retrieval's ranked set.
        The draft is host-declared (GIGO boundary); only its digest
        crosses the audit boundary.
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                if not isinstance(query, str) or not query:
                    raise BadQueryError("query must be a non-empty str")
                if not isinstance(retrieval_id, str) or not retrieval_id:
                    raise UnknownRetrievalError(
                        "retrieval_id must be a non-empty str"
                    )
                draft = _check_draft(draft)
                grounded = _check_id_list(grounded_chunks, "grounded_chunks")
            except RAGPipelineError as exc:
                self._reject(seq, type(exc).__name__, str(retrieval_id))
                raise
            retrieval = self._retrievals.get(retrieval_id)
            if retrieval is None:
                self._reject(seq, "UnknownRetrievalError", retrieval_id)
                raise UnknownRetrievalError(
                    f"unknown retrieval_id: {retrieval_id!r}"
                )
            if query != retrieval.query:
                self._reject(seq, "BadQueryError", retrieval_id)
                raise BadQueryError(
                    "query does not match the retrieval's query"
                )
            hit_ids = set(retrieval.hit_ids())
            for chunk_id in grounded:
                if chunk_id not in self._chunks:
                    self._reject(seq, "UnknownChunkError", chunk_id)
                    raise UnknownChunkError(
                        f"chunk_id {chunk_id!r} is not live"
                    )
                if chunk_id not in hit_ids:
                    self._reject(seq, "UncitedChunkError", chunk_id)
                    raise UncitedChunkError(
                        f"chunk_id {chunk_id!r} not in retrieval {retrieval_id!r}"
                    )
            generation_id = f"gen-{self._next_generation}"
            self._next_generation += 1
            grounded_list = list(grounded)
            draft_digest = _digest_pin(["draft", draft])
            digest = _digest_pin(
                [
                    generation_id,
                    query,
                    retrieval_id,
                    grounded_list,
                    draft_digest,
                ]
            )
            record = GenerationRecord(
                generation_id=generation_id,
                query=query,
                retrieval_id=retrieval_id,
                grounded_chunks=grounded,
                draft_digest=draft_digest,
                digest=digest,
                seq=seq,
            )
            self._generations[generation_id] = record
            self._audit.append(
                rag_pipeline_audit_event(
                    KIND_GENERATED,
                    {
                        "generation_id": generation_id,
                        "retrieval_id": retrieval_id,
                        "grounded_count": len(grounded),
                        "draft_digest": draft_digest,
                        "digest": digest,
                    },
                    seq,
                )
            )
            return record

    def cite(
        self, generation_id: str, claim: str, chunk_id: str, seq: int
    ) -> CitationRecord:
        """Bind one claim to a chunk grounded in the generation.

        The chunk must be one of the generation's grounded chunks.
        The claim is pinned by digest; raw claim text never crosses
        the audit boundary.
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                if not isinstance(generation_id, str) or not generation_id:
                    raise UnknownGenerationError(
                        "generation_id must be a non-empty str"
                    )
                claim = _check_claim(claim)
                chunk_id = _check_chunk_id(chunk_id)
            except RAGPipelineError as exc:
                self._reject(seq, type(exc).__name__, str(generation_id))
                raise
            generation = self._generations.get(generation_id)
            if generation is None:
                self._reject(seq, "UnknownGenerationError", generation_id)
                raise UnknownGenerationError(
                    f"unknown generation_id: {generation_id!r}"
                )
            if chunk_id not in generation.grounded_chunks:
                self._reject(seq, "UncitedChunkError", chunk_id)
                raise UncitedChunkError(
                    f"chunk_id {chunk_id!r} not grounded in {generation_id!r}"
                )
            citation_id = f"cite-{self._next_citation}"
            self._next_citation += 1
            claim_digest = _digest_pin(["claim", claim])
            digest = _digest_pin(
                [citation_id, generation_id, claim_digest, chunk_id]
            )
            record = CitationRecord(
                citation_id=citation_id,
                generation_id=generation_id,
                claim_digest=claim_digest,
                chunk_id=chunk_id,
                digest=digest,
                seq=seq,
            )
            self._citations[citation_id] = record
            self._audit.append(
                rag_pipeline_audit_event(
                    KIND_CITED,
                    {
                        "citation_id": citation_id,
                        "generation_id": generation_id,
                        "chunk_id": chunk_id,
                        "claim_digest": claim_digest,
                        "digest": digest,
                    },
                    seq,
                )
            )
            return record

    def retire(self, chunk_id: str, seq: int, reason: str = "") -> RetireRecord:
        """Terminally tombstone a chunk; the id is retired forever."""
        with self._lock:
            seq = self._claim(seq)
            try:
                chunk_id = _check_chunk_id(chunk_id)
                if not isinstance(reason, str) or len(reason) > _MAX_SOURCE_LEN:
                    raise BadChunkError("reason must be a str")
            except RAGPipelineError as exc:
                self._reject(seq, type(exc).__name__, str(chunk_id))
                raise
            if chunk_id in self._retired:
                self._reject(seq, "RetiredChunkError", chunk_id)
                raise RetiredChunkError(
                    f"chunk_id {chunk_id!r} already retired"
                )
            if chunk_id not in self._chunks:
                self._reject(seq, "UnknownChunkError", chunk_id)
                raise UnknownChunkError(
                    f"unknown chunk_id: {chunk_id!r}"
                )
            self._remove_postings(chunk_id)
            del self._chunks[chunk_id]
            self._retired.add(chunk_id)
            record = RetireRecord(chunk_id=chunk_id, reason=reason, seq=seq)
            self._audit.append(
                rag_pipeline_audit_event(
                    KIND_RETIRED,
                    {"chunk_id": chunk_id, "reason": reason},
                    seq,
                )
            )
            return record

    # -- pure read views ----------------------------------------------------

    def chunk(self, chunk_id: str) -> Optional[Dict[str, Any]]:
        """Return the booked pins for a live chunk, else None."""
        with self._lock:
            entry = self._chunks.get(chunk_id)
            if entry is None:
                return None
            return {
                "chunk_id": chunk_id,
                "source": entry["source"],
                "term_count": entry["term_count"],
                "unique_terms": len(entry["terms"]),
                "digest": entry["digest"],
            }

    def chunk_ids(self) -> Tuple[str, ...]:
        """Sorted ids of live chunks."""
        with self._lock:
            return tuple(sorted(self._chunks))

    def retired_ids(self) -> Tuple[str, ...]:
        """Sorted ids of retired chunks."""
        with self._lock:
            return tuple(sorted(self._retired))

    def retrieval(self, retrieval_id: str) -> Optional[RetrievalRecord]:
        """Return a booked retrieval record, else None."""
        with self._lock:
            return self._retrievals.get(retrieval_id)

    def generation(self, generation_id: str) -> Optional[GenerationRecord]:
        """Return a booked generation record, else None."""
        with self._lock:
            return self._generations.get(generation_id)

    def citations_for(self, generation_id: str) -> Tuple[CitationRecord, ...]:
        """Citations bound to one generation, in citation order."""
        with self._lock:
            return tuple(
                c
                for c in self._citations.values()
                if c.generation_id == generation_id
            )

    def stats(self) -> Dict[str, Any]:
        """Ledger counters."""
        with self._lock:
            return {
                "schema": RAG_PIPELINE_SCHEMA,
                "live_chunks": len(self._chunks),
                "retired_chunks": len(self._retired),
                "retrievals": len(self._retrievals),
                "generations": len(self._generations),
                "citations": len(self._citations),
                "last_seq": self._last_seq,
            }

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        """Booked audit rows, oldest first."""
        with self._lock:
            return tuple(self._audit)


def main() -> None:
    """Self-check smoke run."""
    pipe = RAGPipeline()
    pipe.ingest("c1", "the quick brown fox jumps over the lazy dog", 1)
    pipe.ingest("c2", "a fast red car drives down the road", 2)
    ret = pipe.retrieve("quick fox", 3)
    assert ret.total_matched >= 1 and ret.hits[0].chunk_id == "c1"
    gen = pipe.generate(
        "quick fox", ret.retrieval_id, 4, "The fox is quick.", ("c1",)
    )
    cit = pipe.cite(gen.generation_id, "the fox is quick", "c1", 5)
    assert cit.chunk_id == "c1"
    pipe.retire("c2", 6, reason="stale")
    assert pipe.chunk("c2") is None
    print("rag-pipeline OK: ingest, retrieve, generate, cite, retire")


if __name__ == "__main__":
    main()
