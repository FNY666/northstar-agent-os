"""Full-text search with an explicit analyzed tokenizer and ranked retrieval.

A ``FullTextSearch`` instance keeps a deterministic, single-host inverted
index over caller-supplied documents:

* ``tokenize(text, seq)`` makes tokenization an explicit, audited decision:
  lowercase word tokens (``[a-z0-9_]+``), stop-word removal against a pinned
  English stop list, and a minimum-token-length floor of 2. Returns a frozen
  ``TokenizeRecord`` with a ``sha256:`` digest pin over the canonical token
  list.
* ``index(doc_id, text, seq)`` tokenizes ``text`` with the same analyzer,
  records per-term frequencies for ``doc_id``, and returns a frozen
  ``IndexRecord`` with a ``sha256:`` digest pin.
* ``query(text, seq)`` tokenizes the query text, refuses queries that analyze
  down to zero terms fail-closed, and returns a frozen ``QueryRecord``
  (``q-N`` ids) pinning the query's analyzed terms.
* ``rank(query_id, seq, top_k=10)`` executes the stored query plan against the
  index and returns a frozen ``RankReport`` of ``ScoredHit`` records sorted
  by descending score with ``doc_id`` tiebreaks. Scoring is saturated TF
  ``f / (f + 1)`` times a probabilistic ``idf`` ``ln((N - df + 0.5) /
  (df + 0.5) + 1)``, plus a coverage bonus ``0.25 * coverage * sum(idf)``
  rewarding documents that match more distinct query terms.

Relation to the siblings: ``fulltext_search`` offers raw word-token TF-IDF
``index/rank/search`` over raw query text; ``search_engine`` adds a parsed
boolean/phrase query language with BM25. This module is the *analyzed*
layer: explicit audited tokenization decisions (stop-word removal, length
floor) pinned as records, a query session ledger (``query()`` once,
``rank()`` many times), and a distinct saturated-TF + coverage-bonus score.

House style: no wall-clock (caller int seqs only, strictly increasing on
mutations; failed mutations consume their seq and book a rejected audit
row), frozen records, RLock-guarded, fail-closed validation, stdlib-only
(``hashlib``, ``math``, ``re``, ``threading``, ``dataclasses``, ``typing``
plus the standard ``canonical_json`` try/except fallback), deterministic,
version/schema pins, ``main()`` self-check.

Honest scope: this is ranking bookkeeping over *host-reported* text. A hit
says "this document matched the analyzed query plan by this score on the
reported text", never "this document is relevant or true". Tokenization is
a simple word regex; no stemming, no language detection, no phrase queries.
Stop-word removal can erase short queries (refused as ``EmptyQueryError``);
a score of zero means "no shared terms", not "unrelated".

Version pin: full-text-search.v1
Schema pin: northstar.full-text-search.v1
"""

from __future__ import annotations

import hashlib
import math
import re
import threading
from dataclasses import dataclass
from typing import Dict, FrozenSet, List, Mapping, Optional, Tuple

try:  # prefer the repo-wide canonical JSON when importable
    from canonical_json import canonical_json as _canonical_json

    def _encode(value: object) -> bytes:
        return _canonical_json(value).encode("utf-8")

except Exception:  # defensive fallback: local type-tagged encoder

    def _encode(value: object) -> bytes:
        import json

        if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
            raise FullTextSearchError("non-finite float cannot be canonicalized")
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")


FULL_TEXT_SEARCH_VERSION = "full-text-search.v1"
SCHEMA_PIN = "northstar.full-text-search.v1"
AUDIT_FORMAT = "audit.ndjson/1"

AUDIT_TOKENIZED = "tokenized"
AUDIT_INDEXED = "indexed"
AUDIT_QUERIED = "queried"
AUDIT_RANKED = "ranked"
AUDIT_REJECTED = "rejected"
_AUDIT_KINDS = frozenset(
    {AUDIT_TOKENIZED, AUDIT_INDEXED, AUDIT_QUERIED, AUDIT_RANKED, AUDIT_REJECTED}
)

# Pinned stop list (English). Query/document terms in this set are dropped by
# the analyzer. The set is pinned so identical inputs always analyze the same
# way; it is not language detection.
STOP_WORDS: FrozenSet[str] = frozenset(
    {
        "a", "an", "the", "and", "or", "but", "if", "then", "else", "when",
        "at", "by", "for", "with", "about", "into", "through", "during",
        "before", "after", "above", "below", "to", "from", "up", "down",
        "in", "out", "on", "off", "over", "under", "again", "further",
        "once", "here", "there", "all", "any", "both", "each", "few",
        "more", "most", "other", "some", "such", "no", "nor", "not",
        "only", "own", "same", "so", "than", "too", "very", "can",
        "will", "just", "don", "should", "now", "is", "are", "was",
        "were", "be", "been", "being", "have", "has", "had", "having",
        "do", "does", "did", "doing", "would", "could", "ought", "am",
        "as", "i", "me", "my", "myself", "we", "our", "ours",
        "ourselves", "you", "your", "yours", "yourself", "yourselves",
        "he", "him", "his", "himself", "she", "her", "hers", "herself",
        "it", "its", "itself", "they", "them", "their", "theirs",
        "themselves", "what", "which", "who", "whom", "this", "that",
        "these", "those",
    }
)
MIN_TOKEN_LENGTH = 2
_COVERAGE_BONUS_WEIGHT = 0.25

_TOKEN_RE = re.compile(r"[a-z0-9_]+")


class FullTextSearchError(Exception):
    """Base class for full-text-search errors."""


class DuplicateDocumentError(FullTextSearchError):
    """Raised when indexing a doc_id that is already indexed."""


class UnknownDocumentError(FullTextSearchError):
    """Raised when looking up a doc_id that was never indexed."""


class UnknownQueryError(FullTextSearchError):
    """Raised when ranking against a query_id that was never booked."""


class EmptyQueryError(FullTextSearchError):
    """Raised when a query analyzes down to zero terms."""


class SeqOrderError(FullTextSearchError):
    """Raised when a caller seq is not a strictly increasing int."""


class AuditKindError(FullTextSearchError):
    """Raised when building an audit event with an unknown kind."""


def _require_seq(value: object, name: str = "seq") -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise FullTextSearchError(f"{name} must be a non-negative int, got {value!r}")
    return value


def _require_doc_id(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 256:
        raise FullTextSearchError(f"doc_id must be a non-empty str (<=256), got {value!r}")
    return value


def _require_text(value: object, name: str = "text") -> str:
    if not isinstance(value, str):
        raise FullTextSearchError(f"{name} must be a str, got {type(value).__name__}")
    if len(value) > 1_048_576:
        raise FullTextSearchError(f"{name} exceeds 1 MiB")
    return value


def _require_query_id(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise FullTextSearchError(f"query_id must be a non-empty str, got {value!r}")
    return value


def _require_top_k(value: object) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise FullTextSearchError(f"top_k must be a positive int or None, got {value!r}")
    return value


def _digest_pin(parts: Mapping[str, object]) -> str:
    return "sha256:" + hashlib.sha256(_encode(dict(parts))).hexdigest()


def _check_digest(pin: object) -> str:
    if (
        not isinstance(pin, str)
        or not pin.startswith("sha256:")
        or len(pin) != 7 + 64
    ):
        raise FullTextSearchError(f"bad digest pin: {pin!r}")
    try:
        int(pin[7:], 16)
    except ValueError:
        raise FullTextSearchError(f"bad digest pin: {pin!r}") from None
    return pin


def _analyze(text: str) -> Tuple[str, ...]:
    """The pinned analyzer: lowercase, word regex, stop-word removal, length floor."""
    raw = _TOKEN_RE.findall(text.lower())
    return tuple(t for t in raw if len(t) >= MIN_TOKEN_LENGTH and t not in STOP_WORDS)


@dataclass(frozen=True)
class TokenizeRecord:
    """One audited tokenization decision."""

    tokenize_id: str
    text_digest: str
    tokens: Tuple[str, ...]
    token_count: int
    seq: int
    digest: str
    version: str = FULL_TEXT_SEARCH_VERSION
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        _check_digest(self.text_digest)
        _check_digest(self.digest)
        if self.token_count != len(self.tokens):
            raise FullTextSearchError("token_count != len(tokens)")

    def as_dict(self) -> dict:
        return {
            "tokenize_id": self.tokenize_id,
            "text_digest": self.text_digest,
            "tokens": list(self.tokens),
            "token_count": self.token_count,
            "seq": self.seq,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }

    def verify(self) -> bool:
        expect = _digest_pin(
            {
                "tokenize_id": self.tokenize_id,
                "text_digest": self.text_digest,
                "tokens": list(self.tokens),
                "seq": self.seq,
                "version": self.version,
                "schema": self.schema,
            }
        )
        return expect == self.digest


@dataclass(frozen=True)
class IndexRecord:
    """One indexed document."""

    doc_id: str
    term_freqs: Tuple[Tuple[str, int], ...]
    total_terms: int
    unique_terms: int
    seq: int
    digest: str
    version: str = FULL_TEXT_SEARCH_VERSION
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        _check_digest(self.digest)
        freqs = dict(self.term_freqs)
        if sum(freqs.values()) != self.total_terms:
            raise FullTextSearchError("term frequencies do not sum to total_terms")
        if len(freqs) != self.unique_terms:
            raise FullTextSearchError("unique_terms mismatch")

    def as_dict(self) -> dict:
        return {
            "doc_id": self.doc_id,
            "term_freqs": [[t, f] for t, f in self.term_freqs],
            "total_terms": self.total_terms,
            "unique_terms": self.unique_terms,
            "seq": self.seq,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }

    def verify(self) -> bool:
        expect = _digest_pin(
            {
                "doc_id": self.doc_id,
                "term_freqs": [[t, f] for t, f in self.term_freqs],
                "total_terms": self.total_terms,
                "unique_terms": self.unique_terms,
                "seq": self.seq,
                "version": self.version,
                "schema": self.schema,
            }
        )
        return expect == self.digest


@dataclass(frozen=True)
class QueryRecord:
    """One booked query plan."""

    query_id: str
    terms: Tuple[str, ...]
    term_count: int
    seq: int
    digest: str
    version: str = FULL_TEXT_SEARCH_VERSION
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        _check_digest(self.digest)
        if not self.terms:
            raise FullTextSearchError("query terms must be non-empty")
        if self.term_count != len(self.terms):
            raise FullTextSearchError("term_count != len(terms)")

    def as_dict(self) -> dict:
        return {
            "query_id": self.query_id,
            "terms": list(self.terms),
            "term_count": self.term_count,
            "seq": self.seq,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }

    def verify(self) -> bool:
        expect = _digest_pin(
            {
                "query_id": self.query_id,
                "terms": list(self.terms),
                "seq": self.seq,
                "version": self.version,
                "schema": self.schema,
            }
        )
        return expect == self.digest


@dataclass(frozen=True)
class ScoredHit:
    """One ranked document."""

    doc_id: str
    score: float
    matched_terms: Tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.score, (int, float)) or isinstance(self.score, bool):
            raise FullTextSearchError(f"score must be a number, got {self.score!r}")
        if not math.isfinite(self.score) or self.score < 0:
            raise FullTextSearchError(f"score must be finite and >= 0, got {self.score!r}")

    def as_dict(self) -> dict:
        return {
            "doc_id": self.doc_id,
            "score": self.score,
            "matched_terms": list(self.matched_terms),
        }


@dataclass(frozen=True)
class RankReport:
    """One ranked result set for a query."""

    query_id: str
    hits: Tuple[ScoredHit, ...]
    total_indexed: int
    top_k: Optional[int]
    seq: int
    digest: str
    version: str = FULL_TEXT_SEARCH_VERSION
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        _check_digest(self.digest)

    def as_dict(self) -> dict:
        return {
            "query_id": self.query_id,
            "hits": [h.as_dict() for h in self.hits],
            "total_indexed": self.total_indexed,
            "top_k": self.top_k,
            "seq": self.seq,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }

    def verify(self) -> bool:
        expect = _digest_pin(
            {
                "query_id": self.query_id,
                "hits": [h.as_dict() for h in self.hits],
                "total_indexed": self.total_indexed,
                "top_k": self.top_k,
                "seq": self.seq,
                "version": self.version,
                "schema": self.schema,
            }
        )
        return expect == self.digest


def full_text_search_audit_event(kind: str, seq: int, **detail: object) -> dict:
    """Build an ``audit.ndjson/1``-shaped audit event."""
    if kind not in _AUDIT_KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _require_seq(seq)
    # Raw text and token lists stay out of the audit boundary; only pins,
    # counts, ids, and scores cross it.
    banned = {"text", "tokens", "terms", "term_freqs"}
    for key in detail:
        if key in banned:
            raise AuditKindError(f"key {key!r} is banned from the audit boundary")
    event = {
        "format": AUDIT_FORMAT,
        "kind": f"full-text-search.{kind}",
        "seq": seq,
        "version": FULL_TEXT_SEARCH_VERSION,
        "schema": SCHEMA_PIN,
    }
    event.update(detail)
    return event


class FullTextSearch:
    """Deterministic single-host inverted index with analyzed retrieval."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = -1
        self._tokenize_counter = 0
        self._query_counter = 0
        self._tokenizes: Dict[str, TokenizeRecord] = {}
        self._docs: Dict[str, IndexRecord] = {}
        # term -> {doc_id: freq}
        self._postings: Dict[str, Dict[str, int]] = {}
        self._queries: Dict[str, QueryRecord] = {}
        self._audit_events: List[dict] = []

    # -- internal plumbing -------------------------------------------------

    def _claim(self, seq: int) -> int:
        seq = _require_seq(seq)
        if seq <= self._seq:
            raise SeqOrderError(f"seq must be strictly increasing, got {seq} after {self._seq}")
        self._seq = seq
        return seq

    def _audit(self, kind: str, seq: int, **detail: object) -> None:
        self._audit_events.append(full_text_search_audit_event(kind, seq, **detail))

    def _reject(self, seq: int, error: FullTextSearchError, **detail: object) -> FullTextSearchError:
        # Failed mutations consume their seq (batch-21 discipline) and book a
        # rejected audit row; seq rewinds raise bare without consuming.
        if isinstance(error, SeqOrderError):
            raise error
        self._claim(seq)
        self._audit(
            AUDIT_REJECTED,
            seq,
            error_type=type(error).__name__,
            error=str(error),
            **detail,
        )
        return error

    # -- tokenizer ---------------------------------------------------------

    def tokenize(self, text: str, seq: int) -> TokenizeRecord:
        """Tokenize ``text`` and book the decision as a frozen record."""
        with self._lock:
            try:
                _require_text(text)
                _require_seq(seq)
                if seq <= self._seq:
                    raise SeqOrderError(
                        f"seq must be strictly increasing, got {seq} after {self._seq}"
                    )
            except FullTextSearchError as exc:
                raise self._reject(seq, exc)
            self._seq = seq
            self._tokenize_counter += 1
            tokenize_id = f"tok-{self._tokenize_counter}"
            text_digest = "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()
            tokens = _analyze(text)
            digest = _digest_pin(
                {
                    "tokenize_id": tokenize_id,
                    "text_digest": text_digest,
                    "tokens": list(tokens),
                    "seq": seq,
                    "version": FULL_TEXT_SEARCH_VERSION,
                    "schema": SCHEMA_PIN,
                }
            )
            record = TokenizeRecord(
                tokenize_id=tokenize_id,
                text_digest=text_digest,
                tokens=tokens,
                token_count=len(tokens),
                seq=seq,
                digest=digest,
            )
            self._tokenizes[tokenize_id] = record
            self._audit(
                AUDIT_TOKENIZED,
                seq,
                tokenize_id=tokenize_id,
                text_digest=text_digest,
                token_count=len(tokens),
                record_digest=digest,
            )
            return record

    # -- index -------------------------------------------------------------

    def index(self, doc_id: str, text: str, seq: int) -> IndexRecord:
        """Index one document under the analyzed tokenizer."""
        with self._lock:
            try:
                _require_doc_id(doc_id)
                _require_text(text)
                _require_seq(seq)
                if seq <= self._seq:
                    raise SeqOrderError(
                        f"seq must be strictly increasing, got {seq} after {self._seq}"
                    )
                if doc_id in self._docs:
                    raise DuplicateDocumentError(f"doc_id already indexed: {doc_id!r}")
            except FullTextSearchError as exc:
                raise self._reject(seq, exc, doc_id=doc_id if isinstance(doc_id, str) else "")
            self._seq = seq
            tokens = _analyze(text)
            freqs: Dict[str, int] = {}
            for token in tokens:
                freqs[token] = freqs.get(token, 0) + 1
            term_freqs = tuple(sorted(freqs.items()))
            digest = _digest_pin(
                {
                    "doc_id": doc_id,
                    "term_freqs": [[t, f] for t, f in term_freqs],
                    "total_terms": len(tokens),
                    "unique_terms": len(freqs),
                    "seq": seq,
                    "version": FULL_TEXT_SEARCH_VERSION,
                    "schema": SCHEMA_PIN,
                }
            )
            record = IndexRecord(
                doc_id=doc_id,
                term_freqs=term_freqs,
                total_terms=len(tokens),
                unique_terms=len(freqs),
                seq=seq,
                digest=digest,
            )
            self._docs[doc_id] = record
            for term, freq in term_freqs:
                self._postings.setdefault(term, {})[doc_id] = freq
            self._audit(
                AUDIT_INDEXED,
                seq,
                doc_id=doc_id,
                total_terms=len(tokens),
                unique_terms=len(freqs),
                record_digest=digest,
            )
            return record

    def record(self, doc_id: str) -> IndexRecord:
        """Pure read view of one indexed document."""
        with self._lock:
            _require_doc_id(doc_id)
            try:
                return self._docs[doc_id]
            except KeyError:
                raise UnknownDocumentError(f"unknown doc_id: {doc_id!r}") from None

    def doc_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._docs))

    # -- query -------------------------------------------------------------

    def query(self, text: str, seq: int) -> QueryRecord:
        """Book an analyzed query plan (``query()`` once, ``rank()`` many times)."""
        with self._lock:
            try:
                _require_text(text, name="query")
                _require_seq(seq)
                if seq <= self._seq:
                    raise SeqOrderError(
                        f"seq must be strictly increasing, got {seq} after {self._seq}"
                    )
                terms = _analyze(text)
                if not terms:
                    raise EmptyQueryError(
                        "query analyzes down to zero terms (stop words / length floor)"
                    )
            except FullTextSearchError as exc:
                raise self._reject(seq, exc)
            self._seq = seq
            self._query_counter += 1
            query_id = f"q-{self._query_counter}"
            # Deduplicate terms for the plan while keeping deterministic order.
            unique_terms = tuple(sorted(set(terms)))
            digest = _digest_pin(
                {
                    "query_id": query_id,
                    "terms": list(unique_terms),
                    "seq": seq,
                    "version": FULL_TEXT_SEARCH_VERSION,
                    "schema": SCHEMA_PIN,
                }
            )
            record = QueryRecord(
                query_id=query_id,
                terms=unique_terms,
                term_count=len(unique_terms),
                seq=seq,
                digest=digest,
            )
            self._queries[query_id] = record
            self._audit(
                AUDIT_QUERIED,
                seq,
                query_id=query_id,
                term_count=len(unique_terms),
                record_digest=digest,
            )
            return record

    def query_record(self, query_id: str) -> QueryRecord:
        """Pure read view of a booked query plan."""
        with self._lock:
            _require_query_id(query_id)
            try:
                return self._queries[query_id]
            except KeyError:
                raise UnknownQueryError(f"unknown query_id: {query_id!r}") from None

    # -- rank --------------------------------------------------------------

    def _idf(self, term: str, total_docs: int) -> float:
        df = len(self._postings.get(term, {}))
        return math.log((total_docs - df + 0.5) / (df + 0.5) + 1.0)

    def rank(self, query_id: str, seq: int, top_k: Optional[int] = 10) -> RankReport:
        """Execute a booked query plan and return ranked hits."""
        with self._lock:
            try:
                _require_query_id(query_id)
                top_k = _require_top_k(top_k)
                _require_seq(seq)
                if seq <= self._seq:
                    raise SeqOrderError(
                        f"seq must be strictly increasing, got {seq} after {self._seq}"
                    )
                if query_id not in self._queries:
                    raise UnknownQueryError(f"unknown query_id: {query_id!r}")
            except FullTextSearchError as exc:
                raise self._reject(seq, exc, query_id=query_id if isinstance(query_id, str) else "")
            self._seq = seq
            plan = self._queries[query_id]
            total_docs = len(self._docs)
            hits: List[ScoredHit] = []
            if total_docs:
                idfs = {term: self._idf(term, total_docs) for term in plan.terms}
                idf_sum = sum(idfs.values())
                for doc_id in sorted(self._docs):
                    matched: List[str] = []
                    score = 0.0
                    for term in plan.terms:
                        freq = self._postings.get(term, {}).get(doc_id, 0)
                        if freq:
                            matched.append(term)
                            score += idfs[term] * (freq / (freq + 1.0))
                    if not matched:
                        continue
                    coverage = len(matched) / len(plan.terms)
                    score += _COVERAGE_BONUS_WEIGHT * coverage * idf_sum
                    hits.append(
                        ScoredHit(
                            doc_id=doc_id,
                            score=round(score, 6),
                            matched_terms=tuple(sorted(matched)),
                        )
                    )
                hits.sort(key=lambda h: (-h.score, h.doc_id))
            if top_k is not None:
                hits = hits[:top_k]
            digest = _digest_pin(
                {
                    "query_id": query_id,
                    "hits": [h.as_dict() for h in hits],
                    "total_indexed": total_docs,
                    "top_k": top_k,
                    "seq": seq,
                    "version": FULL_TEXT_SEARCH_VERSION,
                    "schema": SCHEMA_PIN,
                }
            )
            report = RankReport(
                query_id=query_id,
                hits=tuple(hits),
                total_indexed=total_docs,
                top_k=top_k,
                seq=seq,
                digest=digest,
            )
            self._audit(
                AUDIT_RANKED,
                seq,
                query_id=query_id,
                hit_count=len(hits),
                total_indexed=total_docs,
                top_k=top_k,
                report_digest=digest,
            )
            return report

    # -- views -------------------------------------------------------------

    def stats(self, seq: int) -> dict:
        """Pure read view: index statistics. Consumes no seq."""
        with self._lock:
            _require_seq(seq)
            return {
                "documents": len(self._docs),
                "unique_terms": len(self._postings),
                "queries": len(self._queries),
                "tokenize_calls": self._tokenize_counter,
                "version": FULL_TEXT_SEARCH_VERSION,
                "schema": SCHEMA_PIN,
            }

    def audit_log(self) -> Tuple[dict, ...]:
        with self._lock:
            return tuple(self._audit_events)

    def __len__(self) -> int:
        with self._lock:
            return len(self._docs)


def main() -> None:
    fts = FullTextSearch()
    rec = fts.tokenize("The quick brown fox jumps", 0)
    assert rec.tokens == ("quick", "brown", "fox", "jumps"), rec.tokens
    assert rec.verify()
    fts.index("d1", "the quick brown fox jumps over the lazy dog", 1)
    fts.index("d2", "a quick brown dog barks loudly at night", 2)
    fts.index("d3", "completely unrelated words about plumbing", 3)
    q = fts.query("quick fox", 4)
    assert q.verify()
    report = fts.rank(q.query_id, 5)
    assert report.verify()
    assert report.hits[0].doc_id == "d1", [h.doc_id for h in report.hits]
    assert report.hits[0].score > report.hits[1].score
    print("full-text-search OK: tokenize, index, query, rank, pins, audit")


if __name__ == "__main__":
    main()
