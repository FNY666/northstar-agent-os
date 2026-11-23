"""Full-text search with TF-IDF ranking over an inverted index.

A ``FulltextSearch`` instance keeps a deterministic, single-host inverted
index over caller-supplied documents:

* ``index(doc_id, text, seq)`` tokenizes ``text`` (lowercase word tokens),
  records per-term frequencies for ``doc_id``, and returns a frozen
  ``IndexRecord`` with a ``sha256:`` digest pin over the canonical record
  body.
* ``rank(query, seq, doc_ids=())`` scores documents by TF-IDF and returns
  them sorted by descending score: ``tf`` is log-normalized
  ``1 + ln(f)`` for a term occurring ``f`` times, ``idf`` is the smoothed
  ``ln((N + 1) / (df + 1)) + 1`` over ``N`` indexed documents. Ties break
  by ``doc_id`` so identical corpora always rank identically.
* ``search(query, seq, top_k=10)`` ranks every indexed document and
  returns a frozen ``SearchResults`` record truncated to ``top_k``
  non-zero-score hits.

House style: no wall-clock (caller int seqs only), frozen records,
fail-closed validation, stdlib-only (``hashlib``, ``math``, ``re``,
``dataclasses``, ``typing`` plus the standard ``canonical_json``
try/except fallback), deterministic, version/schema pins, ``main()``
self-check.

Honest scope: this is ranking bookkeeping over *host-reported* text.
A score says "this document matched the query by TF-IDF on the reported
text", never "this document is relevant or true". Tokenization is a
simple word regex (ASCII letters/digits plus underscore); no stemming,
no stop-word removal, no language detection, no phrase queries. A score
of zero means "no shared terms", not "unrelated".

Version pin: fulltext-search.v1
Schema pin: northstar.fulltext-search.v1
"""

from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, Iterable, List, Mapping, Optional, Tuple

try:  # prefer the repo-wide canonical JSON when importable
    from canonical_json import canonical_json as _canonical_json

    def _encode(value: object) -> bytes:
        return _canonical_json(value).encode("utf-8")

except Exception:  # defensive fallback: local type-tagged encoder

    def _encode(value: object) -> bytes:
        import json

        if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
            raise FulltextError("non-finite float cannot be canonicalized")
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")


#: Module version.
FULLTEXT_SEARCH_VERSION = "fulltext-search.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.fulltext-search.v1"

#: Audit event kinds.
AUDIT_INDEXED = "indexed"
AUDIT_SEARCHED = "searched"
AUDIT_REJECTED = "rejected"

_AUDIT_KINDS = frozenset({AUDIT_INDEXED, AUDIT_SEARCHED, AUDIT_REJECTED})

#: Token pattern: word characters (letters, digits, underscore).
_TOKEN_RE = re.compile(r"[A-Za-z0-9_]+")


class FulltextError(Exception):
    """Base error for the full-text search module."""


class DuplicateDocumentError(FulltextError):
    """Raised when a doc_id is indexed twice."""


class UnknownDocumentError(FulltextError):
    """Raised when an operation names a document that was never indexed."""


def _require_seq(value: object, name: str = "seq") -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise FulltextError(f"{name} must be a non-negative int, got {value!r}")
    return value


def _require_doc_id(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise FulltextError(f"doc_id must be a non-empty str, got {value!r}")
    return value


def _require_text(value: object) -> str:
    if not isinstance(value, str):
        raise FulltextError(f"text must be a str, got {type(value).__name__}")
    return value


def _require_query(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise FulltextError(f"query must be a non-empty str, got {value!r}")
    return value


def _require_top_k(value: object) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise FulltextError(f"top_k must be a positive int or None, got {value!r}")
    return value


def _tokenize(text: str) -> Tuple[str, ...]:
    """Lowercase word tokens from text."""
    return tuple(tok.lower() for tok in _TOKEN_RE.findall(text))


def _digest_pin(parts: Mapping[str, object]) -> str:
    return "sha256:" + hashlib.sha256(_encode(parts)).hexdigest()


@dataclass(frozen=True)
class IndexRecord:
    """Frozen record of one indexed document."""

    doc_id: str
    term_count: int
    unique_terms: int
    digest: str
    seq: int
    version: str = FULLTEXT_SEARCH_VERSION
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        if not self.digest.startswith("sha256:"):
            raise FulltextError(f"bad digest pin: {self.digest!r}")

    def as_dict(self) -> dict:
        return {
            "doc_id": self.doc_id,
            "term_count": self.term_count,
            "unique_terms": self.unique_terms,
            "digest": self.digest,
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class ScoredDoc:
    """One ranked document: doc_id, TF-IDF score, and the matched terms."""

    doc_id: str
    score: float
    matched_terms: Tuple[str, ...]

    def __post_init__(self) -> None:
        if isinstance(self.score, bool) or not isinstance(
            self.score, (int, float)
        ):
            raise FulltextError(f"score must be a number, got {self.score!r}")
        if self.score < 0 or math.isnan(self.score) or math.isinf(self.score):
            raise FulltextError(f"score must be finite and >= 0, got {self.score!r}")

    def as_dict(self) -> dict:
        return {
            "doc_id": self.doc_id,
            "score": self.score,
            "matched_terms": list(self.matched_terms),
        }


@dataclass(frozen=True)
class SearchResults:
    """Frozen result of one search: ranked hits, query pin, total scored."""

    query: str
    query_digest: str
    hits: Tuple[ScoredDoc, ...]
    total_scored: int
    seq: int
    version: str = FULLTEXT_SEARCH_VERSION
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        if not self.query_digest.startswith("sha256:"):
            raise FulltextError(f"bad query digest pin: {self.query_digest!r}")

    def as_dict(self) -> dict:
        return {
            "query": self.query,
            "query_digest": self.query_digest,
            "hits": [h.as_dict() for h in self.hits],
            "total_scored": self.total_scored,
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass
class FulltextSearch:
    """Deterministic inverted index with TF-IDF ranking."""

    def __init__(self) -> None:
        # doc_id -> tuple of tokens (keeps duplicates for tf)
        self._docs: Dict[str, Tuple[str, ...]] = {}
        # term -> {doc_id: frequency}
        self._postings: Dict[str, Dict[str, int]] = {}
        # doc_id -> sha256: digest pin over the canonical record body
        self._pins: Dict[str, str] = {}

    def __len__(self) -> int:
        return len(self._docs)

    def doc_ids(self) -> Tuple[str, ...]:
        return tuple(sorted(self._docs))

    def index(self, doc_id: str, text: str, seq: int) -> IndexRecord:
        """Index one document; duplicate doc_id is refused fail-closed."""
        doc_id = _require_doc_id(doc_id)
        text = _require_text(text)
        seq = _require_seq(seq)
        if doc_id in self._docs:
            raise DuplicateDocumentError(f"doc_id already indexed: {doc_id!r}")
        tokens = _tokenize(text)
        self._docs[doc_id] = tokens
        for term in set(tokens):
            freq = tokens.count(term)
            self._postings.setdefault(term, {})[doc_id] = freq
        pin = _digest_pin(
            {"doc_id": doc_id, "tokens": list(tokens), "seq": seq}
        )
        self._pins[doc_id] = pin
        return IndexRecord(
            doc_id=doc_id,
            term_count=len(tokens),
            unique_terms=len(set(tokens)),
            digest=pin,
            seq=seq,
        )

    def record(self, doc_id: str) -> IndexRecord:
        """Return the index record for an already-indexed document."""
        doc_id = _require_doc_id(doc_id)
        if doc_id not in self._docs:
            raise UnknownDocumentError(f"unknown doc_id: {doc_id!r}")
        tokens = self._docs[doc_id]
        # Re-derive the pin deterministically from stored content; the
        # original seq is not recoverable, so this view carries seq=0 as
        # an explicit placeholder (not a claim about the index seq).
        pin = self._pins[doc_id]
        return IndexRecord(
            doc_id=doc_id,
            term_count=len(tokens),
            unique_terms=len(set(tokens)),
            digest=pin,
            seq=0,
        )

    def _idf(self, term: str) -> float:
        n = len(self._docs)
        df = len(self._postings.get(term, ()))
        return math.log((n + 1) / (df + 1)) + 1.0

    @staticmethod
    def _tf(freq: int) -> float:
        return 1.0 + math.log(freq) if freq > 0 else 0.0

    def rank(
        self,
        query: str,
        seq: int,
        doc_ids: Iterable[str] = (),
    ) -> Tuple[ScoredDoc, ...]:
        """TF-IDF scores for query terms across documents, sorted desc.

        ``doc_ids`` restricts scoring to the named documents; empty means
        every indexed document. Unknown ids raise ``UnknownDocumentError``.
        """
        query = _require_query(query)
        _require_seq(seq)
        candidates: Tuple[str, ...]
        given = tuple(doc_ids)
        if given:
            for did in given:
                _require_doc_id(did)
                if did not in self._docs:
                    raise UnknownDocumentError(f"unknown doc_id: {did!r}")
            candidates = given
        else:
            candidates = tuple(sorted(self._docs))
        query_terms = _tokenize(query)
        if not query_terms:
            return ()
        scored: List[ScoredDoc] = []
        for doc_id in candidates:
            tokens = self._docs[doc_id]
            counts: Dict[str, int] = {}
            for term in set(query_terms):
                freq = tokens.count(term)
                if freq:
                    counts[term] = freq
            if not counts:
                continue
            score = 0.0
            for term, freq in counts.items():
                score += self._tf(freq) * self._idf(term)
            scored.append(
                ScoredDoc(
                    doc_id=doc_id,
                    score=score,
                    matched_terms=tuple(sorted(counts)),
                )
            )
        # Descending score; doc_id tiebreak for determinism.
        scored.sort(key=lambda s: (-s.score, s.doc_id))
        return tuple(scored)

    def search(
        self, query: str, seq: int, top_k: Optional[int] = 10
    ) -> SearchResults:
        """Rank all indexed documents and return the top_k non-zero hits."""
        query = _require_query(query)
        seq = _require_seq(seq)
        top_k = _require_top_k(top_k)
        ranked = self.rank(query, seq)
        hits = tuple(ranked[:top_k] if top_k is not None else ranked)
        query_digest = _digest_pin(
            {"query": query, "terms": list(_tokenize(query))}
        )
        return SearchResults(
            query=query,
            query_digest=query_digest,
            hits=hits,
            total_scored=len(ranked),
            seq=seq,
        )


def fulltext_search_audit_event(kind: str, seq: int, **fields: object) -> dict:
    """Audit-shaped record for a full-text search transition."""
    if kind not in _AUDIT_KINDS:
        raise FulltextError(f"unknown audit kind: {kind!r}")
    _require_seq(seq)
    event: dict = {
        "schema": SCHEMA_PIN,
        "audit_seq": seq,
        "kind": kind,
        "module_version": FULLTEXT_SEARCH_VERSION,
    }
    event.update(fields)
    return event


def main() -> None:
    idx = FulltextSearch()
    r1 = idx.index("d1", "the quick brown fox jumps over the lazy dog", 1)
    assert r1.term_count == 9, f"{r1.term_count}"
    assert r1.unique_terms == 8, f"{r1.unique_terms}"  # "the" twice
    assert r1.digest.startswith("sha256:"), f"{r1.digest}"
    idx.index("d2", "never jump over the lazy dog quickly", 2)
    idx.index("d3", "bright vixens jump; dozy fowl quack", 3)
    assert len(idx) == 3, f"{len(idx)}"

    # "fox" appears only in d1 -> highest idf -> d1 must top.
    hits = idx.rank("fox", 4)
    assert hits and hits[0].doc_id == "d1", f"{hits}"
    assert hits[0].matched_terms == ("fox",), f"{hits[0].matched_terms}"
    assert hits[0].score > 0, f"{hits[0].score}"

    # Common term "the": d1 has tf 2, d2 has tf 1 -> d1 outranks d2.
    ranked = idx.rank("the", 5)
    by_id = {s.doc_id: s for s in ranked}
    assert set(by_id) == {"d1", "d2"}, f"{by_id.keys()}"
    assert by_id["d1"].score > by_id["d2"].score, f"{ranked}"

    # search() truncates to top_k.
    res = idx.search("jump lazy", 6, top_k=1)
    assert len(res.hits) == 1, f"{res.hits}"
    assert res.total_scored >= 1, f"{res.total_scored}"
    assert res.query_digest.startswith("sha256:"), f"{res.query_digest}"

    # No shared terms -> no hits, not an error.
    res = idx.search("zyxwvu", 7)
    assert res.hits == () and res.total_scored == 0, f"{res}"

    # Determinism: identical runs rank identically.
    assert [h.doc_id for h in idx.rank("jump", 8)] == [
        h.doc_id for h in idx.rank("jump", 9)
    ]
    print("fulltext-search OK: index, tf-idf rank, top_k, determinism")


if __name__ == "__main__":
    main()
