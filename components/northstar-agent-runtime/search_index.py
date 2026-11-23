"""Search index: Elasticsearch-shaped document index lifecycle bookkeeping.

Research motivation: in Elasticsearch/Lucene, a search index is a
document store plus an inverted index managed in segments: documents are
indexed (analyzed into per-field postings), deleted via tombstones,
made visible by ``refresh``, compacted by segment ``merge``, and pinned
by ``commit``. This module books that lifecycle deterministically as a
single-host ledger. It runs no cluster, opens no sockets, and persists
nothing -- "durable" here means a pinned commit digest, never a disk
write.

Public API:

- ``SearchIndex()`` -- mutable, RLock-guarded ledger.
  - ``index(doc_id, fields, seq)`` -> frozen ``IndexRecord``: books a
    document; ``fields`` maps field name to text. Each field is
    tokenized (lowercase word tokens) into per-field postings with term
    frequencies. Re-indexing an active ``doc_id`` replaces it
    (``replaced=True``); re-indexing a deleted id is refused.
  - ``delete(doc_id, seq)`` -> frozen ``DeleteRecord``: terminal
    tombstone; the id is retired and may never be re-indexed.
  - ``search(terms, seq, fields=(), boosts=(), top_k=10)`` -> frozen
    ``SearchResults``: pure read view (seq validated, never consumed,
    no audit row). Matches per-field terms, scores
    ``boost * (1 + ln(tf)) * (ln((N + 1) / (df + 1)) + 1)``, sorts by
    descending score with ``doc_id`` tiebreaks.
  - ``refresh(seq)`` -> frozen ``RefreshRecord``: declares a new read
    segment; buffered writes move into it.
  - ``merge(seq)`` -> frozen ``MergeRecord``: compacts all segments
    into one; tombstoned docs are dropped from bookkeeping.
  - ``commit(seq)`` -> frozen ``CommitRecord``: pins the current
    segments, live documents and tombstones as one commit digest.
  - ``document(doc_id)`` / ``doc_ids()`` / ``stats()`` /
    ``audit_log()`` -- pure read views; consume no seq.
- ``search_index_audit_event(kind, detail, seq)`` --
  ``audit.ndjson/1`` records: ``"search-index.indexed"``,
  ``"search-index.deleted"``, ``"search-index.refreshed"``,
  ``"search-index.merged"``, ``"search-index.committed"``,
  ``"search-index.rejected"``.

Raw field text never crosses the audit boundary: ``detail`` may carry
doc ids, field *names*, term pins, counts, digests and segment ids --
never ``text``, ``fields``, ``payload``, ``value`` or ``raw``.

House discipline: caller int seqs strictly increasing on mutations
(failed mutations consume their seq; bool/negative/rewind refused),
RLock-guarded, fail-closed taxonomy, stdlib-only (``canonical_json``
sibling helper behind the standard try/except fallback).

Honest scope:

- This module books *declared* documents, deletions, refreshes, merges
  and commits; it stores no bytes on disk and cannot prove a document
  was actually persisted or that a merge reclaimed any space.
- A ``SearchResults`` hit says "this document matched the query terms
  by TF-IDF on the reported field text", never "this document is
  relevant or true". Tokenization is a simple word regex (ASCII
  letters/digits plus underscore); no stemming, no stop-word removal,
  no language detection, no phrase queries.
- ``search()`` is a pure read: it pins the *query* (GIGO boundary on
  the host's terms) and never books an audit row.

Version pin: ``search-index.v1`` / schema pin
``northstar.search-index.v1``.
"""

from __future__ import annotations

import hashlib
import math
import re
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Tuple

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
SEARCH_INDEX_VERSION = "search-index.v1"

#: Schema pin carried by records and audit events.
SEARCH_INDEX_SCHEMA = "northstar.search-index.v1"

#: Wire format of audit records.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Fixed vocabulary for audit event kinds.
KIND_INDEXED = "search-index.indexed"
KIND_DELETED = "search-index.deleted"
KIND_REFRESHED = "search-index.refreshed"
KIND_MERGED = "search-index.merged"
KIND_COMMITTED = "search-index.committed"
KIND_REJECTED = "search-index.rejected"
_KINDS = frozenset(
    {KIND_INDEXED, KIND_DELETED, KIND_REFRESHED, KIND_MERGED, KIND_COMMITTED, KIND_REJECTED}
)

_TOKEN_RE = re.compile(r"[a-z0-9_]+")
_FIELD_RE = re.compile(r"[a-z][a-z0-9_]*")

_MAX_INT = 2**53 - 1
_DIGEST_PREFIX = "sha256:"
_MAX_ID_LEN = 256
_MAX_FIELD_LEN = 64
_MAX_TEXT_LEN = 64 * 1024
_MAX_TOP_K = 1000


# ---------------------------------------------------------------------------
# Error taxonomy (fail-closed)
# ---------------------------------------------------------------------------


class SearchIndexError(Exception):
    """Base class for all search-index errors."""


class BadDocError(SearchIndexError):
    """doc_id is not a non-empty str within the length cap."""


class BadFieldError(SearchIndexError):
    """A field name or field text is malformed."""


class DeletedDocError(SearchIndexError):
    """doc_id was deleted; ids are retired forever."""


class UnknownDocError(SearchIndexError):
    """doc_id is not in the ledger."""


class BadQueryError(SearchIndexError):
    """Query terms are malformed or empty after tokenization."""


class BadBoostError(SearchIndexError):
    """A field boost is not a finite positive number."""


class BadTopKError(SearchIndexError):
    """top_k is not a positive int within the cap."""


class SeqOrderError(SearchIndexError):
    """Caller seq did not strictly increase."""


class AuditKindError(SearchIndexError):
    """Unknown audit kind, malformed detail, or banned key in detail."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_seq(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SeqOrderError(f"seq must be a non-negative int, got {value!r}")
    return value


def _check_doc_id(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > _MAX_ID_LEN:
        raise BadDocError(f"doc_id must be a non-empty str <= {_MAX_ID_LEN} chars")
    return value


def _check_fields(value: object) -> Dict[str, str]:
    if not isinstance(value, Mapping) or not value:
        raise BadFieldError("fields must be a non-empty mapping of name -> text")
    out: Dict[str, str] = {}
    for name, text in value.items():
        if (
            not isinstance(name, str)
            or not name
            or len(name) > _MAX_FIELD_LEN
            or not _FIELD_RE.fullmatch(name)
        ):
            raise BadFieldError(f"bad field name: {name!r}")
        if not isinstance(text, str) or len(text) > _MAX_TEXT_LEN:
            raise BadFieldError(f"bad text for field {name!r}")
        out[name] = text
    return out


def _check_terms(value: object) -> Tuple[str, ...]:
    if isinstance(value, str) or not isinstance(value, (tuple, list)) or not value:
        raise BadQueryError("terms must be a non-empty tuple/list of term strings")
    terms: list = []
    for term in value:
        if not isinstance(term, str) or not term:
            raise BadQueryError(f"bad query term: {term!r}")
        terms.extend(_TOKEN_RE.findall(term.lower()))
    if not terms:
        raise BadQueryError("query has no indexable terms")
    return tuple(terms)


def _check_fields_subset(value: object) -> Tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str) or not isinstance(value, (tuple, list)):
        raise BadQueryError("fields must be a tuple/list of field names")
    out = []
    for name in value:
        if not isinstance(name, str) or not _FIELD_RE.fullmatch(name):
            raise BadQueryError(f"bad field name in query: {name!r}")
        out.append(name)
    return tuple(out)


def _check_boosts(value: object) -> Dict[str, float]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise BadBoostError("boosts must be a mapping of field -> number")
    out: Dict[str, float] = {}
    for name, boost in value.items():
        if not isinstance(name, str) or not _FIELD_RE.fullmatch(name):
            raise BadBoostError(f"bad field name in boosts: {name!r}")
        if (
            isinstance(boost, bool)
            or not isinstance(boost, (int, float))
            or not math.isfinite(boost)
            or boost <= 0
        ):
            raise BadBoostError(f"bad boost for field {name!r}: {boost!r}")
        out[name] = float(boost)
    return out


def _check_top_k(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= _MAX_TOP_K:
        raise BadTopKError(f"top_k must be an int in [1, {_MAX_TOP_K}]")
    return value


def _tokenize(text: str) -> Tuple[str, ...]:
    return tuple(_TOKEN_RE.findall(text.lower()))


def _digest_pin(parts: object) -> str:
    return _DIGEST_PREFIX + hashlib.sha256(_encode(parts)).hexdigest()


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IndexRecord:
    """Frozen record of one indexed (or re-indexed) document."""

    doc_id: str
    field_names: Tuple[str, ...]
    term_count: int
    unique_terms: int
    digest: str
    segment: int
    replaced: bool
    seq: int
    version: str = SEARCH_INDEX_VERSION
    schema: str = SEARCH_INDEX_SCHEMA

    def __post_init__(self) -> None:
        if not self.digest.startswith(_DIGEST_PREFIX):
            raise ValueError("digest must be a sha256: pin")

    def verify(self, doc_id: str, fields: Mapping[str, str]) -> bool:
        """Recompute the digest pin over (doc_id, sorted fields)."""
        return self.digest == _digest_pin(
            [doc_id, sorted((k, v) for k, v in fields.items())]
        )


@dataclass(frozen=True)
class DeleteRecord:
    """Frozen record of one terminal document deletion (tombstone)."""

    doc_id: str
    seq: int
    version: str = SEARCH_INDEX_VERSION
    schema: str = SEARCH_INDEX_SCHEMA


@dataclass(frozen=True)
class ScoredDoc:
    """One ranked hit: doc_id, score, and matched per-field terms."""

    doc_id: str
    score: float
    matched_terms: Tuple[str, ...]


@dataclass(frozen=True)
class SearchResults:
    """Frozen result of one search: ranked hits and the query pin."""

    query_digest: str
    hits: Tuple[ScoredDoc, ...]
    total_matched: int
    top_k: int
    seq: int
    version: str = SEARCH_INDEX_VERSION
    schema: str = SEARCH_INDEX_SCHEMA

    def __post_init__(self) -> None:
        if not self.query_digest.startswith(_DIGEST_PREFIX):
            raise ValueError("query_digest must be a sha256: pin")


@dataclass(frozen=True)
class RefreshRecord:
    """Frozen record of one refresh: a new read segment is declared."""

    segment: int
    docs_visible: int
    digest: str
    seq: int
    version: str = SEARCH_INDEX_VERSION
    schema: str = SEARCH_INDEX_SCHEMA

    def __post_init__(self) -> None:
        if not self.digest.startswith(_DIGEST_PREFIX):
            raise ValueError("digest must be a sha256: pin")


@dataclass(frozen=True)
class MergeRecord:
    """Frozen record of one segment merge (compaction)."""

    segment: int
    segments_merged: int
    docs_visible: int
    digest: str
    seq: int
    version: str = SEARCH_INDEX_VERSION
    schema: str = SEARCH_INDEX_SCHEMA

    def __post_init__(self) -> None:
        if not self.digest.startswith(_DIGEST_PREFIX):
            raise ValueError("digest must be a sha256: pin")


@dataclass(frozen=True)
class CommitRecord:
    """Frozen record of one commit point pinning segments + tombstones."""

    commit_digest: str
    segments: Tuple[int, ...]
    docs_visible: int
    tombstones: int
    seq: int
    version: str = SEARCH_INDEX_VERSION
    schema: str = SEARCH_INDEX_SCHEMA

    def __post_init__(self) -> None:
        if not self.commit_digest.startswith(_DIGEST_PREFIX):
            raise ValueError("commit_digest must be a sha256: pin")


@dataclass(frozen=True)
class DocView:
    """Pure read view of one live document (pins only, no text)."""

    doc_id: str
    field_names: Tuple[str, ...]
    digest: str
    segment: int


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def search_index_audit_event(
    kind: str, detail: Mapping[str, Any], seq: int
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the search index.

    Raw field text never crosses the audit boundary: ``detail`` may carry
    doc ids, field *names*, term pins, counts, digests and segment ids --
    never ``text``, ``fields``, ``payload``, ``value`` or ``raw``.
    """
    if not isinstance(kind, str) or kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    if not isinstance(detail, Mapping):
        raise AuditKindError("detail must be a mapping")
    banned = {"text", "fields", "payload", "value", "raw", "body"}
    if any(k in detail for k in banned):
        raise AuditKindError("detail carries banned keys")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": SEARCH_INDEX_VERSION,
        "detail": dict(detail),
        "seq": seq,
    }


# ---------------------------------------------------------------------------
# The ledger
# ---------------------------------------------------------------------------


class SearchIndex:
    """Deterministic document index lifecycle ledger.

    Books Elasticsearch-shaped index/delete/search/refresh/merge/commit
    operations as frozen records over caller-supplied logical seqs. The
    inverted index is per-field with term frequencies; deletions are
    terminal tombstones; ``refresh`` declares new read segments;
    ``merge`` compacts segments; ``commit`` pins a commit digest.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = -1
        # doc_id -> {"fields": {name: text}, "terms": {field: {term: tf}},
        #            "digest": str, "segment": int}
        self._docs: Dict[str, Dict[str, Any]] = {}
        self._retired: set = set()
        # (field, term) -> {doc_id: tf}
        self._postings: Dict[Tuple[str, str], Dict[str, int]] = {}
        # (field, term) -> document frequency over visible docs
        self._doc_freq: Dict[Tuple[str, str], int] = {}
        self._segments: list = [0]
        self._next_segment = 1
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

    def _reject(self, seq: int, reason: str, doc_id: str = "") -> Dict[str, Any]:
        row = search_index_audit_event(
            KIND_REJECTED, {"reason": reason, "doc_id": doc_id}, seq
        )
        self._audit.append(row)
        return row

    # -- internal index maintenance ----------------------------------------

    def _remove_postings(self, doc_id: str) -> None:
        entry = self._docs.get(doc_id)
        if entry is None:
            return
        for field_name, terms in entry["terms"].items():
            for term in terms:
                key = (field_name, term)
                post = self._postings.get(key)
                if post is not None and doc_id in post:
                    del post[doc_id]
                    if not post:
                        del self._postings[key]
                df = self._doc_freq.get(key, 0)
                if df <= 1:
                    self._doc_freq.pop(key, None)
                else:
                    self._doc_freq[key] = df - 1

    def _add_postings(self, doc_id: str, terms: Dict[str, Dict[str, int]]) -> None:
        for field_name, term_map in terms.items():
            for term, tf in term_map.items():
                key = (field_name, term)
                post = self._postings.setdefault(key, {})
                if doc_id not in post:
                    self._doc_freq[key] = self._doc_freq.get(key, 0) + 1
                post[doc_id] = tf

    # -- mutations ----------------------------------------------------------

    def index(
        self, doc_id: str, fields: Mapping[str, str], seq: int
    ) -> IndexRecord:
        """Book (or replace) a document with fielded text.

        Tokenizes each field into per-field term postings. Re-indexing an
        active ``doc_id`` replaces it (``replaced=True``); re-indexing a
        deleted id is refused fail-closed.
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                doc_id = _check_doc_id(doc_id)
                clean = _check_fields(fields)
            except SearchIndexError as exc:
                self._reject(seq, type(exc).__name__, str(doc_id))
                raise
            if doc_id in self._retired:
                self._reject(seq, "DeletedDocError", doc_id)
                raise DeletedDocError(f"doc_id {doc_id!r} was deleted")
            replaced = doc_id in self._docs
            if replaced:
                self._remove_postings(doc_id)
            terms: Dict[str, Dict[str, int]] = {}
            term_count = 0
            for field_name, text in clean.items():
                counts: Dict[str, int] = {}
                for tok in _tokenize(text):
                    counts[tok] = counts.get(tok, 0) + 1
                if counts:
                    terms[field_name] = counts
                    term_count += sum(counts.values())
            unique_terms = sum(len(c) for c in terms.values())
            digest = _digest_pin([doc_id, sorted(clean.items())])
            segment = self._segments[-1]
            self._docs[doc_id] = {
                "fields": clean,
                "terms": terms,
                "digest": digest,
                "segment": segment,
            }
            self._add_postings(doc_id, terms)
            record = IndexRecord(
                doc_id=doc_id,
                field_names=tuple(sorted(clean)),
                term_count=term_count,
                unique_terms=unique_terms,
                digest=digest,
                segment=segment,
                replaced=replaced,
                seq=seq,
            )
            self._audit.append(
                search_index_audit_event(
                    KIND_INDEXED,
                    {
                        "doc_id": doc_id,
                        "field_names": list(record.field_names),
                        "term_count": term_count,
                        "unique_terms": unique_terms,
                        "digest": digest,
                        "segment": segment,
                        "replaced": replaced,
                    },
                    seq,
                )
            )
            return record

    def delete(self, doc_id: str, seq: int) -> DeleteRecord:
        """Terminally tombstone a document; the id is retired forever."""
        with self._lock:
            seq = self._claim(seq)
            try:
                doc_id = _check_doc_id(doc_id)
            except SearchIndexError as exc:
                self._reject(seq, type(exc).__name__, str(doc_id))
                raise
            if doc_id in self._retired or doc_id not in self._docs:
                self._reject(seq, "UnknownDocError", doc_id)
                raise UnknownDocError(f"doc_id {doc_id!r} is not indexed")
            self._remove_postings(doc_id)
            del self._docs[doc_id]
            self._retired.add(doc_id)
            record = DeleteRecord(doc_id=doc_id, seq=seq)
            self._audit.append(
                search_index_audit_event(
                    KIND_DELETED, {"doc_id": doc_id}, seq
                )
            )
            return record

    def refresh(self, seq: int) -> RefreshRecord:
        """Declare a new read segment; buffered writes move into it."""
        with self._lock:
            seq = self._claim(seq)
            segment = self._next_segment
            self._next_segment += 1
            self._segments.append(segment)
            for entry in self._docs.values():
                entry["segment"] = segment
            docs_visible = len(self._docs)
            digest = _digest_pin(
                ["refresh", segment, sorted(self._docs), docs_visible]
            )
            record = RefreshRecord(
                segment=segment,
                docs_visible=docs_visible,
                digest=digest,
                seq=seq,
            )
            self._audit.append(
                search_index_audit_event(
                    KIND_REFRESHED,
                    {
                        "segment": segment,
                        "docs_visible": docs_visible,
                        "digest": digest,
                    },
                    seq,
                )
            )
            return record

    def merge(self, seq: int) -> MergeRecord:
        """Compact all segments into one; tombstones stay retired."""
        with self._lock:
            seq = self._claim(seq)
            merged = len(self._segments)
            segment = self._next_segment
            self._next_segment += 1
            self._segments = [segment]
            for entry in self._docs.values():
                entry["segment"] = segment
            docs_visible = len(self._docs)
            digest = _digest_pin(
                ["merge", segment, merged, sorted(self._docs), docs_visible]
            )
            record = MergeRecord(
                segment=segment,
                segments_merged=merged,
                docs_visible=docs_visible,
                digest=digest,
                seq=seq,
            )
            self._audit.append(
                search_index_audit_event(
                    KIND_MERGED,
                    {
                        "segment": segment,
                        "segments_merged": merged,
                        "docs_visible": docs_visible,
                        "digest": digest,
                    },
                    seq,
                )
            )
            return record

    def commit(self, seq: int) -> CommitRecord:
        """Pin the current segments, live documents and tombstones."""
        with self._lock:
            seq = self._claim(seq)
            doc_digests = sorted(
                (doc_id, entry["digest"]) for doc_id, entry in self._docs.items()
            )
            commit_digest = _digest_pin(
                ["commit", self._segments, doc_digests, sorted(self._retired)]
            )
            record = CommitRecord(
                commit_digest=commit_digest,
                segments=tuple(self._segments),
                docs_visible=len(self._docs),
                tombstones=len(self._retired),
                seq=seq,
            )
            self._audit.append(
                search_index_audit_event(
                    KIND_COMMITTED,
                    {
                        "commit_digest": commit_digest,
                        "segments": list(record.segments),
                        "docs_visible": record.docs_visible,
                        "tombstones": record.tombstones,
                    },
                    seq,
                )
            )
            return record

    # -- pure reads ----------------------------------------------------------

    def search(
        self,
        terms: object,
        seq: int,
        fields: object = (),
        boosts: object = None,
        top_k: int = 10,
    ) -> SearchResults:
        """Rank visible documents against query terms (pure read).

        ``terms`` is tokenized; ``fields`` restricts matching to those
        fields; ``boosts`` maps field name to a positive multiplier.
        Score per field-term is
        ``boost * (1 + ln(tf)) * (ln((N + 1) / (df + 1)) + 1)``.
        """
        _check_seq(seq)
        clean_terms = _check_terms(terms)
        field_subset = _check_fields_subset(fields)
        clean_boosts = _check_boosts(boosts)
        top_k = _check_top_k(top_k)
        with self._lock:
            n_docs = len(self._docs)
            all_fields = set()
            for e in self._docs.values():
                all_fields.update(e["terms"])
            query_fields = field_subset or tuple(sorted(all_fields))
            scored: list = []
            for doc_id, entry in self._docs.items():
                total = 0.0
                matched: list = []
                for term in clean_terms:
                    for field_name in query_fields:
                        tf = entry["terms"].get(field_name, {}).get(term, 0)
                        if not tf:
                            continue
                        df = self._doc_freq.get((field_name, term), 1)
                        idf = math.log((n_docs + 1) / (df + 1)) + 1.0
                        boost = clean_boosts.get(field_name, 1.0)
                        total += boost * (1.0 + math.log(tf)) * idf
                        matched.append(f"{field_name}:{term}")
                if total > 0.0:
                    scored.append(
                        ScoredDoc(
                            doc_id=doc_id,
                            score=round(total, 12),
                            matched_terms=tuple(sorted(set(matched))),
                        )
                    )
            scored.sort(key=lambda h: (-h.score, h.doc_id))
            hits = tuple(scored[:top_k])
            return SearchResults(
                query_digest=_digest_pin(
                    [clean_terms, query_fields, sorted(clean_boosts.items()), top_k]
                ),
                hits=hits,
                total_matched=len(scored),
                top_k=top_k,
                seq=seq,
            )

    def document(self, doc_id: str) -> Optional[DocView]:
        """Pure read view of one live document (pins only, no text)."""
        _check_doc_id(doc_id)
        with self._lock:
            entry = self._docs.get(doc_id)
            if entry is None:
                return None
            return DocView(
                doc_id=doc_id,
                field_names=tuple(sorted(entry["fields"])),
                digest=entry["digest"],
                segment=entry["segment"],
            )

    def doc_ids(self) -> Tuple[str, ...]:
        """Ids of live (non-deleted) documents, sorted."""
        with self._lock:
            return tuple(sorted(self._docs))

    def retired_ids(self) -> Tuple[str, ...]:
        """Ids retired by ``delete`` (terminal tombstones), sorted."""
        with self._lock:
            return tuple(sorted(self._retired))

    def stats(self, seq: int) -> Dict[str, Any]:
        """Pure read view of index statistics."""
        _check_seq(seq)
        with self._lock:
            return {
                "docs_visible": len(self._docs),
                "tombstones": len(self._retired),
                "segments": list(self._segments),
                "postings": len(self._postings),
                "terms_indexed": len(self._doc_freq),
            }

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        """All audit rows booked so far, in order."""
        with self._lock:
            return tuple(self._audit)


# ---------------------------------------------------------------------------
# main() self-check
# ---------------------------------------------------------------------------


def main() -> None:
    """Deterministic self-check: index, search, delete, refresh/merge/commit."""
    idx = SearchIndex()
    r1 = idx.index("d1", {"title": "quick brown fox", "body": "fox jumps"}, 1)
    assert r1.verify("d1", {"title": "quick brown fox", "body": "fox jumps"})
    assert not r1.replaced
    r2 = idx.index("d2", {"title": "lazy dog", "body": "dog sleeps"}, 2)
    assert r2.term_count > 0
    res = idx.search(("fox",), 3)
    assert [h.doc_id for h in res.hits] == ["d1"]
    res2 = idx.search(("fox",), 4, fields=("title",), boosts={"title": 2.0})
    assert res2.hits and res2.hits[0].doc_id == "d1"
    # re-index replaces
    r3 = idx.index("d1", {"title": "quick brown fox", "body": "cat naps"}, 5)
    assert r3.replaced
    assert idx.search(("fox",), 6).total_matched == 1
    assert idx.search(("cat",), 7).total_matched == 1
    # delete is terminal
    d = idx.delete("d2", 8)
    assert d.doc_id == "d2"
    assert idx.search(("dog",), 9).total_matched == 0
    assert idx.document("d2") is None
    try:
        idx.index("d2", {"title": "x"}, 10)
        raise AssertionError("re-index after delete must fail")
    except DeletedDocError:
        pass
    ref = idx.refresh(11)
    assert ref.docs_visible == 1 and ref.segment == 1
    mg = idx.merge(12)
    assert mg.segments_merged == 2 and mg.docs_visible == 1
    cm = idx.commit(13)
    assert cm.tombstones == 1 and cm.docs_visible == 1
    kinds = [row["kind"] for row in idx.audit_log()]
    assert KIND_INDEXED in kinds and KIND_DELETED in kinds
    assert KIND_REFRESHED in kinds and KIND_MERGED in kinds
    assert KIND_COMMITTED in kinds and KIND_REJECTED in kinds
    assert all(row["schema"] == AUDIT_SCHEMA for row in idx.audit_log())
    print(
        "search-index OK: index, search, delete, refresh, merge, commit, audit"
    )


if __name__ == "__main__":
    main()
