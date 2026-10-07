"""Boolean query-language search engine over a positional inverted index.

A ``SearchEngine`` instance keeps a deterministic, single-host search
index over caller-supplied documents:

* ``index(doc_id, text, seq)`` tokenizes ``text`` (lowercase word tokens)
  with term positions, records postings for ``doc_id``, and returns a
  frozen ``IndexRecord`` with a ``sha256:`` digest pin.
* ``query(query_string, seq)`` parses a small boolean query language and
  returns a frozen ``QueryRecord`` (``q-N`` ids) carrying the parsed plan.
  Supported syntax (case-insensitive operators):

    ``fox``            single term
    ``fox dog``        implicit AND between adjacent operands
    ``fox AND dog``    explicit AND
    ``fox OR dog``     union
    ``NOT fox`` / ``-fox``  exclusion (complement over indexed docs)
    ``"quick brown"``  phrase: consecutive term positions
    ``(fox OR dog) AND NOT cat``  grouping with parentheses

  Precedence: NOT > AND > OR. Unbalanced quotes or parentheses, empty
  queries, and dangling operators are refused fail-closed.
* ``rank(query_id, seq, top_k=None)`` executes the stored plan against
  the index, scores matched documents with BM25 (k1=1.5, b=0.75,
  ``idf = ln(1 + (N - df + 0.5) / (df + 0.5))``), and returns a frozen
  ``QueryResults`` record sorted by descending score with ``doc_id``
  tiebreaks.

House style: no wall-clock (caller int seqs only), frozen records,
caller-supplied strictly increasing int seqs on mutations
(fail-closed; failed mutations consume their seq), RLock-guarded,
stdlib-only (``hashlib``, ``math``, ``re``, ``threading``,
``dataclasses``, ``typing`` plus the standard ``canonical_json``
try/except fallback), deterministic, version/schema pins, ``main()``
self-check.

Honest scope: ranking bookkeeping over *host-reported* text. A hit says
"this document matched the parsed plan by BM25 on the reported text",
never "this document is relevant or true". Tokenization is a simple
word regex (ASCII letters/digits plus underscore); no stemming, no
stop-word removal, no language detection, no fielded search. A score
of zero means "no matched terms", not "unrelated". ``query()`` pins
the *parse* of the host's query string (GIGO boundary on the string).

Relation to ``fulltext_search``: that module offers plain TF-IDF
``index/rank/search`` over raw query text. This module adds a parsed
boolean/phrase query language with plan reuse (``query()`` once,
``rank()`` many times) and BM25 length normalization.

Version pin: search-engine.v1
Schema pin: northstar.search-engine.v1
"""

from __future__ import annotations

import hashlib
import math
import re
import threading
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

try:  # prefer the repo-wide canonical JSON when importable
    from canonical_json import canonical_json as _canonical_json

    def _encode(value: object) -> bytes:
        return _canonical_json(value).encode("utf-8")

except Exception:  # defensive fallback: local type-tagged encoder

    def _encode(value: object) -> bytes:
        import json

        if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
            raise SearchEngineError("non-finite float cannot be canonicalized")
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")


#: Module version.
SEARCH_ENGINE_VERSION = "search-engine.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.search-engine.v1"

#: Audit envelope schema pin.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Audit event kinds.
AUDIT_INDEXED = "indexed"
AUDIT_QUERY_PARSED = "query-parsed"
AUDIT_RANKED = "ranked"
AUDIT_REJECTED = "rejected"

_AUDIT_KINDS = frozenset(
    {AUDIT_INDEXED, AUDIT_QUERY_PARSED, AUDIT_RANKED, AUDIT_REJECTED}
)

#: Token pattern: word characters (letters, digits, underscore).
_TOKEN_RE = re.compile(r"[A-Za-z0-9_]+")

#: BM25 parameters.
_BM25_K1 = 1.5
_BM25_B = 0.75


class SearchEngineError(Exception):
    """Base error for the search-engine module."""


class DuplicateDocumentError(SearchEngineError):
    """Raised when a doc_id is indexed twice."""


class UnknownDocumentError(SearchEngineError):
    """Raised when an operation names a document that was never indexed."""


class UnknownQueryError(SearchEngineError):
    """Raised when an operation names a query id that was never parsed."""


class BadQueryError(SearchEngineError):
    """Raised when a query string cannot be parsed."""


class SeqOrderError(SearchEngineError):
    """Raised when a caller seq does not strictly increase."""


def _require_seq(value: object, name: str = "seq") -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SearchEngineError(f"{name} must be a non-negative int, got {value!r}")
    return value


def _require_doc_id(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise SearchEngineError(f"doc_id must be a non-empty str, got {value!r}")
    return value


def _require_query_id(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise SearchEngineError(f"query_id must be a non-empty str, got {value!r}")
    return value


def _require_text(value: object) -> str:
    if not isinstance(value, str):
        raise SearchEngineError(f"text must be a str, got {type(value).__name__}")
    return value


def _require_query_string(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SearchEngineError(
            f"query must be a non-empty str, got {value!r}"
        )
    return value


def _require_top_k(value: object) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise SearchEngineError(
            f"top_k must be a positive int or None, got {value!r}"
        )
    return value


def _tokenize(text: str) -> Tuple[str, ...]:
    """Lowercase word tokens from text."""
    return tuple(tok.lower() for tok in _TOKEN_RE.findall(text))


def _digest_pin(parts: object) -> str:
    return "sha256:" + hashlib.sha256(_encode(parts)).hexdigest()


# ---------------------------------------------------------------------------
# Query parsing
# ---------------------------------------------------------------------------

# Plan nodes are frozen nested tuples:
#   ("AND", (child, ...))  ("OR", (child, ...))  ("NOT", child)
#   ("TERM", "word")       ("PHRASE", ("w1", "w2", ...))
Plan = tuple  # recursive shape documented above

_TOK_AND = "AND"
_TOK_OR = "OR"
_TOK_NOT = "NOT"
_TOK_LP = "LP"
_TOK_RP = "RP"
_TOK_MINUS = "MINUS"
_TOK_TERM = "TERM"
_TOK_PHRASE = "PHRASE"


def _lex_query(text: str) -> List[Tuple[str, object]]:
    """Lex a query string into (kind, value) tokens.

    Raises BadQueryError on unterminated quotes.
    """
    tokens: List[Tuple[str, object]] = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch.isspace():
            i += 1
            continue
        if ch == "(":
            tokens.append((_TOK_LP, None))
            i += 1
            continue
        if ch == ")":
            tokens.append((_TOK_RP, None))
            i += 1
            continue
        if ch == "-":
            tokens.append((_TOK_MINUS, None))
            i += 1
            continue
        if ch == '"':
            j = text.find('"', i + 1)
            if j == -1:
                raise BadQueryError("unterminated quoted phrase")
            words = _tokenize(text[i + 1 : j])
            if not words:
                raise BadQueryError("empty quoted phrase")
            tokens.append((_TOK_PHRASE, words))
            i = j + 1
            continue
        m = _TOKEN_RE.match(text, i)
        if not m:
            raise BadQueryError(f"unexpected character {ch!r} in query")
        word = m.group(0)
        upper = word.upper()
        if upper in ("AND", "OR", "NOT"):
            tokens.append((upper, None))
        else:
            tokens.append((_TOK_TERM, word.lower()))
        i = m.end()
    return tokens


class _Parser:
    """Recursive-descent parser: OR > AND > NOT > primary."""

    def __init__(self, tokens: List[Tuple[str, object]]) -> None:
        self._tokens = tokens
        self._pos = 0

    def _peek(self) -> Optional[str]:
        if self._pos < len(self._tokens):
            return self._tokens[self._pos][0]
        return None

    def _next(self) -> Tuple[str, object]:
        tok = self._tokens[self._pos]
        self._pos += 1
        return tok

    def parse(self) -> Plan:
        node = self._parse_or()
        if self._pos != len(self._tokens):
            raise BadQueryError("trailing tokens after query")
        return node

    def _parse_or(self) -> Plan:
        children = [self._parse_and()]
        while self._peek() == _TOK_OR:
            self._next()
            children.append(self._parse_and())
        if len(children) == 1:
            return children[0]
        return ("OR", tuple(children))

    def _starts_primary(self) -> bool:
        return self._peek() in (
            _TOK_TERM,
            _TOK_PHRASE,
            _TOK_LP,
            _TOK_NOT,
            _TOK_MINUS,
        )

    def _parse_and(self) -> Plan:
        children = [self._parse_unary()]
        while True:
            kind = self._peek()
            if kind == _TOK_AND:
                self._next()
                children.append(self._parse_unary())
            elif kind is not None and self._starts_primary():
                # Implicit AND between adjacent operands.
                children.append(self._parse_unary())
            else:
                break
        if len(children) == 1:
            return children[0]
        return ("AND", tuple(children))

    def _parse_unary(self) -> Plan:
        kind = self._peek()
        if kind in (_TOK_NOT, _TOK_MINUS):
            self._next()
            operand = self._parse_unary()
            return ("NOT", operand)
        return self._parse_primary()

    def _parse_primary(self) -> Plan:
        kind, value = self._next() if self._peek() is not None else (None, None)
        if kind == _TOK_LP:
            node = self._parse_or()
            if self._peek() != _TOK_RP:
                raise BadQueryError("unbalanced parenthesis")
            self._next()
            return node
        if kind == _TOK_TERM:
            return ("TERM", value)
        if kind == _TOK_PHRASE:
            return ("PHRASE", value)
        raise BadQueryError("expected a term, phrase, or '('")


def _parse_query(text: str) -> Plan:
    tokens = _lex_query(text)
    if not tokens:
        raise BadQueryError("empty query")
    return _Parser(tokens).parse()


def _plan_terms(plan: Plan) -> Tuple[str, ...]:
    """All terms (phrase terms included) occurring in a plan, sorted."""
    op = plan[0]
    if op == "TERM":
        return (plan[1],)
    if op == "PHRASE":
        return tuple(sorted(set(plan[1])))
    if op == "NOT":
        return _plan_terms(plan[1])
    # AND / OR
    terms: List[str] = []
    for child in plan[1]:
        terms.extend(_plan_terms(child))
    return tuple(sorted(set(terms)))


def _plan_to_json(plan: Plan) -> List[object]:
    """Plan -> JSON-safe nested lists for digest pinning."""
    op = plan[0]
    if op in ("TERM", "PHRASE"):
        return [op, list(plan[1]) if op == "PHRASE" else plan[1]]
    if op == "NOT":
        return [op, _plan_to_json(plan[1])]
    return [op, [_plan_to_json(child) for child in plan[1]]]


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class IndexRecord:
    """Frozen record of one indexed document."""

    doc_id: str
    term_count: int
    unique_terms: int
    digest: str
    seq: int
    version: str = SEARCH_ENGINE_VERSION
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        if not self.digest.startswith("sha256:"):
            raise SearchEngineError(f"bad digest pin: {self.digest!r}")

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
class QueryRecord:
    """Frozen record of one parsed query (plan pinned by digest)."""

    query_id: str
    query: str
    plan_json: Tuple[object, ...]
    digest: str
    seq: int
    version: str = SEARCH_ENGINE_VERSION
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        if not self.digest.startswith("sha256:"):
            raise SearchEngineError(f"bad digest pin: {self.digest!r}")

    def as_dict(self) -> dict:
        return {
            "query_id": self.query_id,
            "query": self.query,
            "plan_json": list(self.plan_json),
            "digest": self.digest,
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class ScoredHit:
    """One ranked hit: doc_id, BM25 score, and the matched terms."""

    doc_id: str
    score: float
    matched_terms: Tuple[str, ...]

    def __post_init__(self) -> None:
        if isinstance(self.score, bool) or not isinstance(
            self.score, (int, float)
        ):
            raise SearchEngineError(
                f"score must be a number, got {self.score!r}"
            )
        if self.score < 0 or math.isnan(self.score) or math.isinf(self.score):
            raise SearchEngineError(
                f"score must be finite and >= 0, got {self.score!r}"
            )

    def as_dict(self) -> dict:
        return {
            "doc_id": self.doc_id,
            "score": self.score,
            "matched_terms": list(self.matched_terms),
        }


@dataclass(frozen=True)
class QueryResults:
    """Frozen result of ranking one stored query plan."""

    query_id: str
    query_digest: str
    hits: Tuple[ScoredHit, ...]
    total_matched: int
    seq: int
    version: str = SEARCH_ENGINE_VERSION
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        if not self.query_digest.startswith("sha256:"):
            raise SearchEngineError(
                f"bad query digest pin: {self.query_digest!r}"
            )

    def as_dict(self) -> dict:
        return {
            "query_id": self.query_id,
            "query_digest": self.query_digest,
            "hits": [h.as_dict() for h in self.hits],
            "total_matched": self.total_matched,
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }


# ---------------------------------------------------------------------------
# Search engine
# ---------------------------------------------------------------------------


class SearchEngine:
    """Deterministic boolean/phrase search engine with BM25 ranking."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = -1
        self._query_counter = 0
        # doc_id -> tuple of tokens (position i == tokens[i])
        self._docs: Dict[str, Tuple[str, ...]] = {}
        # term -> {doc_id: [positions]}
        self._postings: Dict[str, Dict[str, List[int]]] = {}
        # doc_id -> sha256: digest pin
        self._pins: Dict[str, str] = {}
        # query_id -> (query string, plan, digest pin)
        self._queries: Dict[str, Tuple[str, Plan, str]] = {}
        self._audit: List[dict] = []

    # -- views -----------------------------------------------------------

    def __len__(self) -> int:
        with self._lock:
            return len(self._docs)

    def doc_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._docs))

    def query_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._queries))

    def audit_log(self) -> Tuple[dict, ...]:
        with self._lock:
            return tuple(self._audit)

    def doc_record(self, doc_id: str) -> IndexRecord:
        """Return the index record for an already-indexed document."""
        doc_id = _require_doc_id(doc_id)
        with self._lock:
            if doc_id not in self._docs:
                raise UnknownDocumentError(f"unknown doc_id: {doc_id!r}")
            tokens = self._docs[doc_id]
            # The pin was derived with the original mutation seq, which is
            # not recoverable from this view; seq=0 is an explicit
            # placeholder, not a claim about the index seq.
            return IndexRecord(
                doc_id=doc_id,
                term_count=len(tokens),
                unique_terms=len(set(tokens)),
                digest=self._pins[doc_id],
                seq=0,
            )

    def query_record(self, query_id: str) -> QueryRecord:
        """Return the parsed-query record for a stored query id."""
        query_id = _require_query_id(query_id)
        with self._lock:
            if query_id not in self._queries:
                raise UnknownQueryError(f"unknown query_id: {query_id!r}")
            text, plan, pin = self._queries[query_id]
            return QueryRecord(
                query_id=query_id,
                query=text,
                plan_json=tuple(_plan_to_json(plan)),
                digest=pin,
                seq=0,
            )

    # -- mutations -------------------------------------------------------

    def _check_seq(self, seq: int) -> None:
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must strictly increase "
                f"(last={self._last_seq}, got={seq})"
            )

    def index(self, doc_id: str, text: str, seq: int) -> IndexRecord:
        """Index one document; a duplicate doc_id is refused fail-closed."""
        doc_id = _require_doc_id(doc_id)
        text = _require_text(text)
        seq = _require_seq(seq)
        with self._lock:
            self._check_seq(seq)
            if doc_id in self._docs:
                self._last_seq = seq  # failed mutations consume their seq
                self._audit.append(
                    search_engine_audit_event(
                        AUDIT_REJECTED, seq, reason="duplicate-doc",
                        doc_id=doc_id,
                    )
                )
                raise DuplicateDocumentError(
                    f"doc_id already indexed: {doc_id!r}"
                )
            tokens = _tokenize(text)
            self._docs[doc_id] = tokens
            for pos, term in enumerate(tokens):
                self._postings.setdefault(term, {}).setdefault(
                    doc_id, []
                ).append(pos)
            pin = _digest_pin(
                {"doc_id": doc_id, "tokens": list(tokens), "seq": seq}
            )
            self._pins[doc_id] = pin
            self._last_seq = seq
            self._audit.append(
                search_engine_audit_event(
                    AUDIT_INDEXED, seq, doc_id=doc_id, digest=pin
                )
            )
            return IndexRecord(
                doc_id=doc_id,
                term_count=len(tokens),
                unique_terms=len(set(tokens)),
                digest=pin,
                seq=seq,
            )

    def query(self, query_string: str, seq: int) -> QueryRecord:
        """Parse a query string into a stored, digest-pinned plan."""
        query_string = _require_query_string(query_string)
        seq = _require_seq(seq)
        with self._lock:
            self._check_seq(seq)
            try:
                plan = _parse_query(query_string)
            except BadQueryError:
                self._last_seq = seq  # failed mutations consume their seq
                self._audit.append(
                    search_engine_audit_event(
                        AUDIT_REJECTED, seq, reason="bad-query"
                    )
                )
                raise
            self._query_counter += 1
            query_id = f"q-{self._query_counter}"
            plan_json = _plan_to_json(plan)
            pin = _digest_pin(
                {
                    "query_id": query_id,
                    "query": query_string,
                    "plan": plan_json,
                    "seq": seq,
                }
            )
            self._queries[query_id] = (query_string, plan, pin)
            self._last_seq = seq
            self._audit.append(
                search_engine_audit_event(
                    AUDIT_QUERY_PARSED, seq, query_id=query_id, digest=pin
                )
            )
            return QueryRecord(
                query_id=query_id,
                query=query_string,
                plan_json=tuple(plan_json),
                digest=pin,
                seq=seq,
            )

    # -- execution & ranking ---------------------------------------------

    def _docs_with_term(self, term: str) -> Dict[str, List[int]]:
        return self._postings.get(term, {})

    def _docs_with_phrase(self, words: Tuple[str, ...]) -> set:
        """Docs where the phrase words occur at consecutive positions."""
        first, rest = words[0], words[1:]
        postings = [self._docs_with_term(w) for w in words]
        candidates = set(postings[0])
        hits = set()
        for doc_id in candidates:
            starts = set(postings[0][doc_id])
            for offset, posting in enumerate(postings[1:], start=1):
                positions = posting.get(doc_id)
                if not positions:
                    starts = set()
                    break
                pos_set = set(positions)
                starts = {p for p in starts if p + offset in pos_set}
                if not starts:
                    break
            if starts:
                hits.add(doc_id)
        return hits

    def _execute(self, plan: Plan) -> set:
        op = plan[0]
        if op == "TERM":
            return set(self._docs_with_term(plan[1]))
        if op == "PHRASE":
            return self._docs_with_phrase(tuple(plan[1]))
        if op == "NOT":
            return set(self._docs) - self._execute(plan[1])
        if op == "AND":
            result: Optional[set] = None
            for child in plan[1]:
                docs = self._execute(child)
                result = docs if result is None else result & docs
                if not result:
                    break
            return result if result is not None else set()
        if op == "OR":
            result = set()
            for child in plan[1]:
                result |= self._execute(child)
            return result
        raise SearchEngineError(f"unknown plan op: {op!r}")  # pragma: no cover

    def _bm25(self, term: str, doc_id: str, avgdl: float, n_docs: int) -> float:
        posting = self._docs_with_term(term).get(doc_id)
        if not posting:
            return 0.0
        freq = len(posting)
        df = len(self._docs_with_term(term))
        idf = math.log(1.0 + (n_docs - df + 0.5) / (df + 0.5))
        doc_len = len(self._docs[doc_id])
        denom = freq + _BM25_K1 * (1.0 - _BM25_B + _BM25_B * doc_len / avgdl)
        return idf * freq * (_BM25_K1 + 1.0) / denom

    def rank(
        self,
        query_id: str,
        seq: int,
        top_k: Optional[int] = None,
    ) -> QueryResults:
        """Execute a stored query plan and BM25-rank the matched docs.

        ``rank`` is a read: the seq is validated but not consumed.
        """
        query_id = _require_query_id(query_id)
        _require_seq(seq)
        top_k = _require_top_k(top_k)
        with self._lock:
            if query_id not in self._queries:
                raise UnknownQueryError(f"unknown query_id: {query_id!r}")
            _, plan, pin = self._queries[query_id]
            matched = self._execute(plan)
            terms = _plan_terms(plan)
            n_docs = len(self._docs)
            avgdl = (
                sum(len(toks) for toks in self._docs.values()) / n_docs
                if n_docs
                else 0.0
            )
            scored: List[ScoredHit] = []
            for doc_id in matched:
                hit_terms: List[str] = []
                score = 0.0
                for term in terms:
                    contrib = (
                        self._bm25(term, doc_id, avgdl, n_docs)
                        if avgdl > 0
                        else 0.0
                    )
                    if contrib > 0:
                        hit_terms.append(term)
                    score += contrib
                scored.append(
                    ScoredHit(
                        doc_id=doc_id,
                        score=score,
                        matched_terms=tuple(sorted(hit_terms)),
                    )
                )
            # Descending score; doc_id tiebreak for determinism.
            scored.sort(key=lambda h: (-h.score, h.doc_id))
            hits = tuple(scored[:top_k] if top_k is not None else scored)
            self._audit.append(
                search_engine_audit_event(
                    AUDIT_RANKED,
                    seq,
                    query_id=query_id,
                    matched=len(matched),
                )
            )
            return QueryResults(
                query_id=query_id,
                query_digest=pin,
                hits=hits,
                total_matched=len(matched),
                seq=seq,
            )


def search_engine_audit_event(kind: str, seq: int, **fields: object) -> dict:
    """Audit-shaped record for a search-engine transition."""
    if kind not in _AUDIT_KINDS:
        raise SearchEngineError(f"unknown audit kind: {kind!r}")
    _require_seq(seq)
    event: dict = {
        "schema": AUDIT_SCHEMA,
        "audit_seq": seq,
        "kind": kind,
        "module_version": SEARCH_ENGINE_VERSION,
    }
    event.update(fields)
    return event


def main() -> None:
    eng = SearchEngine()
    r1 = eng.index("d1", "the quick brown fox jumps over the lazy dog", 1)
    assert r1.term_count == 9, f"{r1.term_count}"
    assert r1.unique_terms == 8, f"{r1.unique_terms}"  # "the" twice
    assert r1.digest.startswith("sha256:"), f"{r1.digest}"
    eng.index("d2", "never jump over the lazy dog quickly", 2)
    eng.index("d3", "bright vixens jump; dozy fowl quack", 3)
    assert len(eng) == 3, f"{len(eng)}"

    # Phrase query: only d1 contains "quick brown" consecutively.
    q = eng.query('"quick brown"', 4)
    assert q.query_id == "q-1", f"{q.query_id}"
    assert q.digest.startswith("sha256:"), f"{q.digest}"
    res = eng.rank("q-1", 5)
    assert [h.doc_id for h in res.hits] == ["d1"], f"{res.hits}"
    assert res.total_matched == 1, f"{res.total_matched}"
    assert res.query_digest == q.digest, f"{res.query_digest}"

    # Boolean: (jump) AND NOT quickly -> d3 only (d2 has "quickly";
    # d1 has "jumps", not the token "jump").
    q2 = eng.query("jump AND NOT quickly", 6)
    res2 = eng.rank("q-2", 7)
    assert {h.doc_id for h in res2.hits} == {"d3"}, f"{res2.hits}"

    # OR union across the corpus.
    q3 = eng.query("fox OR vixens", 8)
    res3 = eng.rank("q-3", 9)
    assert {h.doc_id for h in res3.hits} == {"d1", "d3"}, f"{res3.hits}"

    # Implicit AND.
    q4 = eng.query("lazy dog", 10)
    res4 = eng.rank("q-4", 11)
    assert {h.doc_id for h in res4.hits} == {"d1", "d2"}, f"{res4.hits}"

    # top_k truncation.
    res5 = eng.rank("q-4", 12, top_k=1)
    assert len(res5.hits) == 1 and res5.total_matched == 2, f"{res5}"

    # BM25: "the" appears twice in d1, once in d2 -> d1 outranks d2.
    q6 = eng.query("the", 13)
    res6 = eng.rank("q-5", 14)
    by_id = {h.doc_id: h for h in res6.hits}
    assert set(by_id) == {"d1", "d2"}, f"{by_id.keys()}"
    assert by_id["d1"].score > by_id["d2"].score, f"{res6.hits}"

    # Scores are finite and non-negative; matched terms are pinned.
    for h in res6.hits:
        assert h.score >= 0 and math.isfinite(h.score), f"{h}"
        assert h.matched_terms == ("the",), f"{h}"

    # Determinism: identical plans rank identically.
    assert [h.doc_id for h in eng.rank("q-5", 15).hits] == [
        h.doc_id for h in res6.hits
    ]

    # Audit shapes.
    ev = search_engine_audit_event(AUDIT_INDEXED, 16, doc_id="d1")
    assert ev["schema"] == AUDIT_SCHEMA, f"{ev}"
    try:
        search_engine_audit_event("bogus", 17)
    except SearchEngineError:
        pass
    else:  # pragma: no cover
        raise AssertionError("bad audit kind accepted")

    print(
        "search-engine OK: index, boolean/phrase queries, BM25 rank, "
        "pins, audit"
    )


if __name__ == "__main__":
    main()
