"""Token counting (count/estimate/truncate) interface, simulated.

Research motivation: every production LLM system is really a budgeting
system with a token ledger at its core -- context budgets, billing
metering, prompt-truncation policies, and cost forecasts all reduce to
"how many tokens is this text under tokenizer T?" Getting the count
wrong means silent context overflow (dropped instructions) or silent
over-billing. The tokenizer itself (BPE, SentencePiece, wordpiece) is a
deterministic algorithm; what this module owns is the *counting
ledger* around it: declare a tokenizer, book exact counts, offer a
cheap heuristic estimate, and book truncation decisions.

This module is the counting layer, deliberately distinct from the
frozen ``TokenLedger``/budget siblings (which spend tokens): those own
allowance; this owns the *measurement* of what a string costs.

- ``TokenCounter.register_tokenizer(tokenizer_id, seq, vocab_size=0,
  kind="whitespace")`` -- declare a tokenizer. Pinned kinds:
  ``whitespace`` (tokens = ``text.split()``), ``char`` (tokens =
  ``list(text)``), ``wordpiece`` (greedy longest-match segmentation
  against the registered piece set -- a real, deterministic
  algorithm, not a toy). Returns a frozen ``TokenizerRecord``.
  Duplicate ids refused; ids never recycled.
- ``TokenCounter.register_piece(tokenizer_id, piece, seq)`` -- book one
  vocabulary piece for a ``wordpiece`` tokenizer. On any other kind
  the call fails closed (there is nothing to segment against);
  duplicates refused.
- ``TokenCounter.count(tokenizer_id, text, seq)`` -- exact count under
  the tokenizer's segmentation. Returns a frozen ``CountRecord`` with
  ``token_count`` and a ``sha256:`` digest pin over
  ``(tokenizer_id, text)`` so the count is replayable without
  re-entering host text. This is an *audited decision*: it consumes a
  seq and books a ``counted`` audit row.
- ``TokenCounter.estimate(tokenizer_id, text, seq)`` -- cheap heuristic
  estimate as a *pure read view* (validates seq shape, consumes
  nothing, books no audit row): ``chars // 4`` scaled per kind
  (``whitespace`` +1 rounding documented as ``ESTIMATE_RULES``).
  Heuristic, never exact -- the docstring says so.
- ``TokenCounter.truncate(tokenizer_id, text, max_tokens, seq)`` --
  segment with the same tokenizer and cut to ``max_tokens`` tokens.
  Returns a frozen ``TruncateRecord`` with the truncated text,
  ``truncated_tokens``, ``dropped_count``, and a digest pin over the
  truncated text. When the text already fits, the text is returned
  unchanged with ``dropped_count == 0``.

- ``token_counter_audit_event(kind, ...)`` -- ``audit.ndjson/1``
  records (``tokenizer-registered`` / ``piece-registered`` /
  ``counted`` / ``truncated`` / ``rejected``); caller-supplied seqs
  only. Raw text never crosses the audit boundary -- audit rows carry
  ids, counts, and digest pins only.

Fail-closed edges (fail loudly, never guess):

- ``tokenizer_id``: non-empty str, <= 256 chars, no whitespace.
- ``kind`` is pinned: ``whitespace`` / ``char`` / ``wordpiece``.
- ``text`` must be a str (bytes refused); token counts are exact
  ``int`` >= 0.
- ``register_piece`` on a non-``wordpiece`` tokenizer raises
  ``BadKindError``; a duplicate piece raises ``DuplicatePieceError``.
- ``truncate`` ``max_tokens`` must be an int >= 1 (bool refused).
- Seqs are ints (not bool), >= 0, strictly increasing per instance.
  Failed mutations consume their seq and book a ``rejected`` audit
  row; seq rewinds raise bare ``SeqOrderError`` without consuming.

Honest scope:

- Counting is *ledger truth*: a booked count is what this module's
  segmentation produced. For ``whitespace``/``char`` that is exact by
  construction; ``wordpiece`` greedy longest-match is the real
  segmentation the ledger applies, but it is not a claim about what
  any production tokenizer (tiktoken, SentencePiece) would emit --
  those need their own vocabulary. Do not use ``count()`` as proof of
  a production tokenizer's bill.
- ``estimate()`` is a heuristic by design -- the docstring and the
  ``ESTIMATE_RULES`` table say exactly what it computes. It is for
  cheap pre-flight checks, never for billing.
- ``truncate()`` books the truncation *decision* (which tokens were
  kept/dropped) -- it is not proof the downstream model saw the
  truncated text.
- No persistence: the ledger is in-memory. Pair with the durable
  audit writer if counting state must survive a restart.
"""

from __future__ import annotations

import ast
import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, List, Optional, Tuple

try:  # canonical-json fast path with stdlib fallback
    from canonical_json import jcs_dumps as _jcs_dumps  # type: ignore
except Exception:  # pragma: no cover - fallback path
    import json as _json

    def _jcs_dumps(obj: Any) -> str:
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False)


VERSION = "token-counter.v1"
SCHEMA = "northstar.token-counter.v1"
AUDIT_SCHEMA = "audit.ndjson/1"

KIND_WHITESPACE = "whitespace"
KIND_CHAR = "char"
KIND_WORDPIECE = "wordpiece"
_TOKENIZER_KINDS: FrozenSet[str] = frozenset(
    {KIND_WHITESPACE, KIND_CHAR, KIND_WORDPIECE})

# Heuristic rules for estimate(): chars_per_token per kind. Documented so
# callers can see exactly what the heuristic computes.
ESTIMATE_RULES: Dict[str, int] = {
    KIND_WHITESPACE: 5,
    KIND_CHAR: 1,
    KIND_WORDPIECE: 4,
}

KIND_TOKENIZER_REGISTERED = "tokenizer-registered"
KIND_PIECE_REGISTERED = "piece-registered"
KIND_COUNTED = "counted"
KIND_TRUNCATED = "truncated"
KIND_REJECTED = "rejected"
_KINDS: FrozenSet[str] = frozenset({
    KIND_TOKENIZER_REGISTERED,
    KIND_PIECE_REGISTERED,
    KIND_COUNTED,
    KIND_TRUNCATED,
    KIND_REJECTED,
})

_BANNED_AUDIT_KEYS: FrozenSet[str] = frozenset(
    {"text", "raw", "payload", "value", "tokens", "pieces"})


# --------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# --------------------------------------------------------------------------

class TokenCounterError(Exception):
    """Base error for the token counter."""


class BadTokenizerError(TokenCounterError):
    pass


class DuplicateTokenizerError(TokenCounterError):
    pass


class UnknownTokenizerError(TokenCounterError):
    pass


class BadKindError(TokenCounterError):
    pass


class BadTextError(TokenCounterError):
    pass


class BadPieceError(TokenCounterError):
    pass


class DuplicatePieceError(TokenCounterError):
    pass


class BadMaxTokensError(TokenCounterError):
    pass


class SeqOrderError(TokenCounterError):
    pass


class AuditKindError(TokenCounterError):
    pass


# --------------------------------------------------------------------------
# Frozen records
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class TokenizerRecord:
    tokenizer_id: str
    kind: str
    vocab_size: int
    seq: int
    digest: str
    schema: str = SCHEMA

    def verify(self) -> bool:
        expect = _digest_pin("tokenizer", (self.tokenizer_id, self.kind,
                                          self.vocab_size))
        return self.digest == expect

    def as_dict(self) -> Dict[str, Any]:
        return {"tokenizer_id": self.tokenizer_id, "kind": self.kind,
                "vocab_size": self.vocab_size, "seq": self.seq,
                "digest": self.digest, "schema": self.schema}


@dataclass(frozen=True)
class CountRecord:
    tokenizer_id: str
    token_count: int
    tokens: Tuple[str, ...]
    seq: int
    digest: str
    schema: str = SCHEMA

    def verify(self) -> bool:
        expect = _digest_pin("count", (self.tokenizer_id, self.tokens))
        return self.digest == expect

    def as_dict(self) -> Dict[str, Any]:
        return {"tokenizer_id": self.tokenizer_id,
                "token_count": self.token_count,
                "seq": self.seq, "digest": self.digest,
                "schema": self.schema}


@dataclass(frozen=True)
class EstimateReport:
    tokenizer_id: str
    kind: str
    char_count: int
    estimated_tokens: int
    rule_chars_per_token: int
    seq: int
    schema: str = SCHEMA

    def as_dict(self) -> Dict[str, Any]:
        return {"tokenizer_id": self.tokenizer_id, "kind": self.kind,
                "char_count": self.char_count,
                "estimated_tokens": self.estimated_tokens,
                "rule_chars_per_token": self.rule_chars_per_token,
                "seq": self.seq, "schema": self.schema}


@dataclass(frozen=True)
class TruncateRecord:
    tokenizer_id: str
    truncated_text: str
    truncated_tokens: Tuple[str, ...]
    dropped_count: int
    original_count: int
    seq: int
    digest: str
    schema: str = SCHEMA

    def verify(self) -> bool:
        expect = _digest_pin("truncate", (self.tokenizer_id,
                                         self.truncated_tokens))
        return self.digest == expect

    def as_dict(self) -> Dict[str, Any]:
        return {"tokenizer_id": self.tokenizer_id,
                "truncated_text": self.truncated_text,
                "dropped_count": self.dropped_count,
                "original_count": self.original_count,
                "seq": self.seq, "digest": self.digest,
                "schema": self.schema}


# --------------------------------------------------------------------------
# Digest helpers
# --------------------------------------------------------------------------

def _digest_pin(tag: str, parts: Tuple[Any, ...]) -> str:
    body = _jcs_dumps({"tag": tag, "parts": list(parts)})
    return "sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------
# Audit event builder (validated boundary)
# --------------------------------------------------------------------------

def token_counter_audit_event(audit_kind: str, **details: Any) -> Dict[str, Any]:
    """Build one validated ``audit.ndjson/1`` audit row."""
    if audit_kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {audit_kind!r}")
    bad = _BANNED_AUDIT_KEYS.intersection(details)
    if bad:
        raise AuditKindError(f"raw content banned from audit boundary: "
                             f"{sorted(bad)}")
    row: Dict[str, Any] = {"schema": AUDIT_SCHEMA, "kind": audit_kind}
    row.update(details)
    return row


# --------------------------------------------------------------------------
# Segmentation
# --------------------------------------------------------------------------

def _segment_whitespace(text: str) -> Tuple[str, ...]:
    return tuple(text.split())


def _segment_char(text: str) -> Tuple[str, ...]:
    return tuple(text)


def _segment_wordpiece(text: str, pieces: FrozenSet[str]) -> Tuple[str, ...]:
    """Greedy longest-match segmentation over the piece set.

    Deterministic: at each position the longest registered piece that
    prefixes the remaining text wins; no piece matches -> the single
    char at the position is emitted as-is (unknown token handling).
    """
    out: List[str] = []
    i = 0
    n = len(text)
    max_len = max((len(p) for p in pieces), default=0)
    while i < n:
        best: Optional[str] = None
        upper = min(n, i + max_len)
        for j in range(upper, i, -1):
            cand = text[i:j]
            if cand in pieces:
                best = cand
                break
        if best is None:
            best = text[i]
            i += 1
        else:
            i += len(best)
        out.append(best)
    return tuple(out)


# --------------------------------------------------------------------------
# Ledger
# --------------------------------------------------------------------------

_REASON_BY_ERROR = (
    (DuplicateTokenizerError, "duplicate-tokenizer"),
    (UnknownTokenizerError, "unknown-tokenizer"),
    (BadKindError, "bad-kind"),
    (BadTextError, "bad-text"),
    (BadPieceError, "bad-piece"),
    (DuplicatePieceError, "duplicate-piece"),
    (BadMaxTokensError, "bad-max-tokens"),
    (BadTokenizerError, "bad-tokenizer"),
)


def _reason(exc: TokenCounterError) -> str:
    for cls, reason in _REASON_BY_ERROR:
        if isinstance(exc, cls):
            return reason
    return "rejected"


class TokenCounter:
    """Deterministic token-count ledger for declared tokenizers."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = -1
        self._tokenizers: Dict[str, Dict[str, Any]] = {}
        self._audit: List[Dict[str, Any]] = []

    # -- seq discipline ----------------------------------------------------

    def _check_seq(self, seq: int) -> None:
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise SeqOrderError(f"bad seq: {seq!r}")

    def _claim_seq(self, seq: int) -> None:
        self._check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must be strictly increasing: {seq} <= {self._last_seq}")
        self._last_seq = seq

    def _emit(self, audit_kind: str, seq: int, **details: Any) -> None:
        self._audit.append(token_counter_audit_event(
            audit_kind, seq=seq, module=VERSION, **details))

    def _reject(self, seq: int, reason: str) -> None:
        self._emit(KIND_REJECTED, seq, reason=reason)

    # -- validation --------------------------------------------------------

    @staticmethod
    def _validate_id(tokenizer_id: Any) -> str:
        if (not isinstance(tokenizer_id, str) or not tokenizer_id
                or len(tokenizer_id) > 256
                or any(ch.isspace() for ch in tokenizer_id)):
            raise BadTokenizerError(f"bad tokenizer id: {tokenizer_id!r}")
        return tokenizer_id

    @staticmethod
    def _validate_text(text: Any) -> str:
        if not isinstance(text, str):
            raise BadTextError(f"text must be str, got {type(text).__name__}")
        return text

    def _segment(self, tokenizer_id: str, text: str) -> Tuple[str, ...]:
        decl = self._tokenizers[tokenizer_id]
        kind = decl["kind"]
        if kind == KIND_WHITESPACE:
            return _segment_whitespace(text)
        if kind == KIND_CHAR:
            return _segment_char(text)
        return _segment_wordpiece(text, decl["pieces"])

    # -- API ---------------------------------------------------------------

    def register_tokenizer(self, tokenizer_id: str, seq: int,
                           vocab_size: int = 0,
                           kind: str = KIND_WHITESPACE) -> TokenizerRecord:
        with self._lock:
            self._claim_seq(seq)  # bare on rewind/malformed, no consumption
            try:
                tid = self._validate_id(tokenizer_id)
                if tid in self._tokenizers:
                    raise DuplicateTokenizerError(
                        f"duplicate tokenizer: {tid!r}")
                if kind not in _TOKENIZER_KINDS:
                    raise BadKindError(f"unknown tokenizer kind: {kind!r}")
                if (isinstance(vocab_size, bool)
                        or not isinstance(vocab_size, int)
                        or vocab_size < 0):
                    raise BadTokenizerError(
                        f"bad vocab_size: {vocab_size!r}")
            except TokenCounterError as e:
                self._reject(seq, _reason(e))
                raise
            self._tokenizers[tid] = {
                "kind": kind, "vocab_size": vocab_size,
                "pieces": frozenset(), "seq": seq,
            }
            rec = TokenizerRecord(
                tokenizer_id=tid, kind=kind, vocab_size=vocab_size, seq=seq,
                digest=_digest_pin("tokenizer", (tid, kind, vocab_size)))
            self._emit(KIND_TOKENIZER_REGISTERED, seq, tokenizer_id=tid,
                       kind=kind, vocab_size=vocab_size,
                       digest=rec.digest)
            return rec

    def register_piece(self, tokenizer_id: str, piece: str,
                       seq: int) -> TokenizerRecord:
        with self._lock:
            self._claim_seq(seq)
            try:
                tid = self._validate_id(tokenizer_id)
                decl = self._tokenizers.get(tid)
                if decl is None:
                    raise UnknownTokenizerError(
                        f"unknown tokenizer: {tid!r}")
                if decl["kind"] != KIND_WORDPIECE:
                    raise BadKindError(
                        f"register_piece only valid for {KIND_WORDPIECE}: "
                        f"{tid!r}")
                if (not isinstance(piece, str) or not piece
                        or len(piece) > 256):
                    raise BadPieceError(f"bad piece: {piece!r}")
                if piece in decl["pieces"]:
                    raise DuplicatePieceError(f"duplicate piece: {piece!r}")
            except TokenCounterError as e:
                self._reject(seq, _reason(e))
                raise
            decl["pieces"] = decl["pieces"] | {piece}
            decl["vocab_size"] = decl["vocab_size"] + 1
            self._emit(KIND_PIECE_REGISTERED, seq, tokenizer_id=tid,
                       piece_digest=_digest_pin("piece", (piece,)),
                       vocab_size=decl["vocab_size"])
            return self.tokenizer(tid)

    def tokenizer(self, tokenizer_id: str) -> TokenizerRecord:
        """Pure read view of a declared tokenizer."""
        with self._lock:
            tid = self._validate_id(tokenizer_id)
            decl = self._tokenizers.get(tid)
            if decl is None:
                raise UnknownTokenizerError(f"unknown tokenizer: {tid!r}")
            return TokenizerRecord(
                tokenizer_id=tid, kind=decl["kind"],
                vocab_size=decl["vocab_size"], seq=decl["seq"],
                digest=_digest_pin("tokenizer",
                                   (tid, decl["kind"], decl["vocab_size"])))

    def count(self, tokenizer_id: str, text: str,
              seq: int) -> CountRecord:
        with self._lock:
            self._claim_seq(seq)
            try:
                tid = self._validate_id(tokenizer_id)
                decl = self._tokenizers.get(tid)
                if decl is None:
                    raise UnknownTokenizerError(
                        f"unknown tokenizer: {tid!r}")
                text = self._validate_text(text)
            except TokenCounterError as e:
                self._reject(seq, _reason(e))
                raise
            tokens = self._segment(tid, text)
            rec = CountRecord(
                tokenizer_id=tid, token_count=len(tokens), tokens=tokens,
                seq=seq, digest=_digest_pin("count", (tid, tokens)))
            self._emit(KIND_COUNTED, seq, tokenizer_id=tid,
                       token_count=len(tokens), text_digest=_digest_pin(
                           "text", (text,)),
                       count_digest=rec.digest)
            return rec

    def estimate(self, tokenizer_id: str, text: str,
                 seq: int) -> EstimateReport:
        """Heuristic estimate -- pure read view, no seq consumed."""
        with self._lock:
            self._check_seq(seq)
            tid = self._validate_id(tokenizer_id)
            decl = self._tokenizers.get(tid)
            if decl is None:
                raise UnknownTokenizerError(f"unknown tokenizer: {tid!r}")
            text = self._validate_text(text)
            chars = len(text)
            per = ESTIMATE_RULES[decl["kind"]]
            estimated = (chars + per - 1) // per
            return EstimateReport(
                tokenizer_id=tid, kind=decl["kind"], char_count=chars,
                estimated_tokens=estimated, rule_chars_per_token=per,
                seq=seq)

    def truncate(self, tokenizer_id: str, text: str, max_tokens: int,
                 seq: int) -> TruncateRecord:
        with self._lock:
            self._claim_seq(seq)
            try:
                tid = self._validate_id(tokenizer_id)
                decl = self._tokenizers.get(tid)
                if decl is None:
                    raise UnknownTokenizerError(
                        f"unknown tokenizer: {tid!r}")
                if (isinstance(max_tokens, bool)
                        or not isinstance(max_tokens, int)
                        or max_tokens < 1):
                    raise BadMaxTokensError(
                        f"bad max_tokens: {max_tokens!r}")
                text = self._validate_text(text)
            except TokenCounterError as e:
                self._reject(seq, _reason(e))
                raise
            tokens = self._segment(tid, text)
            original = len(tokens)
            kept = tokens[:max_tokens]
            dropped = original - len(kept)
            if decl["kind"] == KIND_WHITESPACE:
                truncated_text = " ".join(kept)
            elif decl["kind"] == KIND_CHAR:
                truncated_text = "".join(kept)
            else:
                truncated_text = "".join(kept)
            rec = TruncateRecord(
                tokenizer_id=tid, truncated_text=truncated_text,
                truncated_tokens=kept, dropped_count=dropped,
                original_count=original, seq=seq,
                digest=_digest_pin("truncate", (tid, kept)))
            self._emit(KIND_TRUNCATED, seq, tokenizer_id=tid,
                       max_tokens=max_tokens, original_count=original,
                       dropped_count=dropped, text_digest=_digest_pin(
                           "text", (text,)),
                       truncate_digest=rec.digest)
            return rec

    # -- views -------------------------------------------------------------

    def tokenizer_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._tokenizers))

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            return tuple(self._audit)

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {"tokenizers": len(self._tokenizers),
                    "audit_rows": len(self._audit),
                    "last_seq": self._last_seq,
                    "schema": SCHEMA, "version": VERSION}


def main() -> None:
    tc = TokenCounter()
    r = tc.register_tokenizer("tok-ws", 1)
    assert r.verify()
    c = tc.count("tok-ws", "hello world", 2)
    assert c.token_count == 2 and c.verify()
    e = tc.estimate("tok-ws", "hello world", 3)
    assert e.estimated_tokens >= 0
    t = tc.truncate("tok-ws", "hello world", 1, 4)
    assert t.truncated_text == "hello" and t.dropped_count == 1
    tc.register_tokenizer("tok-wp", 5, kind="wordpiece")
    for i, p in enumerate(["hello", "world", "he", "llo"]):
        tc.register_piece("tok-wp", p, 6 + i)
    cw = tc.count("tok-wp", "helloworld", 10)
    assert cw.tokens == ("hello", "world"), cw.tokens
    print("token-counter OK: register, count, estimate, truncate, wordpiece")


if __name__ == "__main__":
    main()
