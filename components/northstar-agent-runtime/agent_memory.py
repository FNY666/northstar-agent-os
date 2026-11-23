"""Key-addressed agent memory (store/recall/forget) interface, simulated.

Research motivation: agent memory systems -- MemGPT's core/recall/archival
tiers, Zep's conversation graphs, episodic/semantic/procedural splits --
converge on one ledger shape: declare named memory slots, book what the
host *reported* into them, retrieve on demand, and retire slots with an
explicit forget decision. Getting the bookkeeping wrong (silent
overwrite, recalled-then-denied reads, re-storing a forgotten key)
corrupts the agent's continuity before any retrieval policy runs.

This module is the *memory-slot ledger* half of that shape, deliberately
distinct from the other memory layers on this tree: ``memory.py`` owns
workspace-file discovery, ``memory_fact_belief.py`` owns belief
versioning, ``memory_bitemporal.py`` owns bitemporal validity. This
module owns only the key-addressed slot lifecycle:

- ``AgentMemory.store(key, content, seq, tags=())`` -- book one memory
  slot: a frozen ``MemoryRecord`` with a ``sha256:`` digest pin over
  ``(key, seq, content, sorted tags)``. Duplicate keys are refused
  fail-closed; retired keys are never recycled.
- ``AgentMemory.recall(key, seq)`` -- pure read view returning a frozen
  ``RecallReport``: ``found=True`` with the record, or ``found=False``
  as data for unknown keys (never raised). Seq shape is validated, never
  consumed; no audit row is written.
- ``AgentMemory.search(tags, seq, limit=100)`` -- pure read view of the
  sorted key ids whose tag set covers the query, as data.
- ``AgentMemory.forget(key, seq, reason="manual")`` -- book one forget
  decision: a frozen ``ForgetRecord``. The key leaves the live set and
  is retired forever -- re-storing it raises ``RetiredKeyError``.
- ``agent_memory_audit_event(kind, ...)`` -- ``audit.ndjson/1`` records
  (``memory-stored`` / ``memory-forgotten`` / ``rejected``);
  caller-supplied seqs only. Raw content and tags never cross the
  audit boundary -- audit rows carry keys and digest pins only.

Fail-closed edges (fail loudly, never guess):

- ``key`` must be a non-empty str, <= 256 chars, no whitespace.
- ``content`` must be a non-empty str, <= 65536 chars.
- ``tags`` are non-empty str, <= 64 chars, no whitespace each, at most
  32, deduplicated and sorted.
- ``recall`` / ``search`` on unknown keys / no-match tags return data,
  never raise.
- ``forget`` on an unknown key raises ``UnknownKeyError``; a second
  ``forget`` raises ``RetiredKeyError``.
- Seqs are ints (not bool), >= 0, strictly increasing per instance.
  Failed mutations consume their seq and book a ``rejected`` audit
  row; seq rewinds raise bare ``SeqOrderError`` without consuming.

Honest scope:

- This module books *host-reported* content. A booked memory is a
  ledger entry, not a verified fact -- content is GIGO: the module
  cannot prove the host's claim was true or that a real memory system
  holds it.
- ``recall()`` returns what was booked, never what is true; a digest
  pin proves the record was not altered *in this ledger*, not that the
  content was correct.
- ``forget()`` retires the key and removes it from the live set; the
  ledger keeps a terminal tombstone for audit continuity. This is
  bookkeeping, not cryptographic erasure of every copy.
- No persistence: the ledger is in-memory. Pair with the durable
  audit writer if memory must survive a restart.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


#: Version pin for this module's record shape.
AGENT_MEMORY_VERSION = "agent-memory.v1"

#: Schema pin carried by records and audit events.
AGENT_MEMORY_SCHEMA = "northstar.agent-memory.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Audit event kinds.
KIND_STORED = "memory-stored"
KIND_FORGOTTEN = "memory-forgotten"
KIND_REJECTED = "rejected"
_KINDS = (KIND_STORED, KIND_FORGOTTEN, KIND_REJECTED)

#: Detail keys banned from the audit boundary (raw data never crosses it).
_BANNED_DETAIL_KEYS = frozenset(
    {"content", "tags", "payload", "raw", "value", "data"})

#: Max lengths.
_MAX_KEY_LEN = 256
_MAX_CONTENT_LEN = 65_536
_MAX_TAG_LEN = 64
_MAX_TAGS = 32
_MAX_REASON_LEN = 256
_MAX_LIMIT = 10_000


class AgentMemoryError(Exception):
    """Base error for the agent memory ledger (programming errors)."""


class BadKeyError(AgentMemoryError):
    """Raised when a memory key is malformed."""


class DuplicateKeyError(AgentMemoryError):
    """Raised when a live key is stored twice."""


class RetiredKeyError(AgentMemoryError):
    """Raised when a forgotten (retired) key is used again."""


class UnknownKeyError(AgentMemoryError):
    """Raised when a mutation names no live or retired key."""


class BadContentError(AgentMemoryError):
    """Raised when memory content is malformed."""


class BadTagError(AgentMemoryError):
    """Raised when a tag is malformed or the tag set is too large."""


class BadReasonError(AgentMemoryError):
    """Raised when a forget reason is malformed."""


class BadLimitError(AgentMemoryError):
    """Raised when a search limit is malformed."""


class SeqOrderError(AgentMemoryError):
    """Raised when a seq is malformed or not strictly increasing."""


class AuditKindError(AgentMemoryError):
    """Raised when an audit event kind is unknown or leaks banned keys."""


def _check_seq(value: object, name: str = "seq") -> int:
    """Validate a caller-supplied ordering seq: int, not bool, >= 0."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise SeqOrderError(f"{name} must be int, got {type(value).__name__}")
    if value < 0:
        raise SeqOrderError(f"{name} must be >= 0, got {value}")
    return value


def _check_key(key: object) -> str:
    """Validate a memory key: non-empty str, no whitespace, <= 256 chars."""
    if isinstance(key, bool) or not isinstance(key, str):
        raise BadKeyError(f"key must be str, got {type(key).__name__}")
    if not key:
        raise BadKeyError("key must not be empty")
    if len(key) > _MAX_KEY_LEN:
        raise BadKeyError(f"key too long (>{_MAX_KEY_LEN} chars)")
    if any(ch.isspace() for ch in key):
        raise BadKeyError("key must not contain whitespace")
    return key


def _check_content(content: object) -> str:
    """Validate memory content: non-empty str, bounded."""
    if isinstance(content, bool) or not isinstance(content, str):
        raise BadContentError(
            f"content must be str, got {type(content).__name__}")
    if not content:
        raise BadContentError("content must not be empty")
    if len(content) > _MAX_CONTENT_LEN:
        raise BadContentError(
            f"content too long (>{_MAX_CONTENT_LEN} chars)")
    return content


def _check_tags(tags: object) -> Tuple[str, ...]:
    """Validate tags: tuple/list of non-empty str, deduped, sorted."""
    if isinstance(tags, bool):
        raise BadTagError("tags must not be bool")
    if not isinstance(tags, (tuple, list)):
        raise BadTagError(
            f"tags must be tuple/list, got {type(tags).__name__}")
    out: List[str] = []
    for tag in tags:
        if isinstance(tag, bool) or not isinstance(tag, str):
            raise BadTagError(
                f"tag must be str, got {type(tag).__name__}")
        if not tag:
            raise BadTagError("tag must not be empty")
        if len(tag) > _MAX_TAG_LEN:
            raise BadTagError(f"tag too long (>{_MAX_TAG_LEN} chars)")
        if any(ch.isspace() for ch in tag):
            raise BadTagError("tag must not contain whitespace")
        out.append(tag)
    if len(set(out)) != len(out):
        # Dedup is deterministic; duplicates are a caller bug.
        out = sorted(set(out))
    else:
        out = sorted(out)
    if len(out) > _MAX_TAGS:
        raise BadTagError(f"too many tags (>{_MAX_TAGS})")
    return tuple(out)


def _check_reason(reason: object) -> str:
    """Validate a forget reason: str, bounded."""
    if isinstance(reason, bool) or not isinstance(reason, str):
        raise BadReasonError(
            f"reason must be str, got {type(reason).__name__}")
    if len(reason) > _MAX_REASON_LEN:
        raise BadReasonError(
            f"reason too long (>{_MAX_REASON_LEN} chars)")
    return reason


def _check_limit(limit: object) -> int:
    """Validate a search limit: int (not bool), 1..10000."""
    if isinstance(limit, bool) or not isinstance(limit, int):
        raise BadLimitError(
            f"limit must be int, got {type(limit).__name__}")
    if not 1 <= limit <= _MAX_LIMIT:
        raise BadLimitError(f"limit must be 1..{_MAX_LIMIT}, got {limit}")
    return limit


def _pin(*parts: object) -> str:
    """Digest pin over a domain-separated canonical tuple."""
    return "sha256:" + jcs_sha256_hex({
        "domain": AGENT_MEMORY_SCHEMA,
        "parts": list(parts),
    })


def agent_memory_audit_event(kind: str, detail: Dict[str, object],
                             seq: object) -> Dict[str, object]:
    """Build one ``audit.ndjson/1`` audit row for the memory ledger."""
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    banned = _BANNED_DETAIL_KEYS.intersection(detail.keys())
    if banned:
        raise AuditKindError(
            f"detail keys banned from audit boundary: {sorted(banned)}")
    return {
        "schema": AUDIT_SCHEMA,
        "module": AGENT_MEMORY_VERSION,
        "kind": kind,
        "seq": seq,
        "detail": dict(detail),
    }


@dataclass(frozen=True)
class MemoryRecord:
    """Frozen record of one stored memory slot."""
    key: str
    content: str
    tags: Tuple[str, ...]
    seq: int
    digest: str

    def verify(self, key: str, content: str,
               tags: Tuple[str, ...]) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin("store", key, self.seq, content,
                                   list(tags))


@dataclass(frozen=True)
class RecallReport:
    """Pure read view of a recall: found as data, never raised."""
    seq: int
    key: str
    found: bool
    record: Optional[MemoryRecord]


@dataclass(frozen=True)
class SearchReport:
    """Pure read view of a tag search: sorted key ids, as data."""
    seq: int
    tags: Tuple[str, ...]
    keys: Tuple[str, ...]


@dataclass(frozen=True)
class ForgetRecord:
    """Frozen record of one forget decision (terminal)."""
    key: str
    reason: str
    seq: int
    digest: str

    def verify(self, key: str, reason: str) -> bool:
        """Recompute the pin and compare (True = untampered)."""
        return self.digest == _pin("forget", key, reason, self.seq)


class AgentMemory:
    """Deterministic key-addressed agent memory ledger.

    All mutations take caller-supplied strictly increasing int seqs,
    are RLock-guarded, and book frozen records with ``sha256:`` digest
    pins plus ``audit.ndjson/1`` rows. No wall-clock, no randomness.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._live: Dict[str, MemoryRecord] = {}
        self._retired: Dict[str, ForgetRecord] = {}
        self._last_seq = 0
        self._audit: list = []

    # -- seq discipline ---------------------------------------------------

    def _claim(self, seq: object) -> int:
        """Validate seq; rewinds raise bare (no consumption)."""
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must be strictly increasing "
                f"(last={self._last_seq}, got={seq})")
        return seq

    def _burn(self, seq: int, error: Exception) -> None:
        """Consume the seq, book a rejected row, then raise."""
        self._last_seq = seq
        self._audit.append(agent_memory_audit_event(
            KIND_REJECTED, {"error": type(error).__name__}, seq))
        raise error

    def _emit(self, kind: str, detail: Dict[str, object], seq: int) -> None:
        self._audit.append(agent_memory_audit_event(kind, detail, seq))

    def _guard_key(self, key: str) -> str:
        """Refuse retired keys fail-closed (live check done by caller)."""
        if key in self._retired:
            raise RetiredKeyError(f"key is retired: {key!r}")
        return key

    # -- mutations ----------------------------------------------------------

    def store(self, key: object, content: object, seq: object,
              tags: object = ()) -> MemoryRecord:
        """Book one memory slot; duplicates and retired keys refused."""
        with self._lock:
            seq = self._claim(seq)
            try:
                key = _check_key(key)
                content = _check_content(content)
                tags = _check_tags(tags)
                self._guard_key(key)
                if key in self._live:
                    raise DuplicateKeyError(
                        f"key already stored: {key!r}")
            except AgentMemoryError as e:
                self._burn(seq, e)
            rec = MemoryRecord(key=key, content=content, tags=tags,
                               seq=seq,
                               digest=_pin("store", key, seq, content,
                                           list(tags)))
            self._live[key] = rec
            self._last_seq = seq
            # Raw content/tags banned from the audit boundary: pins only.
            self._emit(KIND_STORED,
                       {"key": key, "digest": rec.digest,
                        "tag_count": len(tags)}, seq)
            return rec

    def forget(self, key: object, seq: object,
               reason: object = "manual") -> ForgetRecord:
        """Book one forget decision: key leaves the live set, retired."""
        with self._lock:
            seq = self._claim(seq)
            try:
                key = _check_key(key)
                reason = _check_reason(reason)
                if key in self._retired:
                    raise RetiredKeyError(f"key already retired: {key!r}")
                if key not in self._live:
                    raise UnknownKeyError(f"unknown key: {key!r}")
            except AgentMemoryError as e:
                self._burn(seq, e)
            rec = ForgetRecord(key=key, reason=reason, seq=seq,
                               digest=_pin("forget", key, reason, seq))
            del self._live[key]
            self._retired[key] = rec
            self._last_seq = seq
            self._emit(KIND_FORGOTTEN,
                       {"key": key, "reason": reason,
                        "digest": rec.digest}, seq)
            return rec

    # -- pure reads -----------------------------------------------------------

    def recall(self, key: object, seq: object) -> RecallReport:
        """Pure read: the stored record as data; unknown key is data.

        Validates seq shape, consumes nothing, writes no audit row.
        """
        _check_seq(seq)
        key = _check_key(key)
        with self._lock:
            rec = self._live.get(key)
        return RecallReport(seq=seq, key=key, found=rec is not None,
                            record=rec)

    def search(self, tags: object, seq: object,
               limit: object = 100) -> SearchReport:
        """Pure read: sorted live key ids whose tags cover ``tags``.

        Validates seq shape, consumes nothing, writes no audit row.
        No-match is empty data, never raised.
        """
        _check_seq(seq)
        tags = _check_tags(tags)
        limit = _check_limit(limit)
        with self._lock:
            need = set(tags)
            matched = sorted(k for k, rec in self._live.items()
                             if need.issubset(rec.tags))
        return SearchReport(seq=seq, tags=tags,
                            keys=tuple(matched[:limit]))

    # -- views -----------------------------------------------------------------

    def memory_record(self, key: str) -> Optional[MemoryRecord]:
        """Return the live memory record, or None when absent (pure read)."""
        return self._live.get(key)

    def keys(self) -> Tuple[str, ...]:
        """Sorted live key ids (pure read)."""
        return tuple(sorted(self._live))

    def retired_keys(self) -> Tuple[str, ...]:
        """Sorted retired key ids (pure read)."""
        return tuple(sorted(self._retired))

    def stats(self, seq: object) -> Dict[str, int]:
        """Ledger stats as data: seq validated, never consumed."""
        _check_seq(seq)
        with self._lock:
            return {"live": len(self._live),
                    "retired": len(self._retired),
                    "audit_rows": len(self._audit)}

    def audit_log(self) -> Tuple[Dict[str, object], ...]:
        """Booked audit rows, oldest first (pure read)."""
        return tuple(self._audit)


def main() -> None:
    """Self-check: store, recall, search, forget, terminality."""
    m = AgentMemory()
    rec = m.store("pref/theme", "dark", 1, tags=("pref", "ui"))
    assert rec.verify("pref/theme", "dark", ("pref", "ui"))
    m.store("pref/lang", "zh", 2, tags=("pref",))
    rep = m.recall("pref/theme", 2)
    assert rep.found and rep.record is not None
    assert rep.record.content == "dark"
    assert not m.recall("nope", 2).found
    assert m.search(("pref",), 2).keys == ("pref/lang", "pref/theme")
    assert m.search(("ui",), 2).keys == ("pref/theme",)
    assert m.search(("zzz",), 2).keys == ()
    fr = m.forget("pref/theme", 3, reason="superseded")
    assert fr.verify("pref/theme", "superseded")
    assert m.keys() == ("pref/lang",)
    assert m.retired_keys() == ("pref/theme",)
    assert not m.recall("pref/theme", 3).found
    stats = m.stats(3)
    assert stats == {"live": 1, "retired": 1, "audit_rows": 3}, stats
    assert len(m.audit_log()) == 3
    print("agent-memory OK: store, recall, search, forget, terminal")


if __name__ == "__main__":
    main()
