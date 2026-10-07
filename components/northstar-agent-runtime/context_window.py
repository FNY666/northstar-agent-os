"""Context window: token-budget bookkeeping for a bounded message window.

Research note: production LLM runtimes keep a *context window* — a token
budget over the messages a model may see in one turn. When the booked
messages exceed the budget the runtime must *trim*: decide, by a pinned
eviction policy, which blocks to drop so the survivors fit. This module
is the decision ledger for that process:

* **budget()** declares (or re-declares) a window's token capacity. The
  first call creates the window; later calls book capacity changes.
* **append()** books one message block with a *simulated* token estimate.
* **count()** is a pure read view: used tokens, capacity, remaining.
* **trim()** executes the pinned eviction policy — oldest first — and
  books the eviction decision. Pinned ids and the ``keep_recent`` newest
  blocks are never evicted.
* **close()** retires a window; the id is never recycled.

Deliberately distinct from the siblings ``budget.py`` (permission-gate
budgets), ``budget_token_bucket.py`` (rate-limit bucket) and
``memory_budget_combo.py`` (a combo module): this module owns *token
accounting over ordered message blocks* — estimation, usage, and
eviction decisions — not rate limiting or permission gating. House style
throughout: frozen dataclasses, caller-supplied strictly-increasing int
seqs, no wall-clock, RLock guarding, fail-closed taxonomy, stdlib-only
with the standard ``canonical_json`` try/except fallback, ``sha256:``
digest pins, and ``audit.ndjson/1`` events.

Honest scope: the module books *declared* budgets and host-reported
text. The token estimator (``tok-est.v1``: ``ceil(utf8_bytes / 4)``) is a
pinned *simulation*, not any vendor's tokenizer — counts are
deterministic ledger truth, never proof of what a real model would
count. Raw text never crosses the audit boundary (digest pins only); a
trim decision books which blocks were evicted, never that a model
actually dropped them.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

try:  # stdlib-first; canonical_json is the sibling JCS helper
    import canonical_json as _cj  # type: ignore
except Exception:  # pragma: no cover - fallback keeps stdlib-only promise
    _cj = None  # type: ignore

#: Version pin for this module's record shape.
CONTEXT_WINDOW_VERSION = "context-window.v1"

#: Schema pin carried by records and audit events.
CONTEXT_WINDOW_SCHEMA = "northstar.context-window.v1"

#: Wire format of audit records.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Fixed vocabulary for audit event kinds.
KIND_BUDGET = "context-window.budget-declared"
KIND_APPENDED = "context-window.block-appended"
KIND_TRIMMED = "context-window.trimmed"
KIND_CLOSED = "context-window.closed"
KIND_REJECTED = "context-window.rejected"
_KINDS = frozenset({KIND_BUDGET, KIND_APPENDED, KIND_TRIMMED, KIND_CLOSED, KIND_REJECTED})

#: Pinned simulated token estimator: ceil(utf-8 bytes / 4).
ESTIMATOR_VERSION = "tok-est.v1"
_ESTIMATOR_DIVISOR = 4

#: Pinned message-role vocabulary.
ROLE_SYSTEM = "system"
ROLE_USER = "user"
ROLE_ASSISTANT = "assistant"
ROLE_TOOL = "tool"
_ROLES = frozenset({ROLE_SYSTEM, ROLE_USER, ROLE_ASSISTANT, ROLE_TOOL})

_MAX_INT = 2**53 - 1
_DIGEST_PREFIX = "sha256:"
_MAX_ID_LEN = 256
_MAX_TEXT_LEN = 1_000_000

# Window lifecycle states.
_STATE_ACTIVE = "active"
_STATE_CLOSED = "closed"


# ---------------------------------------------------------------------------
# Error taxonomy (fail-closed)
# ---------------------------------------------------------------------------


class ContextWindowError(Exception):
    """Base class for all context-window errors."""


class BadWindowError(ContextWindowError):
    """window_id is not a usable non-empty str."""


class UnknownWindowError(ContextWindowError):
    """window_id names no window this ledger ever saw."""


class RetiredWindowError(ContextWindowError):
    """The window was closed; the id is never recycled."""


class BadCapacityError(ContextWindowError):
    """capacity is not a positive safe-range int (bool refused)."""


class BadBlockError(ContextWindowError):
    """block_id is not a usable non-empty str."""


class DuplicateBlockError(ContextWindowError):
    """block_id is already booked on this window; ids are never recycled."""


class UnknownBlockError(ContextWindowError):
    """block_id names no live block on this window."""


class BadTextError(ContextWindowError):
    """text is not a str, or exceeds the bounded length."""


class BadRoleError(ContextWindowError):
    """role is not in the pinned vocabulary."""


class BadTrimError(ContextWindowError):
    """keep_recent / pin_ids are malformed."""


class TrimImpossibleError(ContextWindowError):
    """Protected blocks alone exceed the window's capacity."""


class SeqOrderError(ContextWindowError):
    """seq is not a fresh strictly-increasing int."""


class AuditKindError(ContextWindowError):
    """audit builder was handed an unknown kind or a banned detail key."""


# ---------------------------------------------------------------------------
# Canonical encoding and digest pins
# ---------------------------------------------------------------------------


def _canonical(payload: Any) -> bytes:
    if _cj is not None:
        return _cj.jcs_dumps(payload).encode("utf-8")  # type: ignore

    def _tag(v: Any) -> Any:
        if isinstance(v, bool):
            return {"t": "bool", "v": v}
        if isinstance(v, int):
            if abs(v) > _MAX_INT:
                raise ContextWindowError("integer outside safe range")
            return {"t": "int", "v": v}
        if isinstance(v, float):
            if v != v or v in (float("inf"), float("-inf")):
                raise ContextWindowError("non-finite float refused")
            return {"t": "float", "v": repr(v)}
        if isinstance(v, str):
            return {"t": "str", "v": v}
        if isinstance(v, (list, tuple)):
            return {"t": "list", "v": [_tag(i) for i in v]}
        if isinstance(v, dict):
            return {"t": "dict", "v": [[k, _tag(v[k])] for k in sorted(v)]}
        if v is None:
            return {"t": "null"}
        raise ContextWindowError(f"unencodable type: {type(v).__name__}")

    import json

    return json.dumps(_tag(payload), sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest_pin(payload: Any, tag: str) -> str:
    return _DIGEST_PREFIX + hashlib.sha256(
        (tag + ":").encode("utf-8") + _canonical(payload)
    ).hexdigest()


# ---------------------------------------------------------------------------
# Input checks and the simulated estimator
# ---------------------------------------------------------------------------


def _check_id(value: Any, err: type) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise err(f"id must be a str, got {type(value).__name__}")
    if not value or len(value) > _MAX_ID_LEN or value != value.strip():
        raise err(f"id must be 1..{_MAX_ID_LEN} non-blank chars")
    return value


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError(f"seq must be an int, got {type(seq).__name__}")
    return seq


def _check_capacity(capacity: Any) -> int:
    if isinstance(capacity, bool) or not isinstance(capacity, int):
        raise BadCapacityError(f"capacity must be an int, got {type(capacity).__name__}")
    if capacity < 1 or capacity > _MAX_INT:
        raise BadCapacityError(f"capacity must be 1..{_MAX_INT}")
    return capacity


def _check_text(text: Any) -> str:
    if isinstance(text, bool) or not isinstance(text, str):
        raise BadTextError(f"text must be a str, got {type(text).__name__}")
    if len(text) > _MAX_TEXT_LEN:
        raise BadTextError(f"text exceeds {_MAX_TEXT_LEN} chars")
    return text


def _check_role(role: Any) -> str:
    if isinstance(role, bool) or not isinstance(role, str) or role not in _ROLES:
        raise BadRoleError(f"role must be one of {sorted(_ROLES)}")
    return role


def estimate_tokens(text: str) -> int:
    """Simulated token estimate (``tok-est.v1``): ``ceil(utf8_bytes / 4)``.

    Deterministic for identical text; a simulation, never a vendor count.
    """
    _check_text(text)
    return (len(text.encode("utf-8")) + _ESTIMATOR_DIVISOR - 1) // _ESTIMATOR_DIVISOR


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BudgetRecord:
    """One declared token budget for a window."""

    window_id: str
    capacity: int
    seq: int
    estimator_version: str = ESTIMATOR_VERSION
    digest: str = ""
    schema: str = CONTEXT_WINDOW_SCHEMA

    def verify(self) -> bool:
        expect = _digest_pin(
            (self.window_id, self.capacity, self.seq, self.estimator_version),
            "budget-record",
        )
        return self.digest == expect


@dataclass(frozen=True)
class BlockRecord:
    """One booked message block (token estimate + text digest only)."""

    window_id: str
    block_id: str
    role: str
    token_count: int
    text_digest: str
    seq: int
    digest: str = ""
    schema: str = CONTEXT_WINDOW_SCHEMA

    def verify(self) -> bool:
        expect = _digest_pin(
            (
                self.window_id,
                self.block_id,
                self.role,
                self.token_count,
                self.text_digest,
                self.seq,
            ),
            "block-record",
        )
        return self.digest == expect


@dataclass(frozen=True)
class CountReport:
    """Pure read view: token usage of a window against its capacity."""

    window_id: str
    used: int
    capacity: int
    remaining: int
    over_budget: bool
    live_blocks: int
    digest: str = ""
    schema: str = CONTEXT_WINDOW_SCHEMA

    def verify(self) -> bool:
        expect = _digest_pin(
            (self.window_id, self.used, self.capacity, self.live_blocks),
            "count-report",
        )
        return self.digest == expect


@dataclass(frozen=True)
class TrimReport:
    """Booked eviction decision: which blocks were dropped to fit the budget."""

    window_id: str
    evicted_ids: Tuple[str, ...]
    used_after: int
    capacity: int
    seq: int
    digest: str = ""
    schema: str = CONTEXT_WINDOW_SCHEMA

    def verify(self) -> bool:
        expect = _digest_pin(
            (self.window_id, self.evicted_ids, self.used_after, self.capacity, self.seq),
            "trim-report",
        )
        return self.digest == expect


@dataclass(frozen=True)
class CloseRecord:
    """Terminal retirement of a window."""

    window_id: str
    reason: str
    seq: int
    digest: str = ""
    schema: str = CONTEXT_WINDOW_SCHEMA

    def verify(self) -> bool:
        expect = _digest_pin((self.window_id, self.reason, self.seq), "close-record")
        return self.digest == expect


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def context_window_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
    """Build one audit.ndjson/1 event. Raw text never crosses this boundary."""
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    banned = ("text", "content", "value", "payload", "raw", "body", "data", "message")
    for bad in banned:
        if bad in detail:
            raise AuditKindError(f"audit detail bans {bad!r}")
    _check_seq(seq)
    event = {
        "schema": AUDIT_SCHEMA,
        "module": "context_window",
        "kind": kind,
        "seq": seq,
        "detail": detail,
    }
    event["digest"] = _digest_pin((kind, seq, tuple(sorted(detail))), "audit-event")
    return event


# ---------------------------------------------------------------------------
# Ledger
# ---------------------------------------------------------------------------


class ContextWindow:
    """Token-budget ledger over ordered message blocks in named windows."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = 0
        # window_id -> dict(capacity, state, budgets[list], blocks[dict])
        # blocks: block_id -> dict(block_id, role, token_count, text_digest, seq, evicted)
        self._windows: Dict[str, Dict[str, Any]] = {}
        self._audit: List[Dict[str, Any]] = []

    # -- seq discipline ----------------------------------------------------

    def _claim(self, seq: Any) -> int:
        seq = _check_seq(seq)
        if seq <= self._seq:
            raise SeqOrderError(f"seq {seq} not strictly greater than {self._seq}")
        self._seq = seq
        return seq

    def _emit(self, audit_kind: str, seq: int, **detail: Any) -> None:
        self._audit.append(context_window_audit_event(audit_kind, seq, **detail))

    def _fail(self, seq: int, exc: ContextWindowError, **detail: Any) -> None:
        self._emit(KIND_REJECTED, seq, error=type(exc).__name__, **detail)
        raise exc

    def _get_active(self, window_id: str, seq: int) -> Dict[str, Any]:
        entry = self._windows.get(window_id)
        if entry is None:
            self._fail(seq, UnknownWindowError(f"unknown window: {window_id!r}"), window_id=window_id)
        assert entry is not None
        if entry["state"] == _STATE_CLOSED:
            self._fail(
                seq, RetiredWindowError(f"window closed: {window_id!r}"), window_id=window_id
            )
        return entry

    def _usage(self, entry: Dict[str, Any]) -> Tuple[int, int]:
        used = sum(
            b["token_count"] for b in entry["blocks"].values() if not b["evicted"]
        )
        live = sum(1 for b in entry["blocks"].values() if not b["evicted"])
        return used, live

    # -- lifecycle ----------------------------------------------------------

    def budget(self, window_id: str, capacity: int, seq: Any) -> BudgetRecord:
        """Declare (or re-declare) a window's token capacity.

        The first call creates the window; later calls book capacity changes.
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                window_id = _check_id(window_id, BadWindowError)
                capacity = _check_capacity(capacity)
            except ContextWindowError as exc:
                self._fail(seq, exc)
            entry = self._windows.get(window_id)
            if entry is not None and entry["state"] == _STATE_CLOSED:
                self._fail(
                    seq,
                    RetiredWindowError(f"window closed: {window_id!r}"),
                    window_id=window_id,
                )
            if entry is None:
                entry = {
                    "window_id": window_id,
                    "capacity": capacity,
                    "state": _STATE_ACTIVE,
                    "budgets": [],
                    "blocks": {},
                }
                self._windows[window_id] = entry
            entry["capacity"] = capacity
            digest = _digest_pin(
                (window_id, capacity, seq, ESTIMATOR_VERSION), "budget-record"
            )
            rec = BudgetRecord(
                window_id=window_id,
                capacity=capacity,
                seq=seq,
                estimator_version=ESTIMATOR_VERSION,
                digest=digest,
            )
            entry["budgets"].append(rec)
            self._emit(
                KIND_BUDGET,
                seq,
                window_id=window_id,
                capacity=capacity,
                estimator_version=ESTIMATOR_VERSION,
            )
            return rec

    def close(self, window_id: str, seq: Any, reason: str = "manual") -> CloseRecord:
        """Terminally retire a window. The id is never recycled."""
        with self._lock:
            seq = self._claim(seq)
            try:
                window_id = _check_id(window_id, BadWindowError)
                if isinstance(reason, bool) or not isinstance(reason, str) or not reason.strip():
                    raise BadWindowError("reason must be a non-blank str")
            except ContextWindowError as exc:
                self._fail(seq, exc)
            entry = self._windows.get(window_id)
            if entry is None:
                self._fail(
                    seq, UnknownWindowError(f"unknown window: {window_id!r}"), window_id=window_id
                )
            assert entry is not None
            if entry["state"] == _STATE_CLOSED:
                self._fail(
                    seq,
                    RetiredWindowError(f"window already closed: {window_id!r}"),
                    window_id=window_id,
                )
            entry["state"] = _STATE_CLOSED
            digest = _digest_pin((window_id, reason, seq), "close-record")
            self._emit(KIND_CLOSED, seq, window_id=window_id, reason=reason)
            return CloseRecord(window_id=window_id, reason=reason, seq=seq, digest=digest)

    # -- blocks -------------------------------------------------------------

    def append(
        self, window_id: str, block_id: str, text: str, seq: Any, role: str = ROLE_USER
    ) -> BlockRecord:
        """Book one message block with its simulated token estimate."""
        with self._lock:
            seq = self._claim(seq)
            try:
                window_id = _check_id(window_id, BadWindowError)
                block_id = _check_id(block_id, BadBlockError)
                text = _check_text(text)
                role = _check_role(role)
            except ContextWindowError as exc:
                self._fail(seq, exc)
            entry = self._get_active(window_id, seq)
            if block_id in entry["blocks"]:
                self._fail(
                    seq,
                    DuplicateBlockError(f"duplicate block: {block_id!r}"),
                    window_id=window_id,
                    block_id=block_id,
                )
            token_count = estimate_tokens(text)
            text_digest = _digest_pin(("text", text), "text")
            digest = _digest_pin(
                (window_id, block_id, role, token_count, text_digest, seq),
                "block-record",
            )
            entry["blocks"][block_id] = {
                "block_id": block_id,
                "role": role,
                "token_count": token_count,
                "text_digest": text_digest,
                "seq": seq,
                "evicted": False,
            }
            self._emit(
                KIND_APPENDED,
                seq,
                window_id=window_id,
                block_id=block_id,
                role=role,
                token_count=token_count,
                text_digest=text_digest,
                estimator_version=ESTIMATOR_VERSION,
            )
            return BlockRecord(
                window_id=window_id,
                block_id=block_id,
                role=role,
                token_count=token_count,
                text_digest=text_digest,
                seq=seq,
                digest=digest,
            )

    # -- reads (pure; seq shape validated, never consumed) -------------------

    def count(self, window_id: str, seq: Any) -> CountReport:
        """Pure read view: token usage of a window against its capacity."""
        with self._lock:
            _check_seq(seq)
            window_id = _check_id(window_id, BadWindowError)
            entry = self._windows.get(window_id)
            if entry is None:
                raise UnknownWindowError(f"unknown window: {window_id!r}")
            used, live = self._usage(entry)
            capacity = entry["capacity"]
            return CountReport(
                window_id=window_id,
                used=used,
                capacity=capacity,
                remaining=capacity - used,
                over_budget=used > capacity,
                live_blocks=live,
                digest=_digest_pin(
                    (window_id, used, capacity, live), "count-report"
                ),
            )

    # -- trim (mutating decision) --------------------------------------------

    def trim(
        self,
        window_id: str,
        seq: Any,
        keep_recent: int = 0,
        pin_ids: Tuple[str, ...] = (),
    ) -> TrimReport:
        """Evict oldest-first until usage fits the budget; book the decision.

        ``pin_ids`` are never evicted; ``keep_recent`` keeps that many of the
        newest blocks regardless of budget. Refuses fail-closed when the
        protected set alone exceeds capacity.
        """
        with self._lock:
            seq = self._claim(seq)
            try:
                window_id = _check_id(window_id, BadWindowError)
                if isinstance(keep_recent, bool) or not isinstance(keep_recent, int):
                    raise BadTrimError("keep_recent must be an int")
                if keep_recent < 0:
                    raise BadTrimError("keep_recent must be >= 0")
                if isinstance(pin_ids, bool) or not isinstance(pin_ids, (tuple, list)):
                    raise BadTrimError("pin_ids must be a tuple/list of str")
                pins = tuple(_check_id(p, BadTrimError) for p in pin_ids)
            except ContextWindowError as exc:
                self._fail(seq, exc)
            entry = self._get_active(window_id, seq)
            blocks = entry["blocks"]
            live = sorted(
                (b for b in blocks.values() if not b["evicted"]),
                key=lambda b: b["seq"],
            )
            live_ids = {b["block_id"] for b in live}
            for p in pins:
                if p not in live_ids:
                    self._fail(
                        seq,
                        UnknownBlockError(f"pin names no live block: {p!r}"),
                        window_id=window_id,
                        block_id=p,
                    )
            protected = set(pins)
            if keep_recent:
                protected |= {b["block_id"] for b in live[-keep_recent:]}
            capacity = entry["capacity"]
            used = sum(b["token_count"] for b in live)
            evicted: List[str] = []
            evictable = [b for b in live if b["block_id"] not in protected]
            while used > capacity and evictable:
                victim = evictable.pop(0)
                victim["evicted"] = True
                evicted.append(victim["block_id"])
                used -= victim["token_count"]
            if used > capacity:
                # Roll back: the decision cannot be booked; restore flags.
                for b in blocks.values():
                    if b["block_id"] in evicted:
                        b["evicted"] = False
                self._fail(
                    seq,
                    TrimImpossibleError(
                        f"protected blocks use {used} tokens > capacity {capacity}"
                    ),
                    window_id=window_id,
                    protected_tokens=used,
                    capacity=capacity,
                )
            evicted_t = tuple(evicted)
            digest = _digest_pin(
                (window_id, evicted_t, used, capacity, seq), "trim-report"
            )
            self._emit(
                KIND_TRIMMED,
                seq,
                window_id=window_id,
                evicted_count=len(evicted_t),
                used_after=used,
                capacity=capacity,
                keep_recent=keep_recent,
            )
            return TrimReport(
                window_id=window_id,
                evicted_ids=evicted_t,
                used_after=used,
                capacity=capacity,
                seq=seq,
                digest=digest,
            )

    # -- views ---------------------------------------------------------------

    def window_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._windows))

    def active_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(
                sorted(w for w, e in self._windows.items() if e["state"] == _STATE_ACTIVE)
            )

    def capacity(self, window_id: str) -> int:
        with self._lock:
            entry = self._windows.get(window_id)
            if entry is None:
                raise UnknownWindowError(f"unknown window: {window_id!r}")
            return entry["capacity"]

    def block_ids(self, window_id: str) -> Tuple[str, ...]:
        with self._lock:
            entry = self._windows.get(window_id)
            if entry is None:
                raise UnknownWindowError(f"unknown window: {window_id!r}")
            return tuple(sorted(entry["blocks"]))

    def live_block_ids(self, window_id: str) -> Tuple[str, ...]:
        with self._lock:
            entry = self._windows.get(window_id)
            if entry is None:
                raise UnknownWindowError(f"unknown window: {window_id!r}")
            return tuple(sorted(b for b, v in entry["blocks"].items() if not v["evicted"]))

    def evicted_block_ids(self, window_id: str) -> Tuple[str, ...]:
        with self._lock:
            entry = self._windows.get(window_id)
            if entry is None:
                raise UnknownWindowError(f"unknown window: {window_id!r}")
            return tuple(sorted(b for b, v in entry["blocks"].items() if v["evicted"]))

    def block_record(self, window_id: str, block_id: str) -> Optional[BlockRecord]:
        with self._lock:
            entry = self._windows.get(window_id)
            if entry is None:
                return None
            b = entry["blocks"].get(block_id)
            if b is None:
                return None
            return BlockRecord(
                window_id=window_id,
                block_id=b["block_id"],
                role=b["role"],
                token_count=b["token_count"],
                text_digest=b["text_digest"],
                seq=b["seq"],
                digest=_digest_pin(
                    (
                        window_id,
                        b["block_id"],
                        b["role"],
                        b["token_count"],
                        b["text_digest"],
                        b["seq"],
                    ),
                    "block-record",
                ),
            )

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            return tuple(self._audit)


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------


def main() -> None:
    cw = ContextWindow()
    rec = cw.budget("chat", 10, 1)
    assert rec.verify()
    b1 = cw.append("chat", "sys", "system prompt here", 2, role=ROLE_SYSTEM)
    assert b1.verify()
    b2 = cw.append("chat", "m1", "x" * 40, 3)  # 10 tokens
    b3 = cw.append("chat", "m2", "y" * 40, 4)  # 10 tokens
    rep = cw.count("chat", 5)
    assert rep.verify()
    assert rep.over_budget, rep
    trim = cw.trim("chat", 6, pin_ids=("sys",))
    assert trim.verify()
    assert trim.evicted_ids == ("m1", "m2"), trim.evicted_ids
    assert trim.used_after <= 10
    assert cw.live_block_ids("chat") == ("sys",)
    cw.close("chat", 7, reason="turn-over")
    assert cw.active_ids() == ()
    try:
        cw.append("chat", "m3", "late", 8)
        raise AssertionError("append on closed window must fail")
    except RetiredWindowError:
        pass
    kinds = [e["kind"] for e in cw.audit_log()]
    assert kinds[0] == KIND_BUDGET and kinds[-2] == KIND_CLOSED
    assert all(e["schema"] == AUDIT_SCHEMA for e in cw.audit_log())
    print("context-window OK: budget, append, count, trim, close, fail-closed, audit")


if __name__ == "__main__":
    main()
