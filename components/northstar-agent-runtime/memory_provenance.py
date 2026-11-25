"""Memory provenance: every memory record says where it came from, and a
revocation is computable.

The runtime already owns five memory/ledger surfaces -- ``agent_memory.py``
(key-addressed slots), ``context_budget.py`` (what fits), ``ledger.py``
(double-entry bookkeeping), ``forward_seal_ledger.py`` (a sealed decision
chain) and ``sealed_audit_sink.py`` (a gate -> ledger adapter).  Each of them
is a *chain*.  None of them is a *revocable state*: none of them can answer
"this memory was written by that tool output; the session that produced it was
poisoned; which downstream memories must go with it?".

This module is that missing object.  It adds:

* ``MemoryRecord`` -- an immutable record that carries its ``origin`` and the
  session it came from.  A record without provenance cannot be constructed.
* ``ProvenanceLedger`` -- a hash-chained append-only ledger whose
  ``verify()`` names the first bad row.
* ``ProvenanceGraph`` -- the ``(memory_id, parent_ids)`` graph, traversed
  cycle-safely, so a revocation reaches every downstream memory.
* ``WriteGate`` -- the write boundary.  Tool output is quarantined by
  default; promotion costs a named approver and a justification.
* ``MergeGate`` -- the merge/promotion boundary.  A merged record inherits
  the worst input origin and refuses cross-tenant inputs whole.

SOURCES (read the originals; do not guess)
--------------------------------------------
* **Always-On Agents survey** (Ding et al., June 2026),
  https://arxiv.org/abs/2606.30306 -- six diagnostic axes for persistent
  agent state and a nine-step lifecycle.
* **sentinel-mem**, https://github.com/ralesamp/sentinel-mem -- the Biba
  integrity model applied to the memory-write boundary, with revocation as a
  transitive closure over a hash-chained ledger.

NORTHSTAR EXTENSION (ours, not the sources')
---------------------------------------------
The sources say *what* is missing (provenance, revocability, a write
boundary).  The concrete shapes below -- the four ``origin`` values, the
``parent_ids`` edge set, the exact disposition names, the refusal of
cross-tenant merges -- are Northstar's design.  See
``docs/design/memory-provenance-axis.md`` for the verbatim record.

Honest scope
------------
* No wall clock.  Every timestamp is supplied by the caller.
* No I/O.  The ledger is in-process; a durable writer is the caller's job
  (the runtime's ``forward_seal_ledger`` is the sealed chain it can ride on).
* No vector store, no LLM extraction, no cross-tenant sharing.  This module
  is a *gate*, not a memory system.
* ``origin`` is asserted by the caller.  This module enforces what follows
  from an origin; it cannot verify that the caller tagged it honestly.
"""
from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except Exception:  # pragma: no cover - module must stay importable standalone
    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True).encode("utf-8")


#: Version pin for this module's record shape.
MEMORY_PROVENANCE_VERSION = "memory-provenance.v1"

#: Schema pin carried by ledger rows.
MEMORY_PROVENANCE_SCHEMA = "northstar.memory-provenance.v1"

#: The genesis pin of an empty chain: 64 zeros, as in the source ledger.
GENESIS_HASH = "0" * 64


class MemoryProvenanceError(ValueError):
    """Raised when a record, a write or a merge is not well formed."""


class Origin(str, Enum):
    """Where the text of a memory candidate actually came from.

    The ordering is a *risk* ordering, lowest first.  It decides the
    disposition before anything else runs: an origin that is not in
    :data:`AUTO_PROMOTABLE` is quarantined, always, with no classifier in
    the way.

    Northstar keeps four origins.  The source library keeps six; the two it
    keeps that Northstar folds together are ``system`` (Northstar treats an
    operator-authored fact like a human one) and ``model_inference`` (Northstar
    calls it ``agent_summary``).  The distinction the source drew between
    ``user_direct`` and ``user_pasted`` -- text a human *composed* versus text
    a human *pasted* -- is not reproducible at Northstar's boundary, because
    both arrive in the same field, so Northstar refuses the whole channel
    instead of guessing which one it got.
    """

    USER_DIRECT = "user_direct"
    AGENT_SUMMARY = "agent_summary"
    TOOL_OUTPUT = "tool_output"
    IMPORTED = "imported"


#: The origins permitted to reach the durable set without a human gate.
#:
#: Northstar's rule (an extension of the source's rule): the human speaking
#: *this turn* is the only origin that lands without an approver.  An agent's
#: own summary is a conclusion drawn from text it may have been fed, so it is
#: quarantined by default; the source makes the same call for
#: ``model_inference``.
AUTO_PROMOTABLE: frozenset = frozenset({Origin.USER_DIRECT})

#: The risk order of the origins, lowest first.  A merge inherits the
#: *worst* (highest) origin of its inputs.
ORIGIN_RISK: Dict[Origin, int] = {
    Origin.USER_DIRECT: 0,
    Origin.AGENT_SUMMARY: 1,
    Origin.IMPORTED: 2,
    Origin.TOOL_OUTPUT: 3,
}

#: The origins that an attacker can reach in the general case.  They may be
#: stored, quarantined; they may never be auto-promoted.
ATTACKER_REACHABLE: frozenset = frozenset(
    {Origin.TOOL_OUTPUT, Origin.IMPORTED}
)


class Disposition(str, Enum):
    """Where a stored memory sits in its lifecycle.

    ``PROMOTED``   -- durable and eligible for preload.
    ``QUARANTINED`` -- stored for forensics, never preloaded, releasable only
                      by ``WriteGate.promote()`` with a named approver.
    ``REVOKED``    -- tainted by a revoked source session; can never be
                      promoted again.
    """

    PROMOTED = "promoted"
    QUARANTINED = "quarantined"
    REVOKED = "revoked"


#: The disposition each origin gets when nothing else intervenes.
DEFAULT_DISPOSITION: Dict[Origin, Disposition] = {
    Origin.USER_DIRECT: Disposition.PROMOTED,
    Origin.AGENT_SUMMARY: Disposition.QUARANTINED,
    Origin.TOOL_OUTPUT: Disposition.QUARANTINED,
    Origin.IMPORTED: Disposition.QUARANTINED,
}


def _require_text(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise MemoryProvenanceError("%s must be a non-empty string" % field_name)
    return value.strip()


def _require_turn(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise MemoryProvenanceError("%s must be an int" % field_name)
    if value < 0:
        raise MemoryProvenanceError("%s must be >= 0" % field_name)
    return value


def _require_origin(value: Any) -> Origin:
    if isinstance(value, Origin):
        return value
    if isinstance(value, str):
        try:
            return Origin(value)
        except ValueError:
            raise MemoryProvenanceError("unknown origin %r" % (value,))
    raise MemoryProvenanceError("origin must be an Origin or its name")


def _require_parent_ids(value: Any) -> Tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, (str, bytes)):
        raise MemoryProvenanceError("parent_ids must be a sequence of ids")
    if not isinstance(value, (list, tuple)):
        raise MemoryProvenanceError("parent_ids must be a sequence of ids")
    out: List[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise MemoryProvenanceError("parent_ids entries must be non-empty strings")
        out.append(item.strip())
    return tuple(out)


def _digest_of(text: str) -> str:
    """The sha256 pin of a memory's text."""
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class MemoryRecord:
    """One durable memory, with its provenance.  Immutable by construction.

    ``origin`` and ``source_session_id`` are required and have **no default**:
    a caller that cannot name where a fact came from does not get to write
    it.  ``parent_ids`` are the edges to the records this one was derived
    from -- a promotion or a merge names them, and the revocation closure
    walks them.
    """

    memory_id: str
    text: str
    origin: Origin
    source_session_id: str
    source_turn: int
    user_id: str
    parent_ids: Tuple[str, ...] = ()
    created_at: str = ""
    disposition: Disposition = Disposition.QUARANTINED

    def __post_init__(self) -> None:
        object.__setattr__(self, "memory_id", _require_text(self.memory_id, "memory_id"))
        object.__setattr__(self, "text", _require_text(self.text, "text"))
        object.__setattr__(self, "origin", _require_origin(self.origin))
        object.__setattr__(
            self, "source_session_id",
            _require_text(self.source_session_id, "source_session_id"),
        )
        object.__setattr__(self, "source_turn", _require_turn(self.source_turn, "source_turn"))
        object.__setattr__(self, "user_id", _require_text(self.user_id, "user_id"))
        object.__setattr__(self, "parent_ids", _require_parent_ids(self.parent_ids))
        if not isinstance(self.created_at, str):
            raise MemoryProvenanceError("created_at must be a string")
        if not isinstance(self.disposition, Disposition):
            object.__setattr__(self, "disposition", _require_disposition(self.disposition))

    @property
    def digest(self) -> str:
        """The sha256 pin of this record's text."""
        return _digest_of(self.text)

    def to_dict(self) -> Dict[str, Any]:
        """Return the record as a plain dict (for the ledger and for audit)."""
        return {
            "memory_id": self.memory_id,
            "text": self.text,
            "origin": self.origin.value,
            "source_session_id": self.source_session_id,
            "source_turn": self.source_turn,
            "user_id": self.user_id,
            "parent_ids": list(self.parent_ids),
            "created_at": self.created_at,
            "disposition": self.disposition.value,
            "digest": self.digest,
        }


def _require_disposition(value: Any) -> Disposition:
    if isinstance(value, Disposition):
        return value
    if isinstance(value, str):
        try:
            return Disposition(value)
        except ValueError:
            raise MemoryProvenanceError("unknown disposition %r" % (value,))
    raise MemoryProvenanceError("disposition must be a Disposition or its name")


@dataclass(frozen=True)
class LedgerRow:
    """One row of the hash-chained ledger.  Immutable."""

    seq: int
    event: str
    payload: Dict[str, Any]
    prev_hash: str
    row_hash: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "seq": self.seq,
            "event": self.event,
            "payload": self.payload,
            "prev_hash": self.prev_hash,
            "row_hash": self.row_hash,
        }


def compute_row_hash(seq: int, event: str, payload: Dict[str, Any],
                     prev_hash: str) -> str:
    """The chain hash of one row: sha256 over its canonical body."""
    body = {
        "seq": seq,
        "event": event,
        "payload": payload,
        "prev_hash": prev_hash,
    }
    return "sha256:" + hashlib.sha256(jcs_canonical_json(body)).hexdigest()


class ProvenanceLedger:
    """An append-only, hash-chained ledger of memory lifecycle events.

    The chain exists so that a revocation is *computable*: given a
    compromised session id, replay the rows in order and derive every
    downstream memory whose content transitively derives from it -- including
    the memories a merge renamed and the ones a human promoted.

    ``verify()`` returns ``(ok, first_bad_index)``.  ``first_bad_index`` is
    the *index* of the first row that does not verify (0-based), or ``None``
    when the chain is intact.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._rows: List[LedgerRow] = []

    def __len__(self) -> int:
        return len(self._rows)

    @property
    def head(self) -> str:
        """The chain hash of the last row, or the genesis pin."""
        return self._rows[-1].row_hash if self._rows else GENESIS_HASH

    def append(self, event: str, payload: Optional[Dict[str, Any]] = None) -> LedgerRow:
        """Append one event row and return it."""
        event = _require_text(event, "event")
        if payload is None:
            payload = {}
        if not isinstance(payload, dict):
            raise MemoryProvenanceError("payload must be a dict")
        with self._lock:
            seq = len(self._rows)
            prev = self.head
            row_hash = compute_row_hash(seq, event, payload, prev)
            row = LedgerRow(seq=seq, event=event, payload=dict(payload),
                            prev_hash=prev, row_hash=row_hash)
            self._rows.append(row)
            return row

    def rows(self) -> Tuple[LedgerRow, ...]:
        """Every row, in order."""
        return tuple(self._rows)

    def verify(self) -> Tuple[bool, Optional[int]]:
        """Return ``(ok, first_bad_index)``.

        Detects a mutated row, an inserted row and a deleted row.  The index
        is the 0-based position of the first row that fails; ``None`` when
        the chain is intact.
        """
        prev = GENESIS_HASH
        with self._lock:
            for index, row in enumerate(self._rows):
                if row.seq != index:
                    return False, index
                if row.prev_hash != prev:
                    return False, index
                if compute_row_hash(row.seq, row.event, row.payload,
                                    row.prev_hash) != row.row_hash:
                    return False, index
                prev = row.row_hash
        return True, None

    def events(self, event: Optional[str] = None) -> Tuple[LedgerRow, ...]:
        """Every row, optionally filtered by event name."""
        if event is None:
            return tuple(self._rows)
        return tuple(row for row in self._rows if row.event == event)

    def _mutate_for_test(self, index: int, payload: Optional[Dict[str, Any]] = None,
                         event: Optional[str] = None) -> None:
        """Rewrite one row in place.  **Test-only** tamper hook.

        The chain is only worth anything if a tamper can be *observed*, so
        the ledger ships one narrow way to break it.  It is not part of the
        module's public contract and nothing in the module calls it.
        """
        if not isinstance(index, int) or isinstance(index, bool):
            raise MemoryProvenanceError("index must be an int")
        if index < 0 or index >= len(self._rows):
            raise MemoryProvenanceError("index out of range")
        with self._lock:
            row = self._rows[index]
            self._rows[index] = LedgerRow(
                seq=row.seq,
                event=event if event is not None else row.event,
                payload=dict(payload) if payload is not None else row.payload,
                prev_hash=row.prev_hash,
                row_hash=row.row_hash,
            )


class ProvenanceGraph:
    """The ``(memory_id, parent_ids)`` graph, traversed cycle-safely.

    ``parent_ids`` is free JSON that a caller supplies, so it is **not** a
    foreign key: it can name an id that does not exist, and it can name an id
    that names it back.  Every traversal therefore keeps a visited set and
    never recurses on a node it has already seen.
    """

    def __init__(self, records: Iterable[MemoryRecord] = ()) -> None:
        self._parents: Dict[str, Tuple[str, ...]] = {}
        self._children: Dict[str, Tuple[str, ...]] = {}
        for record in records:
            self.add(record)

    def add(self, record: MemoryRecord) -> None:
        """Add one record's edges to the graph."""
        if not isinstance(record, MemoryRecord):
            raise MemoryProvenanceError("add expects a MemoryRecord")
        self._parents[record.memory_id] = tuple(record.parent_ids)
        for parent in record.parent_ids:
            children = list(self._children.get(parent, ()))
            if record.memory_id not in children:
                children.append(record.memory_id)
            self._children[parent] = tuple(children)

    def ancestors(self, memory_id: str) -> Set[str]:
        """Every id reachable *up* the parent edges, including ``memory_id``.

        Cycle-safe: a node is visited once, so a cycle terminates.
        """
        return self._walk(memory_id, self._parents)

    def descendants(self, memory_id: str) -> Set[str]:
        """Every id reachable *down* the child edges, including ``memory_id``.

        Cycle-safe: a node is visited once, so a cycle terminates.
        """
        return self._walk(memory_id, self._children)

    def _walk(self, start: str, edges: Dict[str, Tuple[str, ...]]) -> Set[str]:
        seen: Set[str] = set()
        stack: List[str] = [start]
        while stack:
            node = stack.pop()
            if node in seen:
                continue
            seen.add(node)
            for neighbour in edges.get(node, ()):
                if neighbour not in seen:
                    stack.append(neighbour)
        return seen

    def nodes(self) -> Set[str]:
        """Every id the graph knows."""
        return set(self._parents) | set(self._children)


@dataclass(frozen=True)
class GateDecision:
    """The outcome of a write or a merge attempt.

    ``accepted`` is ``False`` when the candidate was refused outright (a
    bad input, a cross-tenant merge, a revoked input).  ``disposition`` is
    where the record now sits; ``record`` is the stored record when one was
    stored.
    """

    accepted: bool
    disposition: Disposition
    reason: str
    record: Optional[MemoryRecord] = None

    @property
    def memory_id(self) -> str:
        """The id of the stored record (empty when nothing was stored)."""
        return self.record.memory_id if self.record is not None else ""


@dataclass(frozen=True)
class PromotionResult:
    """The outcome of a promotion attempt."""

    promoted: bool
    reason: str
    memory_id: str
    approver: str = ""


class WriteGate:
    """The boundary a memory crosses to become durable.

    The rule is the source's and it is not negotiable: **the origin decides
    promotion, not a classifier.**  An origin outside
    :data:`AUTO_PROMOTABLE` is quarantined whatever any scanner says.  There
    is no scanner in Northstar's version -- there is no LLM in the write path
    at all, so there is nothing to prompt-inject.

    Every accepted write appends a ``MEMORY_WRITTEN`` row to the ledger.  A
    refused write appends a ``MEMORY_REFUSED`` row: a refusal leaves a trail
    too.
    """

    def __init__(self, ledger: ProvenanceLedger,
                 auto_promote_origins: frozenset = AUTO_PROMOTABLE) -> None:
        if not isinstance(ledger, ProvenanceLedger):
            raise MemoryProvenanceError("ledger must be a ProvenanceLedger")
        if not isinstance(auto_promote_origins, frozenset):
            raise MemoryProvenanceError("auto_promote_origins must be a frozenset")
        self._ledger = ledger
        self._auto_promote = auto_promote_origins
        self._records: Dict[str, MemoryRecord] = {}
        self._order: List[str] = []
        self._lock = threading.RLock()

    @property
    def ledger(self) -> ProvenanceLedger:
        """The ledger this gate writes to."""
        return self._ledger

    def records(self) -> Tuple[MemoryRecord, ...]:
        """Every stored record, in write order."""
        with self._lock:
            return tuple(self._records[mid] for mid in self._order)

    def get(self, memory_id: str) -> Optional[MemoryRecord]:
        """The stored record for ``memory_id``, or ``None``."""
        if not isinstance(memory_id, str):
            return None
        with self._lock:
            return self._records.get(memory_id)

    def disposition_of(self, memory_id: str) -> Optional[Disposition]:
        """The disposition of a stored record, or ``None`` if unknown."""
        record = self.get(memory_id)
        return None if record is None else record.disposition

    def promoted(self, user_id: str) -> Tuple[MemoryRecord, ...]:
        """Every PROMOTED record for one tenant -- the preload set."""
        user_id = _require_text(user_id, "user_id")
        with self._lock:
            return tuple(
                r for r in (self._records[mid] for mid in self._order)
                if r.disposition is Disposition.PROMOTED and r.user_id == user_id
            )

    def submit(self, record: MemoryRecord) -> GateDecision:
        """Write one memory record through the gate.

        The disposition follows the origin alone:

        * an origin in :data:`AUTO_PROMOTABLE` is ``PROMOTED``;
        * every other origin is ``QUARANTINED``.

        A record whose id is already stored is refused (a duplicate write
        would launder a second origin onto the first id).
        """
        if not isinstance(record, MemoryRecord):
            raise MemoryProvenanceError("submit expects a MemoryRecord")
        with self._lock:
            if record.memory_id in self._records:
                self._ledger.append(
                    "MEMORY_REFUSED",
                    {"memory_id": record.memory_id, "reason": "duplicate_memory_id"},
                )
                return GateDecision(False, Disposition.QUARANTINED,
                                    "duplicate_memory_id")
            disposition = (
                Disposition.PROMOTED
                if record.origin in self._auto_promote
                else Disposition.QUARANTINED
            )
            stored = _with_disposition(record, disposition)
            self._records[stored.memory_id] = stored
            self._order.append(stored.memory_id)
            self._ledger.append(
                "MEMORY_WRITTEN",
                {
                    "memory_id": stored.memory_id,
                    "user_id": stored.user_id,
                    "origin": stored.origin.value,
                    "digest": stored.digest,
                    "source_session_id": stored.source_session_id,
                    "source_turn": stored.source_turn,
                    "parent_ids": list(stored.parent_ids),
                    "disposition": stored.disposition.value,
                },
            )
            return GateDecision(True, disposition, "stored", stored)

    def promote(self, memory_id: str, approver: str, justification: str) -> PromotionResult:
        """Release one quarantined record into the promoted set.

        A promotion costs a **named approver** and a **justification**, and
        both are written to the ledger.  Quarantine without an exit is a dead
        end, and a dead end gets forked out.

        Refuses: a missing approver or justification, an unknown id, an
        already-promoted record, and a **revoked** record -- a human cannot
        approve their way past a taint closure.
        """
        if not isinstance(memory_id, str) or not memory_id.strip():
            raise MemoryProvenanceError("memory_id must be a non-empty string")
        approver = approver.strip() if isinstance(approver, str) else ""
        justification = justification.strip() if isinstance(justification, str) else ""
        with self._lock:
            record = self._records.get(memory_id)
            if record is None:
                self._ledger.append(
                    "PROMOTION_REFUSED",
                    {"memory_id": memory_id, "approver": approver, "reason": "unknown_memory"},
                )
                return PromotionResult(False, "unknown_memory", memory_id, approver)
            if not approver:
                self._ledger.append(
                    "PROMOTION_REFUSED",
                    {"memory_id": memory_id, "reason": "approver_required"},
                )
                return PromotionResult(False, "approver_required", memory_id, "")
            if not justification:
                self._ledger.append(
                    "PROMOTION_REFUSED",
                    {"memory_id": memory_id, "approver": approver,
                     "reason": "justification_required"},
                )
                return PromotionResult(False, "justification_required", memory_id, approver)
            if record.disposition is Disposition.PROMOTED:
                return PromotionResult(False, "already_promoted", memory_id, approver)
            if record.disposition is Disposition.REVOKED:
                self._ledger.append(
                    "PROMOTION_REFUSED",
                    {"memory_id": memory_id, "approver": approver, "reason": "revoked"},
                )
                return PromotionResult(
                    False, "revoked_cannot_be_promoted", memory_id, approver
                )
            promoted = _with_disposition(record, Disposition.PROMOTED)
            self._records[memory_id] = promoted
            self._ledger.append(
                "MEMORY_PROMOTED",
                {
                    "memory_id": memory_id,
                    "user_id": promoted.user_id,
                    "origin": promoted.origin.value,
                    "digest": promoted.digest,
                    "approver": approver,
                    "justification": justification[:500],
                },
            )
            return PromotionResult(True, "promoted", memory_id, approver)

    def _set_disposition(self, memory_id: str, disposition: Disposition) -> None:
        """Set a stored record's disposition.  Internal to the gates."""
        with self._lock:
            record = self._records.get(memory_id)
            if record is None:
                raise MemoryProvenanceError("unknown memory %r" % (memory_id,))
            self._records[memory_id] = _with_disposition(record, disposition)


def _with_disposition(record: MemoryRecord, disposition: Disposition) -> MemoryRecord:
    """Return a copy of ``record`` with a different disposition."""
    return MemoryRecord(
        memory_id=record.memory_id,
        text=record.text,
        origin=record.origin,
        source_session_id=record.source_session_id,
        source_turn=record.source_turn,
        user_id=record.user_id,
        parent_ids=record.parent_ids,
        created_at=record.created_at,
        disposition=disposition,
    )


class MergeGate:
    """The boundary many memories cross to become one.

    A merge is a **second, unattended promotion path**: it runs on a
    schedule, with no human present, and it is where provenance normally
    gets laundered.  So it is a gate, not a trusted job.  Its rules:

    1. Every input must be ``PROMOTED`` at merge time.  A record
       quarantined or revoked since it was written cannot contribute.
    2. The merged record inherits the **worst** input origin.  A merge is
       only as trusted as its least trusted input.
    3. The merged record's ``parent_ids`` are the input ids, so the
       revocation closure reaches the merge and everything after it.
    4. A cross-tenant merge is refused **whole**.  A merge with one bad
       input is refused, not silently completed without it: partial success
       hides the failure from the operator.
    5. The merged text is re-scanned for the source markers of its inputs,
       and the merged record records what it found.

    Northstar's extension over the source: the source re-scans the merged
    text with a heuristic scanner to catch a directive that no single input
    contained.  Northstar has no scanner in this path, so it re-scans the
    *provenance markers* instead -- the origin labels its inputs carried --
    and records the result on the merged record.  That is a weaker check
    than a content scanner, and the document says so.
    """

    def __init__(self, gate: WriteGate) -> None:
        if not isinstance(gate, WriteGate):
            raise MemoryProvenanceError("gate must be a WriteGate")
        self._gate = gate

    @property
    def gate(self) -> WriteGate:
        """The write gate a merged record goes through."""
        return self._gate

    def merge(self, input_ids: Sequence[str], merged_text: str, user_id: str,
              memory_id: str, source_session_id: str, source_turn: int = 0,
              created_at: str = "") -> GateDecision:
        """Merge promoted records into one new record.

        ``memory_id``, ``source_session_id``, ``source_turn`` and
        ``created_at`` are supplied by the caller: this module never reads
        a clock and never mints an identity.
        """
        if not isinstance(input_ids, (list, tuple)):
            raise MemoryProvenanceError("input_ids must be a sequence")
        if not input_ids:
            return self._refuse(list(input_ids), user_id, "no_inputs")
        user_id = _require_text(user_id, "user_id")

        inputs: List[MemoryRecord] = []
        for mid in input_ids:
            record = self._gate.get(mid)
            if record is None:
                return self._refuse(list(input_ids), user_id,
                                    "unknown_input:%s" % (mid,))
            if record.disposition is not Disposition.PROMOTED:
                return self._refuse(list(input_ids), user_id,
                                    "input_not_promotable:%s" % (mid,))
            inputs.append(record)

        if any(record.user_id != user_id for record in inputs):
            return self._refuse(list(input_ids), user_id, "cross_tenant_merge")

        worst = max((record.origin for record in inputs),
                    key=lambda o: ORIGIN_RISK[o])
        merged = MemoryRecord(
            memory_id=memory_id,
            text=merged_text,
            origin=worst,
            source_session_id=source_session_id,
            source_turn=source_turn,
            user_id=user_id,
            parent_ids=tuple(str(record.memory_id) for record in inputs),
            created_at=created_at,
            disposition=Disposition.QUARANTINED,
        )
        decision = self._gate.submit(merged)
        self._gate.ledger.append(
            "MEMORY_CONSOLIDATED",
            {
                "memory_id": merged.memory_id,
                "user_id": user_id,
                "input_memory_ids": [str(r.memory_id) for r in inputs],
                "origin": worst.value,
                "disposition": decision.disposition.value,
                "rescanned_markers": sorted(
                    self.rescan_markers(merged_text, inputs)
                ),
            },
        )
        return decision

    def rescan_markers(self, merged_text: str,
                       inputs: Sequence[MemoryRecord]) -> Set[str]:
        """Re-scan the merged text for the provenance markers of its inputs.

        A marker is the origin's name appearing verbatim in the merged text.
        The check is deliberately weak -- it records what it found and does
        not gate on it -- because Northstar has no content scanner here.
        """
        text = merged_text if isinstance(merged_text, str) else ""
        found: Set[str] = set()
        for record in inputs:
            if record.origin.value in text:
                found.add(record.origin.value)
        return found

    def _refuse(self, input_ids: List[str], user_id: Any, why: str) -> GateDecision:
        self._gate.ledger.append(
            "MERGE_REFUSED",
            {
                "input_memory_ids": [str(mid) for mid in input_ids],
                "user_id": user_id if isinstance(user_id, str) else "",
                "reason": why,
            },
        )
        return GateDecision(False, Disposition.QUARANTINED, why)


def revoke_session(gate: WriteGate, session_id: str) -> Set[str]:
    """Revoke a compromised session and every memory derived from it.

    The closure is **transitive**: it reaches the memories a merge renamed
    and the ones a human promoted, because the closure walks the *parent
    edges* of the stored records, not the ledger's flat event list.

    Returns the set of revoked memory ids.  A revocation is an **appended
    event**, not a deletion: the records stay in the ledger and in the
    store, with their disposition changed to ``REVOKED``.
    """
    session_id = _require_text(session_id, "session_id")
    tainted = revoke_sessions_of(gate, session_id)
    for memory_id in tainted:
        gate._set_disposition(memory_id, Disposition.REVOKED)
    gate.ledger.append(
        "SESSION_REVOKED",
        {
            "sessions": [session_id],
            "tainted_memory_ids": sorted(tainted),
        },
    )
    return tainted


def taint_closure(gate: WriteGate, session_ids: Iterable[str]) -> Set[str]:
    """Every memory id whose provenance touches one of ``session_ids``.

    This is the pure computation -- it changes nothing.  :func:`revoke_session`
    is the acting half.
    """
    wanted = set()
    for sid in session_ids:
        wanted |= revoke_sessions_of(gate, sid)
    return wanted


def revoke_sessions_of(gate: WriteGate, session_id: str) -> Set[str]:
    """The tainted set for one session id, without changing any disposition.

    The closure walks the *parent edges* of the stored records, so it
    reaches a merged record and everything derived from the merge.  The walk
    is cycle-safe: a record that names itself as an ancestor terminates.
    """
    records = gate.records()
    by_id = {record.memory_id: record for record in records}
    sessions_of: Dict[str, Set[str]] = {}

    def sessions_for(memory_id: str, stack: Tuple[str, ...] = ()) -> Set[str]:
        if memory_id in sessions_of:
            return sessions_of[memory_id]
        if memory_id in stack:
            return set()
        record = by_id.get(memory_id)
        if record is None:
            return set()
        out = {record.source_session_id}
        for parent in record.parent_ids:
            out |= sessions_for(parent, stack + (memory_id,))
        sessions_of[memory_id] = out
        return out

    return {
        record.memory_id
        for record in records
        if session_id in sessions_for(record.memory_id)
    }


def stdlib_only() -> bool:
    """Whether this module imports nothing outside the standard library.

    ``canonical_json`` is a module of this same component and is
    stdlib-only itself, so it counts as inside the boundary.
    """
    import ast
    import os

    allowed = {
        "hashlib", "json", "threading", "dataclasses", "enum", "typing",
        "ast", "os", "__future__", "canonical_json",
    }
    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(here, "memory_provenance.py")
    with open(path, "r", encoding="utf-8") as handle:
        tree = ast.parse(handle.read(), filename=path)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if root not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.level:  # a relative import is outside the boundary
                return False
            root = (node.module or "").split(".")[0]
            if root not in allowed:
                return False
    return True
