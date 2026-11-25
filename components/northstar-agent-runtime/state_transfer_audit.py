"""State-transfer auditing: the failures happen *between* the boxes.

The runtime already records **actions** (``sealed_audit_sink`` seals every
tool call and every permission decision) and it already records **evidence**
(``forward_seal_ledger`` keeps a forward hash chain over sealed records).
What it does not record is the thing that crosses a boundary: state moving
between the working context, the session history, persistent memory and the
external environment.

The source of this slice says that is exactly where the failures live.  Its
abstract (arXiv 2611.23346) states, **verbatim**:

    "While conventional execution traces log model prompts and tool calls,
     critical security and reliability failures occur during state transfers"

and names the three shapes of failure, **verbatim**:

    "a transfer can admit unchecked content (indirect prompt injections,
     unverified memory writes), rewrite state lossily (context compaction
     dropping user constraints, memory consolidation stripping source
     authority), or restore state incompletely (workspace rollbacks leaving
     aborted KV state active on the inference server)."

and the consequence, **verbatim**:

    "Because current traces omit what crosses these boundaries, failure
     attribution and runtime monitors fail on multi-step trajectories."

This module is the Northstar answer to that gap, and it is deliberately
small.  It does four things:

* ``TransferKind`` -- the four enumerable state-transfer kinds.
* ``TransferEvent`` -- an immutable event that answers the three questions
  the invariant demands: *what moved* (``payload_digest``), *where it came
  from* (``source_event_id``), and *who approved it* (``approved_by``).
* ``evaluate`` / ``classify`` -- the rule table.  An event that cannot
  answer all three questions is ``unverified``, with a **reason code**
  naming exactly what was missing.
* ``TransferAuditor`` -- a forward hash chain over the events, so "who
  brought this unverified state in" is answerable offline.

and one enforcement point:

* ``assert_verified`` -- raises on an ``unverified`` event.  A marker is
  not a control; this is the control.

NORTHSTAR EXTENSION (ours, not the sources')
--------------------------------------------
The sources say *what* is missing (an audit point at every transfer, a
hash-chained record, a binding between context/memory/cache state and
external actions).  The following are Northstar's own design and are NOT
claimed by the source:

* the **four** kinds (``context_write``, ``context_compact``, ``memory_write``,
  ``workspace_restore``).  The source enumerates eight transfer classes
  (observation, context assembly, compaction, memory write, consolidation,
  action, rollback, delegation); Northstar collapses them onto the four
  *state* boundaries this runtime actually owns, because this runtime has
  no inference-server KV cache to bind and no delegation transfer of its own.
* the **three-question invariant** (digest + provenance + approval).
* the **reason codes** and their precedence.
* the rule that **approval is required for the two durable boundaries**
  (``memory_write``, ``workspace_restore``) and not for the two
  in-context ones.
* the rule that a compaction event must **declare** the user constraints it
  dropped, and a restore event must **declare** whether aborted in-flight
  state survived.

See ``docs/design/state-transfer-audit.md`` for the verbatim record and the
full derivation.

HONEST SCOPE
------------
* No wall clock.  ``occurred_at`` is supplied by the caller.
* No I/O.  The chain is in-process; a durable writer is the caller's job.
* No vector store, no LLM scoring, no cross-system tracing.  This is a
  *classifier and a chain*, not a memory system and not a monitor.
* The auditor does not decide whether a digest is *honest*.  It decides
  whether the event says enough to be checked later.
"""
from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except Exception:  # pragma: no cover - module must stay importable standalone
    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True).encode("utf-8")


#: Version pin for this module's record shape.
STATE_TRANSFER_AUDIT_VERSION = "state-transfer-audit.v1"

#: Schema pin carried by the chain's rows.
STATE_TRANSFER_AUDIT_SCHEMA = "northstar.state-transfer-audit.v1"

#: The genesis pin of an empty chain: 64 zeros, as in the sibling ledger.
GENESIS_HASH = "0" * 64

#: The module's public surface.  Every name here is named by at least one
#: test in ``tests/test_state_transfer_audit.py``.
__all__ = (
    "GENESIS_HASH",
    "POLICIES",
    "REASON_CODES",
    "REASON_MISPLACED_FIELD",
    "REASON_MISSING_APPROVAL",
    "REASON_MISSING_PROVENANCE",
    "REASON_OK",
    "REASON_RESIDUAL_IN_FLIGHT",
    "REASON_UNDECLARED_DROPPED_CONSTRAINTS",
    "REASON_UNDECLARED_RESIDUAL",
    "STATE_TRANSFER_AUDIT_SCHEMA",
    "STATE_TRANSFER_AUDIT_VERSION",
    "StateTransferAuditError",
    "TransferAuditor",
    "TransferEvent",
    "TransferKind",
    "TransferPolicy",
    "TransferRow",
    "UnverifiedTransferError",
    "Verdict",
    "assert_verified",
    "classify",
    "compute_row_hash",
    "evaluate",
    "stdlib_only",
)


class StateTransferAuditError(ValueError):
    """Raised when an event, a verdict or a rule is not well formed."""


class UnverifiedTransferError(StateTransferAuditError):
    """Raised by :func:`assert_verified` when an event is not verified.

    This is the execution point for "an unverified event must not be treated
    as verified downstream".  It subclasses
    :class:`StateTransferAuditError` so a caller that only catches the
    module's own errors still catches it.
    """


class TransferKind(str, Enum):
    """The four enumerable state-transfer kinds.

    * ``CONTEXT_WRITE`` -- external content enters the working context.
    * ``CONTEXT_COMPACT`` -- the working context is compacted into a
      summary; older turns move to session history.
    * ``MEMORY_WRITE`` -- content is written into persistent memory.
    * ``WORKSPACE_RESTORE`` -- the workspace is restored or rolled back.
    """

    CONTEXT_WRITE = "context_write"
    CONTEXT_COMPACT = "context_compact"
    MEMORY_WRITE = "memory_write"
    WORKSPACE_RESTORE = "workspace_restore"


#: The reason codes.  ``REASON_OK`` is the only code a verified event
#: carries; every other code names exactly what was missing.
REASON_OK = "ok"
REASON_MISSING_PROVENANCE = "missing_provenance"
REASON_MISSING_APPROVAL = "missing_approval"
REASON_UNDECLARED_DROPPED_CONSTRAINTS = "undeclared_dropped_constraints"
REASON_UNDECLARED_RESIDUAL = "undeclared_residual"
REASON_RESIDUAL_IN_FLIGHT = "residual_in_flight"
REASON_MISPLACED_FIELD = "misplaced_field"

#: Every reason code, in one tuple, so a caller can enumerate them.
REASON_CODES: Tuple[str, ...] = (
    REASON_OK,
    REASON_MISSING_PROVENANCE,
    REASON_MISSING_APPROVAL,
    REASON_UNDECLARED_DROPPED_CONSTRAINTS,
    REASON_UNDECLARED_RESIDUAL,
    REASON_RESIDUAL_IN_FLIGHT,
    REASON_MISPLACED_FIELD,
)


@dataclass(frozen=True)
class TransferPolicy:
    """The per-kind rule row: what this kind must declare to be verified."""

    kind: TransferKind
    requires_approval: bool
    requires_dropped_constraints: bool
    requires_residual_declaration: bool
    description: str


#: The rule table.  **Northstar extension** -- see the module docstring.
POLICIES: Dict[TransferKind, TransferPolicy] = {
    TransferKind.CONTEXT_WRITE: TransferPolicy(
        kind=TransferKind.CONTEXT_WRITE,
        requires_approval=False,
        requires_dropped_constraints=False,
        requires_residual_declaration=False,
        description=(
            "External content enters the working context.  Provenance is "
            "required: the source event id says which tool result or user "
            "turn is being admitted.  Approval is not required -- the "
            "content stays inside the current context, and the context's own "
            "sanitizer is the gate there."
        ),
    ),
    TransferKind.CONTEXT_COMPACT: TransferPolicy(
        kind=TransferKind.CONTEXT_COMPACT,
        requires_approval=False,
        requires_dropped_constraints=True,
        requires_residual_declaration=False,
        description=(
            "The working context is compacted into a summary and older turns "
            "move to session history.  Provenance is required, and the event "
            "must DECLARE the user constraints it dropped -- 'context "
            "compaction dropping user constraints' is the source's named "
            "lossy-rewrite failure, so a silent drop is the failure itself. "
            "An empty declaration ('I dropped nothing') is a declaration; "
            "an absent one is not."
        ),
    ),
    TransferKind.MEMORY_WRITE: TransferPolicy(
        kind=TransferKind.MEMORY_WRITE,
        requires_approval=True,
        requires_dropped_constraints=False,
        requires_residual_declaration=False,
        description=(
            "Content is written into persistent memory, where it outlives "
            "the turn.  Provenance is required and an approval is required: "
            "the sibling memory-provenance slice quarantines tool output "
            "and charges a named approver for promotion, and a memory write "
            "is that same boundary."
        ),
    ),
    TransferKind.WORKSPACE_RESTORE: TransferPolicy(
        kind=TransferKind.WORKSPACE_RESTORE,
        requires_approval=True,
        requires_dropped_constraints=False,
        requires_residual_declaration=True,
        description=(
            "The workspace is restored or rolled back.  Provenance is "
            "required, an approval is required (the world changes), and "
            "the event must declare whether aborted in-flight state "
            "survived the restore -- the source names 'workspace rollbacks "
            "leaving aborted KV state active on the inference server' as a "
            "failure of this boundary."
        ),
    ),
}


def _require_text(value: Any, field_name: str) -> str:
    """A non-blank string, or a refusal."""
    if not isinstance(value, str):
        raise StateTransferAuditError("%s must be a string" % field_name)
    if not value.strip():
        raise StateTransferAuditError("%s must not be blank" % field_name)
    return value


def _require_digest(value: Any, field_name: str = "payload_digest") -> str:
    """A ``sha256:``-prefixed digest pin, or a refusal.

    The pin is checked for *shape* only.  This module cannot know whether
    the digest matches the bytes it describes; it can only refuse a digest
    that could not be checked later.
    """
    if not isinstance(value, str):
        raise StateTransferAuditError("%s must be a string" % field_name)
    text = value.strip()
    if not text:
        raise StateTransferAuditError("%s must not be blank" % field_name)
    lowered = text.lower()
    if not (lowered.startswith("sha256:") or lowered.startswith("sha256-")):
        raise StateTransferAuditError(
            "%s must be a sha256 pin of the form 'sha256:<64 hex chars>', got %r"
            % (field_name, value)
        )
    hex_part = text.split(":", 1)[1].replace("-", "")
    if len(hex_part) != 64 or any(c not in "0123456789abcdefABCDEF" for c in hex_part):
        raise StateTransferAuditError(
            "%s must carry 64 hex characters after the pin prefix" % field_name
        )
    return "sha256:" + hex_part.lower()


def _require_kind(value: Any) -> TransferKind:
    """A :class:`TransferKind`, or its name, or a refusal."""
    if isinstance(value, TransferKind):
        return value
    if isinstance(value, str):
        try:
            return TransferKind(value)
        except ValueError:
            raise StateTransferAuditError(
                "unknown transfer kind %r; the kinds are %s"
                % (value, ", ".join(k.value for k in TransferKind))
            )
    raise StateTransferAuditError("kind must be a TransferKind or its name")


def _require_optional_text(value: Any, field_name: str) -> Optional[str]:
    """``None`` or a non-blank string."""
    if value is None:
        return None
    return _require_text(value, field_name)


def _require_optional_tuple(value: Any, field_name: str) -> Optional[Tuple[str, ...]]:
    """``None`` or a tuple of non-blank strings.

    ``None`` is *absent* and ``()`` is *declared empty*.  The difference is
    the whole point of the compaction rule, so the two are kept distinct.
    """
    if value is None:
        return None
    if isinstance(value, (str, bytes)) or not isinstance(value, (list, tuple)):
        raise StateTransferAuditError(
            "%s must be a tuple of strings or None" % field_name
        )
    items = tuple(value)
    for item in items:
        _require_text(item, "%s entry" % field_name)
    return items


@dataclass(frozen=True)
class TransferEvent:
    """One state transfer, recorded.  Immutable by construction.

    The three questions the invariant asks, as three fields:

    * ``payload_digest`` -- **what moved**.  A ``sha256:`` pin of the
      bytes that crossed.
    * ``source_event_id`` -- **where it came from**.  The id of the event
      (or user turn, or tool call) the content was taken from.  ``None``
      means "I will not say", and that is never verified.
    * ``approved_by`` -- **who approved it**.  ``None`` is allowed for the
      kinds that do not require approval.

    Two kind-specific fields:

    * ``dropped_constraints`` -- **only** meaningful for ``CONTEXT_COMPACT``.
      The user constraints the compaction discarded.  ``None`` means *not
      declared*; ``()`` means *declared: none dropped*.  The distinction
      is the invariant, so it is preserved exactly.
    * ``residual_in_flight`` -- **only** meaningful for
      ``WORKSPACE_RESTORE``.  Whether aborted in-flight state survived the
      restore.  ``None`` means *not declared*.

    ``verified`` is **derived**, never supplied: it is computed by
    :func:`evaluate` from the rule table, so an event cannot be
    constructed already-verified by accident.
    """

    event_id: str
    kind: TransferKind
    payload_digest: str
    source_event_id: Optional[str] = None
    approved_by: Optional[str] = None
    dropped_constraints: Optional[Tuple[str, ...]] = None
    residual_in_flight: Optional[bool] = None
    occurred_at: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "event_id", _require_text(self.event_id, "event_id"))
        object.__setattr__(self, "kind", _require_kind(self.kind))
        object.__setattr__(
            self, "payload_digest", _require_digest(self.payload_digest)
        )
        object.__setattr__(
            self, "source_event_id",
            _require_optional_text(self.source_event_id, "source_event_id"),
        )
        object.__setattr__(
            self, "approved_by",
            _require_optional_text(self.approved_by, "approved_by"),
        )
        object.__setattr__(
            self, "dropped_constraints",
            _require_optional_tuple(self.dropped_constraints, "dropped_constraints"),
        )
        if self.residual_in_flight is not None and not isinstance(
            self.residual_in_flight, bool
        ):
            raise StateTransferAuditError("residual_in_flight must be a bool or None")
        if not isinstance(self.occurred_at, str):
            raise StateTransferAuditError("occurred_at must be a string")

    @property
    def verified(self) -> bool:
        """Whether this event satisfies the invariant.  Derived, not stored."""
        return evaluate(self).verified

    @property
    def reason(self) -> str:
        """The reason code for this event's verdict.  Derived, not stored."""
        return evaluate(self).reason

    def to_dict(self) -> Dict[str, Any]:
        """Return the event as a plain dict (for the chain and for audit)."""
        return {
            "event_id": self.event_id,
            "kind": self.kind.value,
            "payload_digest": self.payload_digest,
            "source_event_id": self.source_event_id,
            "approved_by": self.approved_by,
            "dropped_constraints": (
                None if self.dropped_constraints is None
                else list(self.dropped_constraints)
            ),
            "residual_in_flight": self.residual_in_flight,
            "occurred_at": self.occurred_at,
        }


@dataclass(frozen=True)
class Verdict:
    """The outcome of evaluating one event."""

    verified: bool
    reason: str
    kind: TransferKind

    def __post_init__(self) -> None:
        if self.reason not in REASON_CODES:
            raise StateTransferAuditError(
                "unknown reason code %r; the codes are %s"
                % (self.reason, ", ".join(REASON_CODES))
            )
        if self.verified != (self.reason == REASON_OK):
            raise StateTransferAuditError(
                "a verdict is verified exactly when its reason is %r" % REASON_OK
            )


def evaluate(event: TransferEvent) -> Verdict:
    """Apply the rule table to one event and return its :class:`Verdict`.

    The rules, in the order they are checked:

    1. **Provenance.**  ``source_event_id`` must be present.  A transfer
       that will not say where it came from is not verifiable, whatever
       else it says.
    2. **Approval.**  For the kinds whose policy says ``requires_approval``,
       ``approved_by`` must be present.
    3. **Declared drop.**  For ``CONTEXT_COMPACT``,
       ``dropped_constraints`` must be present -- an empty tuple is a
       declaration, ``None`` is not.
    4. **Declared residual.**  For ``WORKSPACE_RESTORE``,
       ``residual_in_flight`` must be present.
    5. **Residual state.**  For ``WORKSPACE_RESTORE``, a declared
       ``residual_in_flight=True`` is itself a failure: the aborted
       in-flight state survived the restore, which is the source's named
       "restore state incompletely" failure.
    6. **Misplaced field.**  A kind-specific field set on a kind that does
       not use it is refused, because a field that means nothing here is a
       field that will be read as if it meant something.

    The first failing rule wins, and its code names what was missing.
    """
    if not isinstance(event, TransferEvent):
        raise StateTransferAuditError("evaluate expects a TransferEvent")
    policy = POLICIES[event.kind]

    if event.source_event_id is None:
        return Verdict(False, REASON_MISSING_PROVENANCE, event.kind)
    if policy.requires_approval and event.approved_by is None:
        return Verdict(False, REASON_MISSING_APPROVAL, event.kind)
    if policy.requires_dropped_constraints and event.dropped_constraints is None:
        return Verdict(False, REASON_UNDECLARED_DROPPED_CONSTRAINTS, event.kind)
    if policy.requires_residual_declaration and event.residual_in_flight is None:
        return Verdict(False, REASON_UNDECLARED_RESIDUAL, event.kind)
    if event.kind is TransferKind.WORKSPACE_RESTORE and event.residual_in_flight:
        return Verdict(False, REASON_RESIDUAL_IN_FLIGHT, event.kind)
    if event.kind is not TransferKind.CONTEXT_COMPACT and event.dropped_constraints is not None:
        return Verdict(False, REASON_MISPLACED_FIELD, event.kind)
    if event.kind is not TransferKind.WORKSPACE_RESTORE and event.residual_in_flight is not None:
        return Verdict(False, REASON_MISPLACED_FIELD, event.kind)
    return Verdict(True, REASON_OK, event.kind)


def classify(event: TransferEvent) -> str:
    """The transfer kind's name for one event, as a string.

    The classifier and the evaluator are separate because a caller may
    want to bucket events for a report without asking whether they are
    verified -- and the *order* matters: classify first, then evaluate.
    """
    if not isinstance(event, TransferEvent):
        raise StateTransferAuditError("classify expects a TransferEvent")
    return event.kind.value


def assert_verified(event: TransferEvent) -> TransferEvent:
    """Return the event if it is verified; raise otherwise.

    This is the enforcement point for "an unverified event must not be
    treated as verified downstream".  A ``verified`` flag is a label; this
    is the gate.  The exception names the reason code so the caller learns
    *which* rule failed rather than merely that one did.
    """
    verdict = evaluate(event)
    if not verdict.verified:
        raise UnverifiedTransferError(
            "state transfer %r (%s) is not verified: %s"
            % (event.event_id, event.kind.value, verdict.reason)
        )
    return event


def compute_row_hash(seq: int, event: TransferEvent, prev_hash: str) -> str:
    """The chain hash of one row: sha256 over its canonical body."""
    body = {
        "seq": seq,
        "event": event.to_dict(),
        "prev_hash": prev_hash,
    }
    return "sha256:" + hashlib.sha256(jcs_canonical_json(body)).hexdigest()


@dataclass(frozen=True)
class TransferRow:
    """One row of the state-transfer chain.  Immutable."""

    seq: int
    event: TransferEvent
    prev_hash: str
    row_hash: str

    def to_dict(self) -> Dict[str, Any]:
        """Return the row as a plain dict (for export and for audit)."""
        return {
            "seq": self.seq,
            "event": self.event.to_dict(),
            "prev_hash": self.prev_hash,
            "row_hash": self.row_hash,
        }


class TransferAuditor:
    """An append-only, hash-chained ledger of state transfers.

    The chain exists so that a question like "which transfer brought this
    unverified state into the context?" has an answer that does not depend
    on anybody's memory.  Each row pins the event's full content, so a
    later edit to an event is a chain break, not a silent correction.

    ``verify()`` returns ``(ok, first_bad_index)``.  ``first_bad_index`` is
    the *index* of the first row that does not verify (0-based), or
    ``None`` when the chain is intact.

    ``record()`` accepts an event that is **not** verified: the point of
    the chain is to record what actually happened, including the transfers
    that failed their rules.  A failure is *reported*, not hidden.  Use
    :func:`assert_verified` at the point where a downstream consumer must
    refuse to treat the state as checked.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._rows: List[TransferRow] = []

    def __len__(self) -> int:
        return len(self._rows)

    @property
    def head(self) -> str:
        """The chain hash of the last row, or the genesis pin."""
        return self._rows[-1].row_hash if self._rows else GENESIS_HASH

    def record(self, event: TransferEvent) -> TransferRow:
        """Append one transfer event to the chain and return its row."""
        if not isinstance(event, TransferEvent):
            raise StateTransferAuditError("record expects a TransferEvent")
        with self._lock:
            seq = len(self._rows)
            prev = self.head
            row_hash = compute_row_hash(seq, event, prev)
            row = TransferRow(seq=seq, event=event, prev_hash=prev,
                              row_hash=row_hash)
            self._rows.append(row)
            return row

    def events(self) -> Tuple[TransferEvent, ...]:
        """Every recorded event, in order."""
        with self._lock:
            return tuple(row.event for row in self._rows)

    def rows(self) -> Tuple[TransferRow, ...]:
        """Every row, in order."""
        with self._lock:
            return tuple(self._rows)

    def verify(self) -> Tuple[bool, Optional[int]]:
        """Return ``(ok, first_bad_index)``.

        Detects a mutated row, an inserted row and a deleted row.  The
        index is the 0-based position of the first row that fails;
        ``None`` when the chain is intact.
        """
        prev = GENESIS_HASH
        with self._lock:
            for index, row in enumerate(self._rows):
                if row.seq != index:
                    return False, index
                if row.prev_hash != prev:
                    return False, index
                if compute_row_hash(row.seq, row.event, row.prev_hash) != row.row_hash:
                    return False, index
                prev = row.row_hash
        return True, None

    def unverified(self) -> Tuple[TransferEvent, ...]:
        """Every recorded event that did not satisfy the invariant."""
        with self._lock:
            return tuple(
                row.event for row in self._rows if not evaluate(row.event).verified
            )

    def _mutate_for_test(self, index: int, **changes: Any) -> None:
        """Rewrite one row in place.  **Test-only** tamper hook.

        The chain is only worth anything if a tamper can be *observed*, so
        the auditor ships one narrow way to break it.  It is not part of
        the module's public contract and nothing in the module calls it.
        """
        if not isinstance(index, int) or isinstance(index, bool):
            raise StateTransferAuditError("index must be an int")
        if index < 0 or index >= len(self._rows):
            raise StateTransferAuditError("index out of range")
        with self._lock:
            row = self._rows[index]
            event = row.event
            if "event" in changes:
                event = changes["event"]
            else:
                fields = {
                    "event_id": event.event_id,
                    "kind": event.kind,
                    "payload_digest": event.payload_digest,
                    "source_event_id": event.source_event_id,
                    "approved_by": event.approved_by,
                    "dropped_constraints": event.dropped_constraints,
                    "residual_in_flight": event.residual_in_flight,
                    "occurred_at": event.occurred_at,
                }
                for key, value in changes.items():
                    if key not in fields:
                        raise StateTransferAuditError("unknown field %r" % key)
                    fields[key] = value
                event = TransferEvent(**fields)
            self._rows[index] = TransferRow(
                seq=row.seq,
                event=event,
                prev_hash=row.prev_hash,
                row_hash=row.row_hash,
            )


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
    path = os.path.join(here, "state_transfer_audit.py")
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



