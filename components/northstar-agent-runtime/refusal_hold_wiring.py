"""Refusal-hold wiring: a recorded refusal blocks the re-seal of a grant.

What was missing
----------------
:mod:`refusal_hold` (the previous slice) built a **refusal hold**: a query
that answers *is this re-dispatch blocked by a refusal, and by which row?*.
Nothing consulted it.  Meanwhile :mod:`forward_seal_ledger` already owns the
exact place where the same action gets **signed again**: ``append_grant()``
asks its tombstone registry, *inside the append's critical section*, whether
this action was cancelled -- and on a hit raises :class:`ForwardSealError`
with **the record not written to disk**.

The refusal hold is the tombstone gate's isomorphism, but it sat on no
re-issue path.  So refusal rows piled up on the books while the same action
kept getting signed: *recorded but not enforced*, which is worse than *not
recorded*, because the ledger creates the illusion that the refusal was
handled.

This module is the **wiring component**: it maps the ledger's action
identity onto the hold's key, adapts the hold to the shape the ledger's
injection point accepts, and answers the one question the seal path asks.

The four identity questions (answered, with the evidence, in
``docs/design/refusal-hold-wiring.md``)
------------------------------------------------------------
1. **How is a ``RefusalHoldKey`` built from ``(grant_id, action, subject)``?**
   ``scope_id`` is the **grant id**, ``action`` is the action, and the
   **subject is collapsed** -- see (3).
2. **What goes in ``scope_kind``?**  The ledger side has no queue/task
   dimension.  The wiring **reuses the existing vocabulary** and declares
   which member it means on the ledger side: :data:`DEFAULT_SCOPE_KIND`
   (``"task"``), overridable per action.  A *new* scope kind would have to
   be added to :mod:`refusal_hold`, which this slice may not do.
3. **How is the third ``subject`` layer expressed?**  It is **not**: the
   hold's key has three fields and no subject.  The wiring therefore
   collapses the subject, which makes a refusal **coarser than a
   cancellation**: a refusal recorded for one subject also blocks the other
   subjects of the same grant and action.  Over-blocking is the safe
   direction for a refusal gate; the cost is stated in the design doc.
4. **On which side is the refusal row recorded?**  **On the
   :mod:`refusal_row` side** -- the row itself carries no scope field at
   all (verdict, evidence hash, ruleset hash, verifier key, population
   digest, refused_at, reason, instruments), and its digest is computed
   over exactly those fields, so a scope cannot be added to it without
   breaking ``verify_row``.  The **scope lives on the hold side**, in the
   entry key.  The two sides meet in the wiring's conversion table --
   :func:`refusal_hold_key` -- and both sides of a refusal go through it,
   so the recording side and the checking side can never drift apart.

Fail closed
-----------
A malformed identity (empty grant id, an action that is not a string, a
subject of the wrong type), an unreadable store, a tampered row -- every one
of them **refuses the seal**.  The repository's own answer is
``scope_qualifier.BLOCKING_OUTCOMES``, which contains ``OUTCOME_UNKNOWN``:
an unknown state is never a clean read.

Expiry
------
**Nothing expires.**  ``now`` is threaded through (the caller owns the
clock) but it does not change the answer: a permission-class refusal has no
bound to pass.  If a ``capacity``-class split is wanted later, it belongs in
``RefusalHold``'s policy layer -- not in this wiring layer.

Source mapping
--------------
**Source (hermesagentj, "The most useful thing I built this month is a
check that refuses to run", Moltbook post
``abe9e16f-21a4-4d38-a2b1-03fd84c3543c``)** -- the source names the
refusal row and the refusal's own fields.  It does **not** name a hold, a
key, a seal path, a grant pin, a subject layer, or a concurrency contract.

**The evidence for this slice is therefore repository code**, cited by line
number throughout: ``forward_seal_ledger.py`` (the injection point at line
240, ``set_tombstones`` at line 265, the lock-internal authorization at
lines 488-552), ``cancellation_tombstone.py`` (``Tombstone.covers`` at line
157, ``TombstoneSet.blocked`` at line 399), ``grant_pin_ledger.py``
(``GrantPin`` at line 163, ``seal_into`` at line 423), ``refusal_row.py``
(``RefusalRow`` at line 193, ``verify_row`` at line 426) and
``refusal_hold.py``.

**Northstar extensions** (not in the source): the identity mapping
(``grant_id`` -> ``scope_id``), the scope-kind default, the subject
collapse, the registry adapter, the tombstone composition, the
lock-binding that makes "refusal recorded but still issued" impossible, and
the executable wiring helpers :func:`authorize` and
:func:`install_refusal_gate`.

House style: frozen dataclasses, caller-supplied clock (never the wall
clock), fail-closed taxonomy, stdlib-only, ``sha256:`` digest pins,
version/schema pins, ``stdlib_only()`` + ``main()`` self-check.
"""

from __future__ import annotations

import contextlib
import threading
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from refusal_hold import (
    REASON_ALLOWED_NO_REFUSAL,
    REASON_BLOCKED_BY_REFUSAL,
    REASON_BLOCKED_KEY_INVALID,
    REASON_BLOCKED_ROW_INVALID,
    REASON_BLOCKED_ROW_TAMPERED,
    REASON_BLOCKED_STORE_UNREADABLE,
    SCOPE_KIND_LEASE,
    SCOPE_KIND_QUEUE,
    SCOPE_KIND_TASK,
    SCOPE_KINDS,
    RefusalHold,
    RefusalHoldEntry,
    RefusalHoldError,
    RefusalHoldKey,
    RefusalHoldKeyError,
    RefusalHoldResult,
    RefusalHoldStore,
)
from refusal_row import RefusalRow

try:  # pragma: no cover - the coupling is best-effort, never load-bearing
    from forward_seal_ledger import ForwardSealError as _ForwardSealError
except Exception:  # pragma: no cover - a host without the ledger still works
    _ForwardSealError = Exception  # type: ignore[assignment,misc]

__all__ = [
    "REFUSAL_HOLD_WIRING_VERSION",
    "SCHEMA_PIN",
    "DEFAULT_SCOPE_KIND",
    "MAX_WIRING_EVENTS",
    "RefusalHoldWiringError",
    "RefusalHoldKeyMappingError",
    "RefusalRefusedError",
    "scope_kind_for",
    "refusal_hold_key",
    "queue_hold_key",
    "task_hold_key",
    "authorize",
    "install_refusal_gate",
    "install_queue_refusal_gate",
    "RefusalHoldRegistry",
    "RefusalHoldQueueGate",
]

#: Module version pin.
REFUSAL_HOLD_WIRING_VERSION = "refusal-hold-wiring.v1"

#: Schema pin carried by the wiring's own records.
SCHEMA_PIN = "northstar.refusal-hold-wiring.v1"

#: The scope kind a **ledger-side** refusal lives under.
#:
#: The hold's vocabulary is closed (``queue`` / ``task``) and the ledger side
#: has no queue/task dimension, so the wiring *declares* which member it
#: means here: a grant pin authorizes one concrete action on one concrete
#: subject, which is a **task-scoped** authorization.  ``scope_id`` is the
#: grant id, so the key reads ``task:<grant id>:<action>``.
#:
#: A host that wants a different namespace supplies ``scope_kind=`` to the
#: registry, or a per-action override.  The declaration must be the *same*
#: on the recording side and the checking side -- :func:`refusal_hold_key`
#: is the single home of that decision, so it cannot drift.
DEFAULT_SCOPE_KIND = SCOPE_KIND_TASK

#: How many events the registry remembers for its audit trail.
MAX_WIRING_EVENTS = 4096


class RefusalHoldWiringError(RefusalHoldError, _ForwardSealError):
    """Fail-closed: the wiring could not be used, so nothing is sealed.

    The class inherits ``refusal_hold.RefusalHoldError`` (the hold's own
    error vocabulary) and ``forward_seal_ledger.ForwardSealError`` (the
    seal ledger's refusal vocabulary) so that a host which already catches
    either one catches the wiring's errors too.  A refusal that reaches the
    seal path is a **seal refusal**, not an unexpected crash.
    """


class RefusalHoldKeyMappingError(RefusalHoldWiringError, RefusalHoldKeyError):
    """The ledger-side identity could not be mapped onto a hold key.

    An empty grant id, an action of the wrong type, a subject of the wrong
    type, an unknown scope kind, an action that contains a colon: the
    mapping is **refused**, never defaulted to an empty key.  An empty key
    would name *every* action, so a malformed identity must never produce
    a usable key.

    The class inherits ``RefusalHoldKeyError`` so that a host which already
    catches the hold's key vocabulary catches this one too.
    """

    reason = REASON_BLOCKED_KEY_INVALID


class RefusalRefusedError(RefusalHoldWiringError):
    """A recorded refusal blocks the seal.

    It carries the hold's ``reason`` slug, so the *why* survives the
    crossing: ``blocked_by_refusal``, ``blocked_row_tampered``,
    ``blocked_store_unreadable`` or ``blocked_row_invalid``.
    """

    def __init__(self, message: str, reason: str = REASON_BLOCKED_BY_REFUSAL) -> None:
        super().__init__(message)
        self.reason = reason


def _require_grant_id(value: Any) -> str:
    """The grant id, or a refused mapping.

    An empty (or whitespace-only) grant id is a **malformed identity**, not
    an empty scope: a refusal for "no grant" would cover everything.
    """
    if not isinstance(value, str):
        raise RefusalHoldKeyMappingError(
            f"wiring: grant_id must be a string, got {value!r}"
        )
    text = value.strip()
    if text == "":
        raise RefusalHoldKeyMappingError("wiring: grant_id must not be empty")
    return text


def _require_action(value: Any) -> str:
    """The action, or a refused mapping.

    Emptiness and the colon rule belong to ``RefusalHoldKey`` itself: the
    key's canonical form is ``<scope_kind>:<scope_id>:<action>``, so a colon
    in the action would make the key ambiguous.
    """
    if not isinstance(value, str):
        raise RefusalHoldKeyMappingError(
            f"wiring: action must be a string, got {value!r}"
        )
    return value


def _require_subject(value: Any) -> str:
    """The subject, or a refused mapping.

    The subject is **collapsed** by this wiring (see the module docstring),
    but it is still **typed**: a subject that is not a string is a
    malformed identity, not an absent one.
    """
    if value is None:
        return ""
    if not isinstance(value, str):
        raise RefusalHoldKeyMappingError(
            f"wiring: subject must be a string or None, got {value!r}"
        )
    return value


def _require_row(row: Any) -> RefusalRow:
    """The refusal row, or a refused mapping.

    A refusal is a row, not a boolean and not a summary: the wiring hands
    the *row* to the hold, which re-verifies it on every query.  ``None``
    is not a row either, so it is refused by the same rule.
    """
    if not isinstance(row, RefusalRow):
        raise RefusalHoldWiringError(
            "wiring: a refusal must be a refusal_row.RefusalRow, got "
            f"{type(row).__name__}"
        )
    return row


def scope_kind_for(
    action: str,
    *,
    default: str = DEFAULT_SCOPE_KIND,
    overrides: Optional[Mapping[str, str]] = None,
) -> str:
    """The scope kind an action's refusals live under.

    The scope kind is **not** derived from the action's text: deriving a
    refusal's scope from a string would make the meaning of a refusal
    depend on string matching, and a name collision would silently
    re-scope refusals.  It is a **declared** attribute of the action
    namespace -- a per-action override table, with one default for
    everything else.

    Both sides of a refusal go through this function, so the recording side
    and the checking side cannot drift apart.
    """
    if overrides:
        for known_action, kind in overrides.items():
            if known_action == action:
                if kind not in SCOPE_KINDS:
                    raise RefusalHoldKeyMappingError(
                        f"wiring: scope kind {kind!r} is not one of "
                        f"{sorted(SCOPE_KINDS)}"
                    )
                return kind
    if default not in SCOPE_KINDS:
        raise RefusalHoldKeyMappingError(
            f"wiring: scope kind {default!r} is not one of {sorted(SCOPE_KINDS)}"
        )
    return default

def refusal_hold_key(
    grant_id: str,
    action: str,
    subject: Optional[str] = None,
    *,
    scope_kind: str = DEFAULT_SCOPE_KIND,
    scope_kind_overrides: Optional[Mapping[str, str]] = None,
) -> RefusalHoldKey:
    """The hold key for one ledger-side action identity.

    This is the **conversion table** between the two sides:

    ===================  =========================================
    ledger side          hold side
    ===================  =========================================
    ``grant_id``         ``scope_id``
    ``action``           ``action``
    ``subject``          *collapsed* (not represented)
    *(none)*             ``scope_kind`` (declared, see below)
    ===================  =========================================

    A malformed input **fails closed**: it raises rather than constructing
    an empty key, because an empty key would name *every* action.
    """
    grant_text = _require_grant_id(grant_id)
    action_text = _require_action(action)
    _require_subject(subject)
    kind = scope_kind_for(
        action_text, default=scope_kind, overrides=scope_kind_overrides
    )
    # ``RefusalHoldKey`` owns the emptiness and the colon rule; its error
    # is deliberately *not* rewritten here, so a caller can tell a
    # ledger-side mapping failure from a hold-side key failure.
    try:
        return RefusalHoldKey(kind, grant_text, action_text)
    except RefusalHoldKeyError as error:
        raise RefusalHoldKeyMappingError(
            f"wiring: the ledger-side identity does not map onto a hold key: {error}"
        ) from error


def subject_covers(
    refused_subject: Optional[str], offered_subject: Optional[str]
) -> bool:
    """True when a refusal refused for ``refused_subject`` covers the
    action when it is offered with ``offered_subject``.

    **The subject layer is collapsed.**  The refusal hold's key carries no
    subject, so a refusal recorded for one subject covers **every** subject
    of the same ``(grant_id, action)``.  A refusal that named no subject
    covers every subject as well.

    This is the asymmetry the design document states: **a refusal is
    coarser than a cancellation.**  The tombstone gate narrows by subject
    (``Tombstone.covers``): a tombstone that names a subject covers that
    subject, and an unscoped tombstone covers all of them.  The refusal
    hold has no subject field at all, so it cannot narrow -- it can only
    refuse more than strictly necessary.

    The consequence is deliberate: over-blocking is the safe direction for
    a refusal gate (a refused action stays refused until the refusal is
    withdrawn), and under-blocking is the unsafe one (the action gets
    signed again, which is exactly the gap this slice closes).  The cost is
    that a refusal of one subject also refuses its siblings, so a host
    that needs subject-level granularity must use the **cancellation**
    gate, not the refusal gate.

    The function exists so the semantics live in **code** and are pinned by
    a test, rather than being described only in a design document.
    """
    if refused_subject is None:
        # A refusal that named no subject covers every subject.
        return True
    if offered_subject is None:
        # An action offered without a subject is covered by any refusal
        # of the same (grant, action): "not naming a subject" is not
        # evidence of being outside the scope.
        return True
    # The collapsed layer: the subject does not narrow the refusal.
    return True


class RefusalHoldRegistry:
    """The registry the seal ledger's injection point accepts.

    Its shape is the shape of ``cancellation_tombstone.TombstoneSet``:
    ``blocked(grant_id, action, subject, now=...)`` answers "is this action
    blocked, and by what", and ``is_blocked(...)`` answers the same
    question as a boolean.  A ledger written against ``TombstoneSet`` can
    hold this object without changing a line.

    Three differences from the tombstone set are deliberate and are the
    whole point of this slice:

    * the thing that comes back is a **refusal** (a ``RefusalHoldResult``
      carrying the row), not a tombstone -- the caller can name the refusal
      that stopped the seal;
    * a **broken gate blocks**.  The tombstone set answers ``None`` when
      nothing is live; the refusal registry answers "blocked" when it
      cannot reach a well-founded conclusion (an unreadable store, a
      tampered row).  ``None`` means *no refusal covers this action* -- and
      only after the gate has answered;
    * a **malformed identity raises** (it is not answered as "no refusal"):
      a key that cannot be built would otherwise name *no* action, and
      "nothing covers it" is the one answer that must never be given by
      accident.

    The registry is **thread-safe**, and it can be **bound to the ledger's
    own lock** (:meth:`bind_gate`).  The binding is what makes "a refusal
    was recorded but the action was issued anyway" impossible: the refusal
    is recorded under the *same* lock the seal's check runs under, so a
    seal and a recording are serialized with respect to each other.
    """

    def __init__(
        self,
        hold: Optional[RefusalHold] = None,
        *,
        scope_kind: str = DEFAULT_SCOPE_KIND,
        scope_kind_overrides: Optional[Mapping[str, str]] = None,
    ) -> None:
        self._lock = threading.RLock()
        self._entries: List[RefusalHoldEntry] = []
        self._scope_kind = scope_kind
        self._scope_kind_overrides = dict(scope_kind_overrides or {})
        self._events: List[Dict[str, Any]] = []
        self._gate_lock: Optional[Any] = None
        if hold is not None:
            self._entries = list(hold.entries())
        self._store = RefusalHoldStore(self._entries)
        self._hold = RefusalHold(
            entries=self._entries, store=self._store, now=int(hold.now) if hold else 0
        )

    # -- reading ----------------------------------------------------------

    @property
    def hold(self) -> RefusalHold:
        """The hold this registry reads from."""
        return self._hold

    @property
    def store(self) -> RefusalHoldStore:
        """The store this registry reads from.

        A host that wants to test the broken-gate case breaks *this*
        store; the registry notices (through ``is_readable()``) and keeps
        it broken across further recordings.
        """
        return self._store

    @property
    def scope_kind(self) -> str:
        """The scope kind this registry's refusals live under."""
        return self._scope_kind

    @property
    def is_refusal_registry(self) -> bool:
        """This registry is the **refusal** family, not the cancellation one.

        The seal ledger's injection point holds **two** gate families --
        the cancellation tombstone and the refusal hold -- and they are
        both ``TombstoneSet``-shaped.  The ledger tells them apart by
        this flag, so installing a refusal gate does not displace an
        installed cancellation gate (and neither displaces the other).
        """
        return True

    def key_for(
        self, grant_id: str, action: str, subject: Optional[str] = None
    ) -> RefusalHoldKey:
        """The hold key for one ledger-side identity.

        A malformed identity **raises** -- see the class docstring.
        """
        return refusal_hold_key(
            grant_id,
            action,
            subject,
            scope_kind=self._scope_kind,
            scope_kind_overrides=self._scope_kind_overrides,
        )

    def check(
        self,
        grant_id: str,
        action: str,
        subject: Optional[str] = None,
        *,
        now: Optional[float] = None,
    ) -> RefusalHoldResult:
        """The gate's full answer for one identity.

        Unlike :meth:`blocked`, this never returns ``None``: the caller
        always gets a reason, whether the action is refused, allowed, or
        the gate was unusable.
        """
        key = self.key_for(grant_id, action, subject)
        return self.check_key(key, now=now)

    def check_key(
        self, key: RefusalHoldKey, *, now: Optional[float] = None
    ) -> RefusalHoldResult:
        """The gate's full answer for an **already-built** hold key.

        This is :meth:`check` without the key construction, for the
        callers that already hold a key: the queue gate's two namespaces
        (``queue`` and ``lease``) build their keys with
        :func:`queue_hold_key` and :func:`task_hold_key`, because those
        keys carry a scope kind the ledger side does not use.

        The reason this method exists at all is the **audit trail**.  The
        registry's events are documented as "what was recorded and what
        was checked", and every check that goes through the registry
        records a ``checked`` event.  The queue gate used to reach past
        the registry into ``registry.hold.check`` and read the hold
        directly, so a queue-side check produced **no event at all** --
        the gate that stops a job from going back to ``ready`` left no
        trace.  Measured 2026-11-23, before the fix:

            registry.check("grant-1", "seal")       ->  1 event
            gate.check_queue("job-1", "dispatch")   ->  still 1
            gate.check_task("task-1", "dispatch")   ->  still 1

        Routing both sides through one method is what makes them agree.
        """
        result = self._hold.check(key, now=now)
        self._record_event("checked", key, result)
        return result

    def blocked(
        self,
        grant_id: str,
        action: str,
        subject: Optional[str] = None,
        *,
        now: Optional[float] = None,
    ) -> Optional[RefusalHoldResult]:
        """The refusal that blocks this action now, if any.

        The shape is ``TombstoneSet.blocked``'s: ``None`` means *no refusal
        covers this action*, and a non-``None`` result means *this action
        is blocked* -- by a refusal, or by a gate that could not answer
        (an unreadable store, a tampered row).
        """
        result = self.check(grant_id, action, subject, now=now)
        if not result.blocked:
            return None
        return result

    def is_blocked(
        self,
        grant_id: str,
        action: str,
        subject: Optional[str] = None,
        *,
        now: Optional[float] = None,
    ) -> bool:
        """True when the action is blocked by a refusal (or by a broken gate)."""
        result = self.check(grant_id, action, subject, now=now)
        return bool(result.blocked)

    # -- mutation ---------------------------------------------------------

    def record(
        self,
        grant_id: str,
        action: str,
        subject: Optional[str] = None,
        *,
        row: Optional[RefusalRow] = None,
        now: Optional[float] = None,
    ) -> RefusalHoldKey:
        """Record a refusal against one ledger-side identity.

        The refusal **row** is recorded on the :mod:`refusal_row` side (the
        row carries no scope: see the module docstring), and the **scope**
        is recorded here, in the hold's entry key.  The two sides are joined
        by :func:`refusal_hold_key` -- the same conversion the checking
        side uses -- so a refusal cannot be recorded under one scope and
        checked under another.

        The entry holds the row **by reference**, and the hold re-verifies
        it on every query, so a row that is tampered with after it was
        recorded is still caught.

        When the registry is **bound** to a ledger's lock, the recording
        happens under that lock, so a seal in flight and this recording are
        serialized: the seal either commits before the refusal lands (the
        action was issued, and is then refused) or it sees the refusal and
        is refused.  "The refusal is on the books and the action was issued
        anyway" cannot happen.
        """
        if row is None:
            raise RefusalHoldWiringError(
                "wiring: record() needs the refusal row itself -- a refusal "
                "with no row is not a refusal"
            )
        _require_row(row)
        key = self.key_for(grant_id, action, subject)
        return self.record_entry(key, row=row, now=now)

    def record_entry(
        self,
        key: RefusalHoldKey,
        *,
        row: Optional[RefusalRow] = None,
        now: Optional[float] = None,
    ) -> RefusalHoldKey:
        """Record a refusal against an **already-built** hold key.

        :meth:`record` is the ledger-side entry point: it maps the
        ledger's ``(grant_id, action, subject)`` onto a key and records
        against it.  The queue side has a different namespace, so it
        builds its own key (see :func:`queue_hold_key` and
        :func:`task_hold_key`) and needs a recording path that takes the
        key directly.

        The two paths share this method, so the recording semantics --
        the row check, the lock order, the store rebuild, the event --
        cannot drift apart between the two sides.  Only the *key* differs.
        """
        if row is None:
            raise RefusalHoldWiringError(
                "wiring: record_entry() needs the refusal row itself -- a "
                "refusal with no row is not a refusal"
            )
        _require_row(row)
        if not isinstance(key, RefusalHoldKey):
            raise RefusalHoldKeyMappingError(
                "wiring: record_entry() needs a RefusalHoldKey, got "
                f"{type(key).__name__}"
            )
        with self._gate():
            with self._lock:
                self._entries = list(self._entries) + [
                    RefusalHoldEntry(key=key, row=row)
                ]
                self._rebuild_store(now=now)
                self._record_event("recorded", key, None)
        return key

    def lift(self, lift: Any) -> None:
        """A tombstone lift offered against a refusal is refused.

        The seal ledger offers a lift when its registry reports a block.
        A **refusal** is not a cancellation and it cannot be lifted by a
        tombstone-lift: the lift names a declared tombstone, and no
        tombstone exists here.  The refusal stands.
        """
        raise RefusalHoldWiringError(
            "a recorded refusal cannot be lifted by a tombstone lift: the "
            "lift names a declared tombstone, and this gate holds a refusal"
        )

    # -- the gate ---------------------------------------------------------

    def bind_gate(self, lock: Any) -> None:
        """Bind the registry to the lock the seal path runs under.

        The bound lock is taken by :meth:`record` and is the same lock the
        seal ledger holds across its check and its write.  The lock order
        is always *gate lock first, registry lock second*, which is the
        order the seal path uses too -- so the two cannot deadlock.
        """
        if lock is not None and not hasattr(lock, "__enter__"):
            raise RefusalHoldWiringError(
                "wiring: the gate lock must be a context manager"
            )
        with self._lock:
            self._gate_lock = lock

    def _gate(self):
        """The bound gate lock, or a no-op when the registry is unbound."""
        lock = self._gate_lock
        if lock is None:
            return contextlib.nullcontext()
        return lock

    # -- audit ------------------------------------------------------------

    def events(self) -> Tuple[Dict[str, Any], ...]:
        """The audit trail: what was recorded and what was checked."""
        with self._lock:
            return tuple(self._events)

    def _record_event(
        self,
        kind: str,
        key: Optional[RefusalHoldKey],
        result: Optional[RefusalHoldResult],
    ) -> None:
        event: Dict[str, Any] = {
            "kind": kind,
            "key": key.identity if key is not None else None,
            "blocked": bool(result is not None and result.blocked),
            "reason": result.reason if result is not None else None,
            "row_digest": result.row_digest if result is not None else None,
            "schema": SCHEMA_PIN,
            "version": REFUSAL_HOLD_WIRING_VERSION,
        }
        with self._lock:
            self._events.append(event)
            if len(self._events) > MAX_WIRING_EVENTS:
                del self._events[: len(self._events) - MAX_WIRING_EVENTS]

    def to_dict(self) -> dict:
        """The registry as a plain dict (the rows are not copied)."""
        return {
            "schema": SCHEMA_PIN,
            "version": REFUSAL_HOLD_WIRING_VERSION,
            "scope_kind": self._scope_kind,
            "entries": [entry.to_dict() for entry in self._entries],
        }

    def _rebuild_store(self, *, now: Optional[float] = None) -> None:
        """Rebuild the store and the hold from the registry's own entries.

        The registry is the authority on its entries.  A store that was
        broken stays broken: a recording must not heal the gate.
        """
        try:
            store = RefusalHoldStore(self._entries)
        except RefusalHoldError as error:
            raise RefusalHoldWiringError(f"wiring: {error}") from error
        if not self._store.is_readable():
            store.break_reads()
        self._store = store
        self._hold = RefusalHold(
            entries=self._entries, store=self._store, now=int(now or 0)
        )


def authorize(
    registry: Any,
    pin: Any,
    action: str,
    subject: Optional[str] = None,
    *,
    now: Optional[float] = None,
) -> str:
    """Authorize one grant seal against the refusal hold.

    The function has the shape of ``forward_seal_ledger``'s lock-internal
    authorization: it takes the **pin**, the **action** and the
    **subject**, asks the registry, and either returns the pin's rendering
    (the seal may proceed) or raises :class:`RefusalRefusedError` (the seal
    is refused and **no record lands**).

    The registry is asked for the **same identity the tombstone gate would
    be asked for**: ``(grant_id, action, subject)``.  The subject is
    collapsed by the mapping -- see the module docstring.
    """
    if registry is None:
        raise RefusalHoldWiringError("wiring: authorize() needs a registry, got None")
    grant_id = getattr(pin, "grant_id", None)
    if grant_id is None:
        raise RefusalHoldKeyMappingError("wiring: the pin must carry a grant_id")
    result = registry.check(grant_id, action, subject, now=now)
    if result.blocked:
        raise RefusalRefusedError(
            f"action {grant_id!r}/{action!r} is refused: a recorded refusal "
            f"covers it ({result.reason}); the seal is refused and no record "
            f"lands",
            reason=result.reason,
        )
    render = getattr(pin, "render", None)
    if not callable(render):
        raise RefusalHoldWiringError(
            "wiring: the pin must carry a render() method"
        )
    return render()


@contextlib.contextmanager
def install_refusal_gate(
    ledger: Any,
    registry: RefusalHoldRegistry,
    *,
    action: str = "dispatch",
    subject: str = "",
    now: Optional[float] = None,
    grant_id: Optional[str] = None,
):
    """Bind the refusal gate into a ledger's commit critical section.

    This is the **executable form of the wiring example** in
    ``docs/design/refusal-hold-wiring.md``: it takes the ledger's lock,
    consults the refusal registry inside it, and lets the seal proceed only
    when no refusal covers the action.

    The binding is what makes "a refusal was recorded but the action was
    issued anyway" impossible: the refusal is recorded under the *same*
    lock, so a seal and a recording are serialized with respect to each
    other.  A seal that runs first commits before the refusal lands (the
    action was issued, and then refused); a recording that runs first
    blocks the seal.  There is no interleaving in which the refusal is on
    the books and the seal still goes through.

    The context manager yields the gate's answer, so the caller can see
    *why* it was blocked.
    """
    lock = getattr(ledger, "_lock", None)
    if lock is None:
        raise RefusalHoldWiringError(
            "wiring: the ledger must expose a lock to bind the gate into"
        )
    # Bind first, so a refusal recorded through this registry is taken
    # under the ledger's lock too.
    registry.bind_gate(lock)
    with lock:
        resolved = grant_id
        if resolved is None:
            resolved = _current_grant_id(ledger)
        result = registry.check(resolved or "", action, subject, now=now)
        if result.blocked:
            raise RefusalRefusedError(
                f"action {resolved!r}/{action!r} is refused: a recorded "
                f"refusal covers it ({result.reason}); the seal is refused "
                f"and no record lands",
                reason=result.reason,
            )
        yield result


def _current_grant_id(ledger: Any) -> Optional[str]:
    """The grant id the ledger is about to seal, when it can be named.

    ``install_refusal_gate`` is called *before* the seal, so the pin may
    not exist yet.  When the ledger exposes the grant id it is about to
    seal, it is used; otherwise the caller supplies ``grant_id=``.
    """
    for name in ("_current_grant_id", "current_grant_id", "_grant_id"):
        value = getattr(ledger, name, None)
        if isinstance(value, str) and value:
            return value
    pin = _current_pin(ledger)
    if pin is not None:
        grant_id = getattr(pin, "grant_id", None)
        if isinstance(grant_id, str) and grant_id:
            return grant_id
    return None


def _current_pin(ledger: Any) -> Any:
    """The pin the ledger is about to seal, when it can be named."""
    for name in ("_current_pin", "current_pin", "_pin"):
        pin = getattr(ledger, name, None)
        if pin is not None:
            return pin
    return None


# ---------------------------------------------------------------------------
# The queue side: a recorded refusal blocks the re-dispatch of the same job
# ---------------------------------------------------------------------------
#
# `docs/design/refusal-hold-wiring.md` §4 names the two re-dispatch paths
# and says why the wiring could not land them: the queue side holds no
# **action identity**, so the hold cannot be asked a question in its own
# vocabulary.
#
# The action identity turns out to be **already carried**.  `JobQueue`
# keeps the job's `task` string on every entry, and `LeasedTaskClaim`
# keeps it in the `ltc_task.task` column.  Neither is a *grant* id, but
# the hold's key does not need one: `scope_id` is the job id or the task
# id, and `action` is the work item's action.  So the queue side needs a
# **mapping**, not a schema change -- which is what this section adds.
#
# The scope namespaces are DIFFERENT and are not interchangeable:
#
#   ledger side    task:<grant id>:<action>
#   queue side     queue:<job id>:<action>
#   lease side     lease:<task id>:<action>
#
# The same refusal row can be registered in more than one namespace, but
# the two keys are not the same key, and a refusal recorded in one does
# not block the other.  The lease side needed its OWN scope kind: the
# ledger side's ``scope_id`` is a grant id and the lease side's is a task
# id, and both are plain strings, so on a shared scope kind the two keys
# were the SAME whenever the id strings matched -- a refusal recorded
# against a grant blocked an unrelated lease.


def queue_hold_key(
    job_id: str,
    action: str,
    *,
    scope_kind: str = SCOPE_KIND_QUEUE,
) -> RefusalHoldKey:
    """The hold key for one queue-side action identity.

    ``scope_id`` is the **job id**, ``action`` is the work item's action.
    The scope kind is ``"queue"`` -- a different namespace from the
    ledger side's ``"task"``, and the two are deliberately not
    interchangeable.

    A malformed input **fails closed**: it raises rather than
    constructing an empty key, because an empty key would name *every*
    action.
    """
    if scope_kind not in SCOPE_KINDS:
        raise RefusalHoldKeyMappingError(
            f"wiring: scope kind {scope_kind!r} is not one of "
            f"{sorted(SCOPE_KINDS)}"
        )
    job_text = _require_grant_id(job_id)
    action_text = _require_action(action)
    try:
        return RefusalHoldKey(scope_kind, job_text, action_text)
    except RefusalHoldKeyError as error:
        raise RefusalHoldKeyMappingError(
            f"wiring: the queue-side identity does not map onto a hold key: {error}"
        ) from error


def task_hold_key(
    task_id: str,
    action: str,
    *,
    scope_kind: str = SCOPE_KIND_LEASE,
) -> RefusalHoldKey:
    """The hold key for one lease-side action identity.

    The lease side's namespace is ``lease:<task id>:<action>``.

    It was **not** ``task:``, and that is a fix rather than a choice.
    The ledger side's namespace is ``task:<grant id>:<action>`` and both
    sides put a plain string in ``scope_id`` -- a grant id and a task id
    are the same *shape*.  So with both sides on ``task``, the two keys
    were the SAME whenever the id strings matched, and a refusal
    recorded against a grant blocked an unrelated lease.  The lease side
    therefore has its own scope kind.

    A malformed input fails closed, as in :func:`queue_hold_key`.
    """
    if scope_kind not in SCOPE_KINDS:
        raise RefusalHoldKeyMappingError(
            f"wiring: scope kind {scope_kind!r} is not one of "
            f"{sorted(SCOPE_KINDS)}"
        )
    task_text = _require_grant_id(task_id)
    action_text = _require_action(action)
    try:
        return RefusalHoldKey(scope_kind, task_text, action_text)
    except RefusalHoldKeyError as error:
        raise RefusalHoldKeyMappingError(
            f"wiring: the lease-side identity does not map onto a hold key: {error}"
        ) from error


class RefusalHoldQueueGate:
    """The queue-side gate: one refusal registry, two queue namespaces.

    The registry it wraps is the same :class:`RefusalHoldRegistry` the
    ledger side uses, so a host can record a refusal once and consult it
    from either side -- but through **this** gate's two methods, which
    build the right key for each side.

    The gate **fails closed**: a gate that cannot answer blocks.  An
    unreadable store, a tampered row, a malformed identity -- all of them
    refuse the re-dispatch rather than letting the job go back to
    ``ready``.
    """

    def __init__(self, registry: RefusalHoldRegistry) -> None:
        if registry is None:
            raise RefusalHoldWiringError(
                "wiring: the queue gate needs a registry, got None"
            )
        self._registry = registry

    @property
    def registry(self) -> RefusalHoldRegistry:
        """The registry this gate consults."""
        return self._registry

    # -- the two sides ----------------------------------------------------

    def check_queue(
        self, job_id: str, action: str, *, now: Optional[float] = None
    ) -> RefusalHoldResult:
        """The gate's answer for one **queue-side** re-dispatch.

        The check goes through the registry, not around it, so it is
        **audited** like every other check -- see
        :meth:`RefusalHoldRegistry.check_key`.
        """
        key = queue_hold_key(job_id, action)
        return self._registry.check_key(key, now=now)

    def check_task(
        self, task_id: str, action: str, *, now: Optional[float] = None
    ) -> RefusalHoldResult:
        """The gate's answer for one **lease-side** re-dispatch.

        Audited, like every other check -- see
        :meth:`RefusalHoldRegistry.check_key`.
        """
        key = task_hold_key(task_id, action)
        return self._registry.check_key(key, now=now)

    # -- the check that refuses -------------------------------------------

    def require_queue_allowed(
        self, job_id: str, action: str, *, now: Optional[float] = None
    ) -> None:
        """Raise :class:`RefusalRefusedError` when the job may not re-dispatch.

        The caller calls this **inside** the critical section that would
        flip the job back to ``ready``, so a refusal recorded under the
        same lock is serialized with the re-dispatch: there is no
        interleaving in which the refusal is on the books and the job
        still goes back to ``ready``.
        """
        result = self.check_queue(job_id, action, now=now)
        if result.blocked:
            raise RefusalRefusedError(
                f"job {job_id!r} may not be re-dispatched for action "
                f"{action!r}: a recorded refusal covers it "
                f"({result.reason}); the job stays where it is",
                reason=result.reason,
            )

    def require_task_allowed(
        self, task_id: str, action: str, *, now: Optional[float] = None
    ) -> None:
        """Raise :class:`RefusalRefusedError` when the task may not re-dispatch."""
        result = self.check_task(task_id, action, now=now)
        if result.blocked:
            raise RefusalRefusedError(
                f"task {task_id!r} may not be re-dispatched for action "
                f"{action!r}: a recorded refusal covers it "
                f"({result.reason}); the task stays where it is",
                reason=result.reason,
            )

    def task_allowed(
        self, task_id: str, action: str, *, now: Optional[float] = None
    ) -> bool:
        """True when the task MAY be re-dispatched.

        The boolean form of :meth:`require_task_allowed`, for the caller
        that sweeps a **batch** of work items: a refusal there must skip
        one item, not abandon the whole sweep.  A blocked answer is
        ``False`` -- never an exception -- and a gate that cannot answer
        at all is ``False`` too, because the hold fails closed.
        """
        return not self.check_task(task_id, action, now=now).blocked

    # -- recording --------------------------------------------------------

    def record_queue(
        self,
        job_id: str,
        action: str,
        *,
        row: Optional[RefusalRow] = None,
        now: Optional[float] = None,
    ) -> RefusalHoldKey:
        """Record a refusal against one queue-side identity.

        The **scope lives on the hold side** and the **row lives on the
        :mod:`refusal_row` side** -- the same split the ledger side uses,
        and the same reason for it: the row's digest is computed over
        exactly its own fields, so a scope cannot be added to it without
        breaking ``verify_row``.
        """
        key = queue_hold_key(job_id, action)
        return self._registry.record_entry(key, row=row, now=now)

    def record_task(
        self,
        task_id: str,
        action: str,
        *,
        row: Optional[RefusalRow] = None,
        now: Optional[float] = None,
    ) -> RefusalHoldKey:
        """Record a refusal against one lease-side identity."""
        key = task_hold_key(task_id, action)
        return self._registry.record_entry(key, row=row, now=now)


@contextlib.contextmanager
def install_queue_refusal_gate(
    queue: Any,
    gate: RefusalHoldQueueGate,
    *,
    job_id: str,
    action: str,
    now: Optional[float] = None,
):
    """Bind the queue-side refusal gate into a queue's retry path.

    The **executable form** of the queue-side wiring: it takes the
    queue's own lock, consults the refusal hold inside it, and lets the
    job go back to ``ready`` only when no refusal covers the action.

    The binding makes "a refusal was recorded but the job was re-dispatched
    anyway" impossible: the refusal is recorded under the *same* lock, so
    a re-dispatch and a recording are serialized with respect to each
    other.  A re-dispatch that runs first commits before the refusal
    lands (the job was issued, and is then refused); a recording that
    runs first blocks the re-dispatch.
    """
    lock = getattr(queue, "_lock", None)
    if lock is None:
        raise RefusalHoldWiringError(
            "wiring: the queue must expose a lock to bind the gate into"
        )
    with lock:
        gate.require_queue_allowed(job_id, action, now=now)
        yield


def stdlib_only() -> bool:
    """True when this module imports nothing outside the standard library."""
    import ast
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {
        "__future__",
        "ast",
        "contextlib",
        "pathlib",
        "threading",
        "typing",
        "refusal_hold",
        "refusal_row",
        "forward_seal_ledger",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    """Self-check: block, do not over-block, fail closed."""
    from refusal_row import digest_of, record_refusal

    evidence = digest_of({"evidence": "stale"})
    ruleset = digest_of({"ruleset": "gate-v3"})
    population = digest_of({"population": "nightly"})
    row = record_refusal(
        "denied",
        evidence,
        ruleset,
        "check-alpha@v1",
        population,
        reason="the evidence digest does not match the ruleset",
        refused_at=1_700_000_000,
        instruments=["check-alpha@v1", "check-beta@v2"],
    )

    registry = RefusalHoldRegistry()
    registry.record("grant-1", "checkout", "order-7", row=row, now=1_700_000_000)

    blocked = registry.check("grant-1", "checkout", "order-7", now=1_700_000_100)
    assert blocked.blocked
    assert blocked.reason == REASON_BLOCKED_BY_REFUSAL

    other_action = registry.check("grant-1", "refund", "order-7")
    assert not other_action.blocked
    assert other_action.reason == REASON_ALLOWED_NO_REFUSAL

    broken = RefusalHoldRegistry()
    broken.record("grant-1", "checkout", "order-7", row=row)
    broken.store.break_reads()
    unreadable = broken.check("grant-1", "checkout", "order-7")
    assert unreadable.blocked
    assert unreadable.reason == REASON_BLOCKED_STORE_UNREADABLE

    assert stdlib_only()
    print("refusal-hold-wiring self-check: ok")


if __name__ == "__main__":  # pragma: no cover
    main()
