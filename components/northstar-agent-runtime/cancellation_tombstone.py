"""Cancellation tombstones: sticky revocation state that survives compaction.

A tombstone is what a cancellation becomes when it has to outlive the message
that carried it.  The failure this module exists to prevent is the one the
Moltbook post names: a summary that keeps the task ("publish the post") and
prunes the cancellation ("stop, don't publish") has *manufactured permission*,
because the compressed handoff now carries a wider authorization than the
principal ever gave.

So a tombstone is not prose.  It is a structured record with:

* the identity of the revoked action (``grant_id`` + ``action`` + ``subject``,
  the same grant-pin identity the sealed ledger uses),
* the declarer and the channel the declarer spoke on,
* the kind of denial (``permission`` or ``capacity``), which decides how it
  may end.

Two rules do the load-bearing work.

**Named lift only.**  A tombstone lifts when a *new* instruction from the
declarer's own channel names the revoked action exactly.  "Continue the work",
"resume", "go on" name nothing, so they lift nothing -- and they are exactly
the sentences a compressor is most likely to keep.

**Expiry split.**  A capacity denial may be renewed by a bounded fresh
measurement, and a capacity denial whose bound has passed is no longer
blocking.  A *permission* stop never expires on the executor's clock: it is
not the executor's to expire.  Only the declarer can lift it, and the lift
itself is a record that gets sealed.

The tombstone's survival mechanism is not clever: it lives in the session's
append-only record stream, next to the transcript, and the compressed prose is
never its home.  Compaction can drop every word of "stop, don't publish" and
the tombstone is still there.
"""
from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence

#: Schema tag written into every serialized tombstone.
TOMBSTONE_SCHEMA_VERSION = "northstar.cancellation-tombstone.v1"

#: The two kinds of denial, and therefore the two expiry rules.
PERMISSION = "permission"
CAPACITY = "capacity"

#: Phrases that never lift a tombstone, however they are phrased.  They are
#: listed explicitly so the rule is auditable rather than a side effect of
#: "does not name the action".
GENERIC_CONTINUATIONS = frozenset({
    "continue",
    "continue the work",
    "continue anyway",
    "continue as planned",
    "carry on",
    "go ahead",
    "go on",
    "keep going",
    "proceed",
    "resume",
    "resume the work",
})

#: Bounds on the carried set, so a handoff grant cannot become a payload.
MAX_TOMBSTONES = 64
MAX_ID_CHARS = 128
MAX_TEXT_CHARS = 512


class TombstoneError(Exception):
    """Base class for tombstone failures.  Fail-closed: always raise."""


class TombstoneLiftError(TombstoneError):
    """A lift was refused.  The tombstone stays standing."""


class CancelledActionError(TombstoneError):
    """An action was refused because a tombstone covers it."""


def _require_text(value: Any, name: str, *, limit: int = MAX_ID_CHARS) -> str:
    if not isinstance(value, str) or not value.strip():
        raise TombstoneError(f"{name} must be a non-empty string")
    if len(value) > limit:
        raise TombstoneError(f"{name} is longer than {limit} characters")
    return value


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _is_generic_continuation(text: str) -> bool:
    """True when the text is one of the phrases that never lifts anything."""
    if not isinstance(text, str):
        return False
    normalized = " ".join(text.strip().lower().rstrip(".!").split())
    return normalized in GENERIC_CONTINUATIONS


@dataclass(frozen=True)
class Tombstone:
    """One sticky revocation.

    ``grant_id`` + ``action`` (+ ``subject``) is the identity: the same
    grant-pin identity the sealed ledger checks, so a tombstone is never
    matched against prose.

    ``declarer`` and ``declarer_channel`` say *who* stopped the action and
    *where they said it*.  Only a new instruction on that same channel from
    that same declarer can lift the tombstone.

    ``kind`` decides the expiry rule: a ``capacity`` denial carries a bound
    (``expires_at``) and may be renewed by a bounded fresh measurement; a
    ``permission`` stop carries no bound at all, because a stop is not the
    executor's to expire.
    """

    grant_id: str
    action: str
    subject: str = ""
    declarer: str = ""
    declarer_channel: str = ""
    declared_at: float = 0.0
    kind: str = PERMISSION
    expires_at: float | None = None
    measurement: str = ""
    reason: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "grant_id", _require_text(self.grant_id, "grant_id"))
        object.__setattr__(self, "action", _require_text(self.action, "action"))
        object.__setattr__(self, "subject", _require_text(self.subject, "subject", limit=MAX_TEXT_CHARS) if self.subject else "")
        object.__setattr__(self, "declarer", _require_text(self.declarer, "declarer"))
        object.__setattr__(self, "declarer_channel", _require_text(self.declarer_channel, "declarer_channel"))
        if self.kind not in (PERMISSION, CAPACITY):
            raise TombstoneError(f"kind must be {PERMISSION!r} or {CAPACITY!r}")
        if self.kind == CAPACITY:
            if self.expires_at is None:
                raise TombstoneError("a capacity denial must carry the bound that measures it")
        elif self.expires_at is not None:
            raise TombstoneError("a permission stop must not carry an expiry: it does not expire on the executor's clock")
        if not isinstance(self.declared_at, (int, float)) or isinstance(self.declared_at, bool):
            raise TombstoneError("declared_at must be a number")

    # -- identity ---------------------------------------------------------
    @property
    def identity(self) -> tuple[str, str, str]:
        """The grant-pin identity this tombstone covers."""
        return (self.grant_id, self.action, self.subject)

    def covers(self, grant_id: str, action: str, subject: str | None = None) -> bool:
        """True when this tombstone covers the given action identity.

        A tombstone that names a subject covers that subject; an unscoped
        tombstone covers every subject of the action.  A caller that names no
        subject is covered by a scoped tombstone too: an unspecified subject
        is not evidence of being outside the scope.
        """
        if grant_id != self.grant_id or action != self.action:
            return False
        if not self.subject:
            return True
        if subject is None or not subject:
            return True
        return subject == self.subject

    # -- serialization ----------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": TOMBSTONE_SCHEMA_VERSION,
            "grant_id": self.grant_id,
            "action": self.action,
            "subject": self.subject,
            "declarer": self.declarer,
            "declarer_channel": self.declarer_channel,
            "declared_at": self.declared_at,
            "kind": self.kind,
            "expires_at": self.expires_at,
            "measurement": self.measurement,
            "reason": self.reason,
        }

    @classmethod
    def from_dict(cls, value: Any) -> "Tombstone":
        if not isinstance(value, Mapping):
            raise TombstoneError("a tombstone must be a mapping")
        data = dict(value)
        version = data.get("schema_version", TOMBSTONE_SCHEMA_VERSION)
        if version != TOMBSTONE_SCHEMA_VERSION:
            raise TombstoneError(f"unknown tombstone schema_version {version!r}")
        unknown = sorted(set(data) - {
            "schema_version", "grant_id", "action", "subject", "declarer",
            "declarer_channel", "declared_at", "kind", "expires_at", "measurement", "reason",
        })
        if unknown:
            raise TombstoneError("tombstone carries unknown fields: " + ", ".join(unknown))
        expires_at = data.get("expires_at")
        if expires_at is not None and (not isinstance(expires_at, (int, float)) or isinstance(expires_at, bool)):
            raise TombstoneError("expires_at must be a number or null")
        return cls(
            grant_id=data.get("grant_id", ""),
            action=data.get("action", ""),
            subject=data.get("subject", "") or "",
            declarer=data.get("declarer", ""),
            declarer_channel=data.get("declarer_channel", ""),
            declared_at=float(data.get("declared_at", 0.0) or 0.0),
            kind=data.get("kind", PERMISSION),
            expires_at=expires_at,
            measurement=str(data.get("measurement", "") or ""),
            reason=str(data.get("reason", "") or ""),
        )

    def digest(self) -> str:
        """Stable digest of the canonical form (a ``sha256:`` pin)."""
        return "sha256:" + hashlib.sha256(_canonical(self.to_dict())).hexdigest()


# ---------------------------------------------------------------------------
# The lift rule
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Lift:
    """A new instruction that claims to lift a tombstone.

    It carries the provenance of the instruction (who spoke, on which
    channel, when) and the action it *names*.  ``text`` is the instruction
    itself; it is never used to decide whether the lift is valid beyond the
    explicit generic-continuation refusal -- the decision is provenance plus
    an exact action match, not wording.
    """

    declarer: str
    declarer_channel: str
    grant_id: str
    action: str
    subject: str = ""
    text: str = ""
    lifted_at: float = 0.0

    def __post_init__(self) -> None:
        object.__setattr__(self, "declarer", _require_text(self.declarer, "declarer"))
        object.__setattr__(self, "declarer_channel", _require_text(self.declarer_channel, "declarer_channel"))
        object.__setattr__(self, "grant_id", _require_text(self.grant_id, "grant_id"))
        object.__setattr__(self, "action", _require_text(self.action, "action"))

    def names(self, tombstone: Tombstone) -> bool:
        """True when this instruction names the tombstone's action exactly."""
        if self.grant_id != tombstone.grant_id or self.action != tombstone.action:
            return False
        if not tombstone.subject:
            return True
        if not self.subject:
            return False
        return self.subject == tombstone.subject

    def to_dict(self) -> dict[str, Any]:
        return {
            "declarer": self.declarer,
            "declarer_channel": self.declarer_channel,
            "grant_id": self.grant_id,
            "action": self.action,
            "subject": self.subject,
            "text": self.text,
            "lifted_at": self.lifted_at,
        }

    @classmethod
    def from_dict(cls, value: Any) -> "Lift":
        if not isinstance(value, Mapping):
            raise TombstoneError("a lift must be a mapping")
        return cls(
            declarer=value.get("declarer", ""),
            declarer_channel=value.get("declarer_channel", ""),
            grant_id=value.get("grant_id", ""),
            action=value.get("action", ""),
            subject=value.get("subject", "") or "",
            text=str(value.get("text", "") or ""),
            lifted_at=float(value.get("lifted_at", 0.0) or 0.0),
        )


def check_lift(tombstone: Tombstone, lift: Lift) -> None:
    """Raise unless ``lift`` may lift ``tombstone``.

    The two conditions, in order:

    1. *Provenance.*  The instruction must come from the tombstone's own
       declarer, on the tombstone's own channel.  A lift from another
       channel is somebody else speaking -- the source thread's warning is
       the reason: a re-authorization has to be ordered against the
       tombstone in the store, not merely timestamped after it.
    2. *Naming.*  The instruction must name the revoked action exactly
       (``grant_id`` + ``action`` + subject).  A generic continuation names
       nothing and lifts nothing.

    The instruction must also be *new*: a lift cannot predate the
    tombstone.
    """
    if not isinstance(tombstone, Tombstone) or not isinstance(lift, Lift):
        raise TombstoneLiftError("a lift is checked against a tombstone")
    if lift.declarer != tombstone.declarer:
        raise TombstoneLiftError(
            f"the lift is not from the declarer {tombstone.declarer!r}: a stop is lifted by its own voice"
        )
    if lift.declarer_channel != tombstone.declarer_channel:
        raise TombstoneLiftError(
            f"the lift is on channel {lift.declarer_channel!r}, not the declarer's channel "
            f"{tombstone.declarer_channel!r}"
        )
    if lift.lifted_at and lift.lifted_at < tombstone.declared_at:
        raise TombstoneLiftError("the lift predates the tombstone: it cannot lift it")
    if not lift.names(tombstone):
        raise TombstoneLiftError(
            f"the lift does not name the revoked action {tombstone.grant_id!r}/{tombstone.action!r}"
        )
    if _is_generic_continuation(lift.text):
        raise TombstoneLiftError(
            "a generic continuation does not name a revoked action, so it lifts nothing"
        )


def check_renewal(tombstone: Tombstone, measurement: str, *, now: float, valid_until: float) -> None:
    """Raise unless a fresh measurement may renew ``tombstone``.

    Only a capacity denial may be renewed, and only by a *bounded* fresh
    measurement: a fresh number can establish capacity, never permission.
    The renewal replaces the old bound with the new one -- it does not extend
    the old bound, and it does not change the tombstone's identity.
    """
    if not isinstance(tombstone, Tombstone):
        raise TombstoneError("a renewal is checked against a tombstone")
    if tombstone.kind != CAPACITY:
        raise TombstoneLiftError(
            "a permission stop is never renewed by a measurement: a fresh number can establish capacity, not permission"
        )
    if not isinstance(measurement, str) or not measurement.strip():
        raise TombstoneLiftError("a renewal must carry a fresh measurement")
    if not isinstance(now, (int, float)) or isinstance(now, bool):
        raise TombstoneError("now must be a number")
    if not isinstance(valid_until, (int, float)) or isinstance(valid_until, bool):
        raise TombstoneError("valid_until must be a number")
    if valid_until <= now:
        raise TombstoneLiftError("a renewal must be bounded: its bound must lie in the future")


# ---------------------------------------------------------------------------
# The live set of tombstones
# ---------------------------------------------------------------------------


class TombstoneSet:
    """The live tombstones of one session (or one ledger), in memory.

    Deterministic order: tombstones are listed in the order they were
    declared, and the set is thread-safe because the sealed ledger consults
    it inside its own lock and the session layer may read it concurrently.

    The set never *decides* anything on prose: ``blocked`` answers "does a
    tombstone cover this grant-pin identity", and ``lift`` accepts only a
    lift that satisfies :func:`check_lift`.
    """

    def __init__(self, tombstones: Iterable[Tombstone] = ()) -> None:
        self._lock = threading.RLock()
        self._tombstones: dict[tuple[str, str, str], Tombstone] = {}
        self._order: list[tuple[str, str, str]] = []
        for tombstone in tombstones:
            self.add(tombstone)

    # -- reading ----------------------------------------------------------
    def list(self) -> tuple[Tombstone, ...]:
        """The live tombstones, in declaration order."""
        with self._lock:
            return tuple(self._tombstones[key] for key in self._order if key in self._tombstones)

    def __len__(self) -> int:
        with self._lock:
            return len(self._tombstones)

    def __iter__(self):
        return iter(self.list())

    def get(self, grant_id: str, action: str, subject: str | None = None) -> Tombstone | None:
        """The tombstone covering the identity, if any."""
        with self._lock:
            for tombstone in self.list():
                if tombstone.covers(grant_id, action, subject):
                    return tombstone
            return None

    def blocked(
        self,
        grant_id: str,
        action: str,
        subject: str | None = None,
        *,
        now: float | None = None,
    ) -> Tombstone | None:
        """The tombstone that blocks this action now, if any.

        A capacity denial whose bound has passed no longer blocks: that is
        the expiry split.  A permission stop blocks regardless of the
        clock, because it has no bound to pass.
        """
        with self._lock:
            for tombstone in self.list():
                if not tombstone.covers(grant_id, action, subject):
                    continue
                if tombstone.kind == CAPACITY and now is not None:
                    if tombstone.expires_at is not None and now >= tombstone.expires_at:
                        continue
                return tombstone
            return None

    def is_blocked(
        self,
        grant_id: str,
        action: str,
        subject: str | None = None,
        *,
        now: float | None = None,
    ) -> bool:
        """True when the action is covered by a live tombstone."""
        return self.blocked(grant_id, action, subject, now=now) is not None

    # -- mutation ---------------------------------------------------------
    def add(self, tombstone: Tombstone) -> Tombstone:
        """Record a tombstone.  Re-declaring the same identity replaces it."""
        if not isinstance(tombstone, Tombstone):
            raise TombstoneError("only a Tombstone can be added")
        with self._lock:
            key = tombstone.identity
            if key not in self._tombstones:
                if len(self._tombstones) >= MAX_TOMBSTONES:
                    raise TombstoneError(f"a set carries at most {MAX_TOMBSTONES} tombstones")
                self._order.append(key)
            self._tombstones[key] = tombstone
            return tombstone

    def lift(self, lift: Lift) -> Tombstone:
        """Lift the tombstone ``lift`` names.

        The lift is checked with :func:`check_lift` first, so an invalid
        lift raises and the tombstone stays standing.  The lifted tombstone
        is removed from the live set and returned, so the caller can seal the
        lift itself.
        """
        with self._lock:
            for tombstone in self.list():
                if lift.names(tombstone):
                    check_lift(tombstone, lift)
                    key = tombstone.identity
                    self._tombstones.pop(key, None)
                    if key in self._order:
                        self._order.remove(key)
                    return tombstone
            raise TombstoneLiftError(
                f"no tombstone names the revoked action {lift.grant_id!r}/{lift.action!r}"
            )

    def renew(
        self,
        grant_id: str,
        action: str,
        *,
        measurement: str,
        now: float,
        valid_until: float,
        subject: str | None = None,
    ) -> Tombstone:
        """Renew a capacity denial with a bounded fresh measurement."""
        with self._lock:
            tombstone = None
            for candidate in self.list():
                if candidate.covers(grant_id, action, subject):
                    tombstone = candidate
                    break
            if tombstone is None:
                raise TombstoneLiftError(
                    f"no tombstone covers {grant_id!r}/{action!r}, so there is nothing to renew"
                )
            check_renewal(tombstone, measurement, now=now, valid_until=valid_until)
            renewed = Tombstone(
                grant_id=tombstone.grant_id,
                action=tombstone.action,
                subject=tombstone.subject,
                declarer=tombstone.declarer,
                declarer_channel=tombstone.declarer_channel,
                declared_at=tombstone.declared_at,
                kind=tombstone.kind,
                expires_at=valid_until,
                measurement=measurement,
                reason=tombstone.reason,
            )
            key = tombstone.identity
            self._tombstones[key] = renewed
            return renewed

    # -- serialization ----------------------------------------------------
    def to_list(self) -> list[dict[str, Any]]:
        return [tombstone.to_dict() for tombstone in self.list()]

    @classmethod
    def from_list(cls, value: Any) -> "TombstoneSet":
        if value is None:
            return cls()
        if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
            raise TombstoneError("a tombstone set is a list of tombstones")
        return cls(Tombstone.from_dict(item) for item in value)


__all__ = [
    "CAPACITY",
    "GENERIC_CONTINUATIONS",
    "MAX_TOMBSTONES",
    "PERMISSION",
    "TOMBSTONE_SCHEMA_VERSION",
    "CancelledActionError",
    "Lift",
    "Tombstone",
    "TombstoneError",
    "TombstoneLiftError",
    "TombstoneSet",
    "check_lift",
    "check_renewal",
]
