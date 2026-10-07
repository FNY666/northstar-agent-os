"""Calendar service: CalDAV-shaped event/freebusy/RSVP bookkeeping.

Research note: the calendaring line is RFC 5545 (iCalendar) for the
event data model, RFC 5546 (iTIP) for the scheduling protocol that moves
invitations between organizers and attendees, and RFC 4791 (CalDAV) for
the access protocol that synchronizes calendar collections over HTTP.
The three verbs this module models are the CalDAV/iTIP core:

* **VEVENT collections** — ``create()`` mints a frozen
  :class:`EventRecord` inside a named calendar: title, location,
  description, attendees, transparency (opaque/transparent), and a
  :class:`TimeRange`. Every event carries a stable ``uid`` (RFC 5545
  ``UID``), because invitations are matched across organizers' and
  attendees' copies by UID, never by title.
* **FREEBUSY queries** — ``freebusy()`` walks the calendars named in the
  request and returns a frozen :class:`FreeBusyReport` of busy ranges
  covering the window. Like a VFREEBUSY response it is a *report*, not a
  lock: the module can tell you a slot is free, it cannot reserve it for
  you — that gap is the host's to close.
* **RSVP attendance** — ``rsvp()`` records an attendee's iTIP reply
  (``accepted`` / ``declined`` / ``tentative`` / ``needs-action``);
  replies move the attendee entry forward only, and a reply from an
  unknown attendee is refused fail-closed rather than invented.

* **Caller seqs are the clock** — event times are caller-supplied
  integers (``start_seq``/``end_seq``), compared as an ordinal scale. The
  module never calls ``time.time()``: it cannot know what "now" is, and
  pretending otherwise would pin wall-clock nondeterminism into the
  ledger. Recurrence is expressed with an RFC 5545-style ``rrule``
  string, expanded eagerly at create time into a bounded instance list
  (``MAX_INSTANCES``), so freebusy sees every occurrence. The rrule
  subset is deliberately small (``FREQ=DAILY|WEEKLY`` with
  ``COUNT``/``UNTIL``/``INTERVAL``); anything else is refused
  fail-closed — an expansion the module cannot bound is a resource
  exhaustion the module will not accept.
* **Overlap policy is explicit** — by default ``create()`` refuses a
  non-transparent event that overlaps an existing opaque event in the
  same calendar (``OverlapError``): the double-booking failure mode is
  opt-out, not opt-in. ``allow_overlap=True`` re-enables the
  conference-room reality where two entries genuinely share a slot.
* **Cancellation is terminal** — ``cancel()`` moves an event to
  ``cancelled``; cancelled events vanish from freebusy and refuse
  further edits or RSVPs fail-closed. The record stays for audit; the
  slot is freed.
* **Pins bind** — every record carries a ``sha256:`` digest pin over
  its canonical body (calendar id, uid, range, attendees, seq). The
  uid is derived from the organizer + title + range + a per-instance
  counter, so identical inputs replay to identical uids (test-verified)
  while distinct events cannot collide.

Honest scope: this is the *event/freebusy/RSVP ledger*, not a
scheduling oracle. It books reported events; it cannot prove an
attendee actually read an invitation, cannot see meetings created
outside the ledger, and ``freebusy == free`` means "nothing booked
*here* overlaps", never "the human is available". Pair with an
attested CalDAV server for production sync.

Version pin: calendar-service.v1
Schema pin: northstar.calendar-service.v1
"""

from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Mapping, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Module version.
CALENDAR_SERVICE_VERSION = "calendar-service.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.calendar-service.v1"

#: Event id prefix.
_EVENT_PREFIX = "ev-"

#: Calendar id prefix.
_CAL_PREFIX = "cal-"

#: Transparency values.
_TRANSPARENT = "transparent"
_OPAQUE = "opaque"
_TRANSPARENCY = frozenset({_TRANSPARENT, _OPAQUE})

#: RSVP statuses.
_RSVP_NEEDS_ACTION = "needs-action"
_RSVP_ACCEPTED = "accepted"
_RSVP_DECLINED = "declined"
_RSVP_TENTATIVE = "tentative"
_RSVP_STATUSES = frozenset(
    {_RSVP_NEEDS_ACTION, _RSVP_ACCEPTED, _RSVP_DECLINED, _RSVP_TENTATIVE}
)

#: Event lifecycle states.
_STATE_ACTIVE = "active"
_STATE_CANCELLED = "cancelled"

#: rrule frequencies this module expands.
_RRULE_FREQS = frozenset({"DAILY", "WEEKLY"})

#: Hard cap on expanded recurring instances.
MAX_INSTANCES = 366

_AUDIT_KINDS = frozenset(
    {
        "calendar-created",
        "event-created",
        "event-cancelled",
        "event-updated",
        "rsvp-recorded",
        "freebusy-queried",
        "rejected",
    }
)


# ---------------------------------------------------------------------------
# Error taxonomy (all fail-closed, all subclass CalendarError)
# ---------------------------------------------------------------------------


class CalendarError(Exception):
    """Base class for all calendar-service errors."""


class UnknownCalendarError(CalendarError):
    """Calendar id is not registered."""


class DuplicateCalendarError(CalendarError):
    """Calendar id is already registered."""


class UnknownEventError(CalendarError):
    """Event id is not known in this service."""


class DuplicateEventError(CalendarError):
    """Event id is already in use."""


class OverlapError(CalendarError):
    """New event overlaps an existing opaque event (policy)."""


class EventCancelledError(CalendarError):
    """Operation refused because the event is cancelled (terminal)."""


class BadTimeRangeError(CalendarError):
    """start_seq/end_seq are not a valid half-open range."""


class BadRRuleError(CalendarError):
    """Recurrence rule is outside the supported subset."""


class UnknownAttendeeError(CalendarError):
    """RSVP from someone not on the attendee list."""


class BadRSVPError(CalendarError):
    """RSVP status value is unknown."""


class SeqOrderError(CalendarError):
    """Caller seq did not strictly increase."""


class BadInputError(CalendarError):
    """Any other malformed input (empty ids, bad types, ...)."""


# ---------------------------------------------------------------------------
# Canonical digest helpers
# ---------------------------------------------------------------------------


def _canonical(obj: Any) -> bytes:
    """Type-tagged canonical encoding (bool is not int; ints bounded)."""
    if isinstance(obj, bool):
        return ("b:" + ("1" if obj else "0")).encode()
    if isinstance(obj, int):
        if abs(obj) >= 2**53:
            raise BadInputError("integer out of canonical range")
        return ("i:" + str(obj)).encode()
    if isinstance(obj, str):
        return ("s:" + obj).encode()
    if obj is None:
        return b"n:"
    if isinstance(obj, (list, tuple)):
        return b"l:[" + b",".join(_canonical(x) for x in obj) + b"]"
    if isinstance(obj, Mapping):
        items = sorted(obj.items(), key=lambda kv: str(kv[0]))
        return (
            b"d:{"
            + b",".join(_canonical(k) + b"=" + _canonical(v) for k, v in items)
            + b"}"
        )
    raise BadInputError(f"non-canonical value type: {type(obj).__name__}")


def _pin(*parts: Any) -> str:
    digest = hashlib.sha256()
    for part in parts:
        digest.update(_canonical(part))
    return "sha256:" + digest.hexdigest()


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SeqOrderError("seq must be a non-negative int")
    return seq


def _require_id(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise BadInputError(f"{what} must be a non-empty string")
    return value.strip()


# ---------------------------------------------------------------------------
# Records (frozen)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CalendarRecord:
    calendar_id: str
    owner: str
    name: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "calendar_id": self.calendar_id,
            "owner": self.owner,
            "name": self.name,
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class TimeRange:
    start_seq: int
    end_seq: int

    def overlaps(self, other: "TimeRange") -> bool:
        return self.start_seq < other.end_seq and other.start_seq < self.end_seq


@dataclass(frozen=True)
class EventRecord:
    event_id: str
    calendar_id: str
    uid: str
    title: str
    start_seq: int
    end_seq: int
    transparency: str
    location: str
    description: str
    attendees: Tuple[str, ...]
    rrule: Optional[str]
    state: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "calendar_id": self.calendar_id,
            "uid": self.uid,
            "title": self.title,
            "start_seq": self.start_seq,
            "end_seq": self.end_seq,
            "transparency": self.transparency,
            "location": self.location,
            "description": self.description,
            "attendees": list(self.attendees),
            "rrule": self.rrule,
            "state": self.state,
            "seq": self.seq,
            "digest": self.digest,
        }

    def time_range(self) -> TimeRange:
        return TimeRange(self.start_seq, self.end_seq)


@dataclass(frozen=True)
class BusyRange:
    event_id: str
    start_seq: int
    end_seq: int
    title: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "start_seq": self.start_seq,
            "end_seq": self.end_seq,
            "title": self.title,
        }


@dataclass(frozen=True)
class FreeBusyReport:
    calendar_ids: Tuple[str, ...]
    start_seq: int
    end_seq: int
    busy: Tuple[BusyRange, ...]
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "calendar_ids": list(self.calendar_ids),
            "start_seq": self.start_seq,
            "end_seq": self.end_seq,
            "busy": [b.as_dict() for b in self.busy],
            "seq": self.seq,
            "digest": self.digest,
        }

    def is_free(self) -> bool:
        return len(self.busy) == 0


@dataclass(frozen=True)
class RSVPRecord:
    event_id: str
    attendee: str
    status: str
    seq: int
    digest: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "attendee": self.attendee,
            "status": self.status,
            "seq": self.seq,
            "digest": self.digest,
        }


@dataclass(frozen=True)
class CalendarAuditEvent:
    kind: str
    seq: int
    detail: Mapping[str, Any]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "schema": "audit.ndjson/1",
            "module": "calendar-service",
            "version": CALENDAR_SERVICE_VERSION,
            "kind": self.kind,
            "seq": self.seq,
            "detail": dict(self.detail),
        }


# ---------------------------------------------------------------------------
# RRULE subset expansion
# ---------------------------------------------------------------------------


def _parse_rrule(rrule: str) -> Tuple[str, int, int, Optional[int]]:
    """Parse ``FREQ=DAILY|WEEKLY;INTERVAL=n;COUNT=n|UNTIL=n``.

    Returns (freq, interval, count_or_0, until_or_None). Raises
    :class:`BadRRuleError` for anything outside the subset.
    """
    if not isinstance(rrule, str) or not rrule.strip():
        raise BadRRuleError("rrule must be a non-empty string")
    parts: Dict[str, str] = {}
    for token in rrule.strip().split(";"):
        if "=" not in token:
            raise BadRRuleError(f"bad rrule token: {token!r}")
        key, _, value = token.partition("=")
        key = key.strip().upper()
        value = value.strip()
        if not key or not value or key in parts:
            raise BadRRuleError(f"bad rrule token: {token!r}")
        parts[key] = value
    freq = parts.get("FREQ", "").upper()
    if freq not in _RRULE_FREQS:
        raise BadRRuleError(f"unsupported FREQ: {freq!r}")
    allowed = {"FREQ", "INTERVAL", "COUNT", "UNTIL"}
    unknown = set(parts) - allowed
    if unknown:
        raise BadRRuleError(f"unsupported rrule keys: {sorted(unknown)}")

    def _pos_int(name: str, default: int) -> int:
        raw = parts.get(name)
        if raw is None:
            return default
        if not re.fullmatch(r"[1-9]\d*", raw):
            raise BadRRuleError(f"bad {name}: {raw!r}")
        return int(raw)

    interval = _pos_int("INTERVAL", 1)
    count = _pos_int("COUNT", 0)
    until: Optional[int] = None
    if "UNTIL" in parts:
        raw = parts["UNTIL"]
        if not re.fullmatch(r"-?\d+", raw):
            raise BadRRuleError(f"bad UNTIL: {raw!r}")
        until = int(raw)
        if abs(until) >= 2**53:
            raise BadRRuleError("UNTIL out of range")
    if "COUNT" in parts and "UNTIL" in parts:
        raise BadRRuleError("COUNT and UNTIL are mutually exclusive")
    if count == 0 and until is None:
        raise BadRRuleError("rrule needs COUNT or UNTIL (unbounded refused)")
    if count > MAX_INSTANCES:
        raise BadRRuleError(f"COUNT exceeds MAX_INSTANCES={MAX_INSTANCES}")
    return freq, interval, count, until


def _expand_rrule(
    rrule: str, start_seq: int, end_seq: int
) -> List[Tuple[int, int]]:
    """Expand the rrule subset into (start, end) instance ranges."""
    freq, interval, count, until = _parse_rrule(rrule)
    duration = end_seq - start_seq
    # One "unit" is 1 seq for DAILY, 7 seqs for WEEKLY (ordinal scale).
    step = interval if freq == "DAILY" else interval * 7
    instances: List[Tuple[int, int]] = []
    n = 0
    while True:
        if count and n >= count:
            break
        s = start_seq + n * step
        if until is not None and s > until:
            break
        instances.append((s, s + duration))
        n += 1
        if len(instances) > MAX_INSTANCES:
            raise BadRRuleError(f"expansion exceeds MAX_INSTANCES={MAX_INSTANCES}")
        if count == 0 and n * step > 10**9:  # UNTIL safety net on the ordinal scale
            break
    return instances


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------


class CalendarService:
    """Deterministic CalDAV-shaped event/freebusy/RSVP ledger."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._calendars: Dict[str, CalendarRecord] = {}
        self._events: Dict[str, EventRecord] = {}
        self._uid_index: Dict[str, str] = {}  # uid -> event_id
        self._rsvps: Dict[Tuple[str, str], RSVPRecord] = {}  # (event_id, attendee)
        self._cal_seq = 0
        self._ev_seq = 0
        self._last_seq = -1
        self._audit: List[CalendarAuditEvent] = []

    # -- internal ------------------------------------------------------

    def _next_seq(self, seq: int) -> int:
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError("caller seqs must strictly increase")
        self._last_seq = seq
        return seq

    def _audit_event(self, kind: str, seq: int, detail: Mapping[str, Any]) -> None:
        if kind not in _AUDIT_KINDS:
            raise BadInputError(f"unknown audit kind: {kind!r}")
        self._audit.append(CalendarAuditEvent(kind=kind, seq=seq, detail=dict(detail)))

    def _event_digest(
        self,
        event_id: str,
        calendar_id: str,
        uid: str,
        title: str,
        start_seq: int,
        end_seq: int,
        transparency: str,
        location: str,
        description: str,
        attendees: Tuple[str, ...],
        rrule: Optional[str],
        state: str,
        seq: int,
    ) -> str:
        return _pin(
            "event",
            SCHEMA_PIN,
            event_id,
            calendar_id,
            uid,
            title,
            start_seq,
            end_seq,
            transparency,
            location,
            description,
            list(attendees),
            rrule if rrule is not None else "",
            state,
            seq,
        )

    # -- calendars -----------------------------------------------------

    def create_calendar(
        self, owner: str, name: str, seq: int, calendar_id: Optional[str] = None
    ) -> CalendarRecord:
        owner = _require_id(owner, "owner")
        name = _require_id(name, "name")
        with self._lock:
            seq = self._next_seq(seq)
            if calendar_id is None:
                self._cal_seq += 1
                calendar_id = f"{_CAL_PREFIX}{self._cal_seq}"
            else:
                calendar_id = _require_id(calendar_id, "calendar_id")
            if calendar_id in self._calendars:
                raise DuplicateCalendarError(f"calendar exists: {calendar_id}")
            digest = _pin("calendar", SCHEMA_PIN, calendar_id, owner, name, seq)
            record = CalendarRecord(
                calendar_id=calendar_id, owner=owner, name=name, seq=seq, digest=digest
            )
            self._calendars[calendar_id] = record
            self._audit_event(
                "calendar-created", seq, {"calendar_id": calendar_id, "owner": owner}
            )
            return record

    def calendar(self, calendar_id: str) -> CalendarRecord:
        with self._lock:
            try:
                return self._calendars[calendar_id]
            except KeyError:
                raise UnknownCalendarError(f"unknown calendar: {calendar_id}")

    def calendar_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._calendars))

    # -- events --------------------------------------------------------

    def create(
        self,
        calendar_id: str,
        title: str,
        start_seq: int,
        end_seq: int,
        seq: int,
        *,
        event_id: Optional[str] = None,
        transparency: str = _OPAQUE,
        location: str = "",
        description: str = "",
        attendees: Tuple[str, ...] = (),
        rrule: Optional[str] = None,
        allow_overlap: bool = False,
    ) -> EventRecord:
        calendar_id = _require_id(calendar_id, "calendar_id")
        title = _require_id(title, "title")
        if isinstance(start_seq, bool) or not isinstance(start_seq, int):
            raise BadTimeRangeError("start_seq must be an int")
        if isinstance(end_seq, bool) or not isinstance(end_seq, int):
            raise BadTimeRangeError("end_seq must be an int")
        if start_seq < 0 or end_seq <= start_seq:
            raise BadTimeRangeError("need 0 <= start_seq < end_seq")
        if transparency not in _TRANSPARENCY:
            raise BadInputError(f"bad transparency: {transparency!r}")
        if not isinstance(location, str) or not isinstance(description, str):
            raise BadInputError("location/description must be strings")
        attendee_list = tuple(_require_id(a, "attendee") for a in attendees)
        if len(set(attendee_list)) != len(attendee_list):
            raise BadInputError("duplicate attendees refused")
        if rrule is not None:
            _parse_rrule(rrule)  # validate now, expand lazily per query
        if not isinstance(allow_overlap, bool):
            raise BadInputError("allow_overlap must be a bool")

        with self._lock:
            seq = self._next_seq(seq)
            if calendar_id not in self._calendars:
                raise UnknownCalendarError(f"unknown calendar: {calendar_id}")
            if event_id is None:
                self._ev_seq += 1
                event_id = f"{_EVENT_PREFIX}{self._ev_seq}"
            else:
                event_id = _require_id(event_id, "event_id")
            if event_id in self._events:
                raise DuplicateEventError(f"event exists: {event_id}")

            new_range = TimeRange(start_seq, end_seq)
            if not allow_overlap and transparency == _OPAQUE:
                for existing in self._events.values():
                    if (
                        existing.calendar_id == calendar_id
                        and existing.state == _STATE_ACTIVE
                        and existing.transparency == _OPAQUE
                    ):
                        if existing.time_range().overlaps(new_range):
                            raise OverlapError(
                                f"overlaps {existing.event_id} "
                                f"[{existing.start_seq},{existing.end_seq})"
                            )
                        if existing.rrule is not None:
                            for s, e in _expand_rrule(
                                existing.rrule, existing.start_seq, existing.end_seq
                            ):
                                if TimeRange(s, e).overlaps(new_range):
                                    raise OverlapError(
                                        f"overlaps recurrence of {existing.event_id}"
                                    )

            uid = _pin("uid", calendar_id, title, start_seq, end_seq, event_id)
            if uid in self._uid_index:
                raise DuplicateEventError("uid collision (unreachable in practice)")
            digest = self._event_digest(
                event_id,
                calendar_id,
                uid,
                title,
                start_seq,
                end_seq,
                transparency,
                location,
                description,
                attendee_list,
                rrule,
                _STATE_ACTIVE,
                seq,
            )
            record = EventRecord(
                event_id=event_id,
                calendar_id=calendar_id,
                uid=uid,
                title=title,
                start_seq=start_seq,
                end_seq=end_seq,
                transparency=transparency,
                location=location,
                description=description,
                attendees=attendee_list,
                rrule=rrule,
                state=_STATE_ACTIVE,
                seq=seq,
                digest=digest,
            )
            self._events[event_id] = record
            self._uid_index[uid] = event_id
            self._audit_event(
                "event-created",
                seq,
                {"event_id": event_id, "calendar_id": calendar_id, "uid": uid},
            )
            return record

    def event(self, event_id: str) -> EventRecord:
        with self._lock:
            try:
                return self._events[event_id]
            except KeyError:
                raise UnknownEventError(f"unknown event: {event_id}")

    def events(
        self, calendar_id: Optional[str] = None, include_cancelled: bool = False
    ) -> Tuple[EventRecord, ...]:
        with self._lock:
            records = list(self._events.values())
            if calendar_id is not None:
                if calendar_id not in self._calendars:
                    raise UnknownCalendarError(f"unknown calendar: {calendar_id}")
                records = [r for r in records if r.calendar_id == calendar_id]
            if not include_cancelled:
                records = [r for r in records if r.state == _STATE_ACTIVE]
            records.sort(key=lambda r: (r.start_seq, r.event_id))
            return tuple(records)

    def update(
        self,
        event_id: str,
        seq: int,
        *,
        title: Optional[str] = None,
        start_seq: Optional[int] = None,
        end_seq: Optional[int] = None,
        location: Optional[str] = None,
        description: Optional[str] = None,
        transparency: Optional[str] = None,
        attendees: Optional[Tuple[str, ...]] = None,
        allow_overlap: bool = False,
    ) -> EventRecord:
        event_id = _require_id(event_id, "event_id")
        with self._lock:
            seq = self._next_seq(seq)
            try:
                current = self._events[event_id]
            except KeyError:
                raise UnknownEventError(f"unknown event: {event_id}")
            if current.state == _STATE_CANCELLED:
                raise EventCancelledError(f"event cancelled: {event_id}")

            new_title = current.title if title is None else _require_id(title, "title")
            new_start = current.start_seq if start_seq is None else start_seq
            new_end = current.end_seq if end_seq is None else end_seq
            if isinstance(new_start, bool) or not isinstance(new_start, int):
                raise BadTimeRangeError("start_seq must be an int")
            if isinstance(new_end, bool) or not isinstance(new_end, int):
                raise BadTimeRangeError("end_seq must be an int")
            if new_start < 0 or new_end <= new_start:
                raise BadTimeRangeError("need 0 <= start_seq < end_seq")
            new_location = (
                current.location if location is None else location
            )
            new_description = (
                current.description if description is None else description
            )
            if not isinstance(new_location, str) or not isinstance(new_description, str):
                raise BadInputError("location/description must be strings")
            new_transparency = (
                current.transparency if transparency is None else transparency
            )
            if new_transparency not in _TRANSPARENCY:
                raise BadInputError(f"bad transparency: {transparency!r}")
            new_attendees = (
                current.attendees
                if attendees is None
                else tuple(_require_id(a, "attendee") for a in attendees)
            )
            if len(set(new_attendees)) != len(new_attendees):
                raise BadInputError("duplicate attendees refused")
            if not isinstance(allow_overlap, bool):
                raise BadInputError("allow_overlap must be a bool")

            new_range = TimeRange(new_start, new_end)
            if not allow_overlap and new_transparency == _OPAQUE:
                for other in self._events.values():
                    if (
                        other.event_id == event_id
                        or other.calendar_id != current.calendar_id
                        or other.state != _STATE_ACTIVE
                        or other.transparency != _OPAQUE
                    ):
                        continue
                    if other.time_range().overlaps(new_range):
                        raise OverlapError(f"overlaps {other.event_id}")

            digest = self._event_digest(
                event_id,
                current.calendar_id,
                current.uid,
                new_title,
                new_start,
                new_end,
                new_transparency,
                new_location,
                new_description,
                new_attendees,
                current.rrule,
                _STATE_ACTIVE,
                seq,
            )
            updated = EventRecord(
                event_id=event_id,
                calendar_id=current.calendar_id,
                uid=current.uid,
                title=new_title,
                start_seq=new_start,
                end_seq=new_end,
                transparency=new_transparency,
                location=new_location,
                description=new_description,
                attendees=new_attendees,
                rrule=current.rrule,
                state=_STATE_ACTIVE,
                seq=seq,
                digest=digest,
            )
            self._events[event_id] = updated
            self._audit_event("event-updated", seq, {"event_id": event_id})
            return updated

    def cancel(self, event_id: str, seq: int) -> EventRecord:
        event_id = _require_id(event_id, "event_id")
        with self._lock:
            seq = self._next_seq(seq)
            try:
                current = self._events[event_id]
            except KeyError:
                raise UnknownEventError(f"unknown event: {event_id}")
            if current.state == _STATE_CANCELLED:
                raise EventCancelledError(f"event already cancelled: {event_id}")
            digest = self._event_digest(
                current.event_id,
                current.calendar_id,
                current.uid,
                current.title,
                current.start_seq,
                current.end_seq,
                current.transparency,
                current.location,
                current.description,
                current.attendees,
                current.rrule,
                _STATE_CANCELLED,
                seq,
            )
            cancelled = EventRecord(
                event_id=current.event_id,
                calendar_id=current.calendar_id,
                uid=current.uid,
                title=current.title,
                start_seq=current.start_seq,
                end_seq=current.end_seq,
                transparency=current.transparency,
                location=current.location,
                description=current.description,
                attendees=current.attendees,
                rrule=current.rrule,
                state=_STATE_CANCELLED,
                seq=seq,
                digest=digest,
            )
            self._events[event_id] = cancelled
            self._audit_event("event-cancelled", seq, {"event_id": event_id})
            return cancelled

    # -- freebusy ------------------------------------------------------

    def _busy_ranges_for(
        self, event: EventRecord, window: TimeRange
    ) -> List[BusyRange]:
        out: List[BusyRange] = []
        base = TimeRange(event.start_seq, event.end_seq)
        if event.rrule is None:
            if base.overlaps(window):
                out.append(
                    BusyRange(
                        event_id=event.event_id,
                        start_seq=max(base.start_seq, window.start_seq),
                        end_seq=min(base.end_seq, window.end_seq),
                        title=event.title,
                    )
                )
        else:
            for s, e in _expand_rrule(event.rrule, event.start_seq, event.end_seq):
                inst = TimeRange(s, e)
                if inst.overlaps(window):
                    out.append(
                        BusyRange(
                            event_id=event.event_id,
                            start_seq=max(s, window.start_seq),
                            end_seq=min(e, window.end_seq),
                            title=event.title,
                        )
                    )
        return out

    def freebusy(
        self,
        calendar_ids: Tuple[str, ...],
        start_seq: int,
        end_seq: int,
        seq: int,
    ) -> FreeBusyReport:
        ids = tuple(_require_id(c, "calendar_id") for c in calendar_ids)
        if not ids:
            raise BadInputError("at least one calendar_id required")
        if isinstance(start_seq, bool) or not isinstance(start_seq, int):
            raise BadTimeRangeError("start_seq must be an int")
        if isinstance(end_seq, bool) or not isinstance(end_seq, int):
            raise BadTimeRangeError("end_seq must be an int")
        if start_seq < 0 or end_seq <= start_seq:
            raise BadTimeRangeError("need 0 <= start_seq < end_seq")
        with self._lock:
            seq = self._next_seq(seq)
            for cid in ids:
                if cid not in self._calendars:
                    raise UnknownCalendarError(f"unknown calendar: {cid}")
            window = TimeRange(start_seq, end_seq)
            busy: List[BusyRange] = []
            for event in self._events.values():
                if event.calendar_id not in ids:
                    continue
                if event.state != _STATE_ACTIVE:
                    continue
                if event.transparency == _TRANSPARENT:
                    continue
                busy.extend(self._busy_ranges_for(event, window))
            busy.sort(key=lambda b: (b.start_seq, b.end_seq, b.event_id))
            digest = _pin(
                "freebusy",
                SCHEMA_PIN,
                list(ids),
                start_seq,
                end_seq,
                [(b.event_id, b.start_seq, b.end_seq) for b in busy],
                seq,
            )
            report = FreeBusyReport(
                calendar_ids=ids,
                start_seq=start_seq,
                end_seq=end_seq,
                busy=tuple(busy),
                seq=seq,
                digest=digest,
            )
            self._audit_event(
                "freebusy-queried",
                seq,
                {"calendar_ids": list(ids), "busy_count": len(busy)},
            )
            return report

    # -- rsvp ----------------------------------------------------------

    def rsvp(self, event_id: str, attendee: str, status: str, seq: int) -> RSVPRecord:
        event_id = _require_id(event_id, "event_id")
        attendee = _require_id(attendee, "attendee")
        if status not in _RSVP_STATUSES:
            raise BadRSVPError(f"bad rsvp status: {status!r}")
        with self._lock:
            seq = self._next_seq(seq)
            try:
                event = self._events[event_id]
            except KeyError:
                raise UnknownEventError(f"unknown event: {event_id}")
            if event.state == _STATE_CANCELLED:
                raise EventCancelledError(f"event cancelled: {event_id}")
            if attendee not in event.attendees:
                raise UnknownAttendeeError(
                    f"{attendee} is not an attendee of {event_id}"
                )
            digest = _pin(
                "rsvp", SCHEMA_PIN, event_id, attendee, status, event.uid, seq
            )
            record = RSVPRecord(
                event_id=event_id,
                attendee=attendee,
                status=status,
                seq=seq,
                digest=digest,
            )
            self._rsvps[(event_id, attendee)] = record
            self._audit_event(
                "rsvp-recorded",
                seq,
                {"event_id": event_id, "attendee": attendee, "status": status},
            )
            return record

    def rsvps(self, event_id: str) -> Mapping[str, str]:
        event_id = _require_id(event_id, "event_id")
        with self._lock:
            if event_id not in self._events:
                raise UnknownEventError(f"unknown event: {event_id}")
            out: Dict[str, str] = {}
            for (eid, attendee), record in self._rsvps.items():
                if eid == event_id:
                    out[attendee] = record.status
            return out

    # -- views ---------------------------------------------------------

    def audit_log(self) -> Tuple[CalendarAuditEvent, ...]:
        with self._lock:
            return tuple(self._audit)


def calendar_service_audit_event(
    kind: str, seq: int, detail: Optional[Mapping[str, Any]] = None
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for this module (no event bodies)."""
    if kind not in _AUDIT_KINDS:
        raise BadInputError(f"unknown audit kind: {kind!r}")
    seq = _check_seq(seq)
    return CalendarAuditEvent(
        kind=kind, seq=seq, detail=dict(detail or {})
    ).as_dict()


def main() -> None:
    svc = CalendarService()
    cal = svc.create_calendar("alice", "work", 1)
    e1 = svc.create(cal.calendar_id, "standup", 100, 130, 2, attendees=("bob",))
    svc.rsvp(e1.event_id, "bob", "accepted", 3)
    fb = svc.freebusy((cal.calendar_id,), 0, 200, 4)
    assert not fb.is_free() and len(fb.busy) == 1
    svc.cancel(e1.event_id, 5)
    fb2 = svc.freebusy((cal.calendar_id,), 0, 200, 6)
    assert fb2.is_free()
    print("calendar-service OK: create, rsvp, freebusy, cancel")


if __name__ == "__main__":
    main()
