"""Status page — Statuspage.io-shaped incident bookkeeping (batch-34 interface).

Research note (status-page literature): Statuspage.io and its peers
(status.io, Cachet, Atlassian Statuspage) model service health as
*components* with pinned statuses (operational / degraded /
partial-outage / major-outage / maintenance), *incidents* opened
against one or more components with a declared impact (none / minor
/ major / critical), and an *update feed* of host-authored status
changes (investigating -> identified -> monitoring -> resolved).
The page-level status is a deterministic aggregate: the worst
component status wins. This module takes the intersection for a
single-host deterministic ledger:

* **Components, not probes**: ``component`` registers a named
  service component; ``set_status`` books a host-reported status
  change with a hash-chained history. Statuses are GIGO — the module
  cannot verify the host's claim.
* **Incidents as data**: ``incident`` opens an incident in
  ``investigating`` status; ``update`` appends host-authored updates
  (message text lives in the record); ``resolve`` is terminal — a
  resolved incident cannot be updated again.
* **Aggregate as a view**: ``page_status`` is a pure read view over
  the component ledger returning the worst status as data.

House rules: frozen dataclasses, caller-supplied strictly-increasing
int seqs on mutations (failed mutations consume their seq; bool/
negative/rewind refused), RLock-guarded, fail-closed taxonomy,
stdlib-only (``canonical_json`` sibling helper behind the standard
try/except fallback), HMAC ``sha256:`` digest pins, ``audit.ndjson/1``
events. Raw update *message text* never crosses the audit boundary
(ids + digest pins + statuses only; messages may carry operator PII).

Honest boundary: this module books *declared* component health and
incident narratives deterministically. It performs no probing,
cannot observe wire truth, cannot notify subscribers, and cannot
prove an incident actually occurred — the host declares every
status and every update. A ``resolved`` record means the host said
so, never that the outage ended.
"""

from __future__ import annotations

import hashlib
import hmac
import threading
from dataclasses import dataclass
from typing import Any, Mapping

try:  # stdlib-first; canonical_json is the sibling JCS helper
    import canonical_json as _cj  # type: ignore
except Exception:  # pragma: no cover - fallback keeps stdlib-only promise
    _cj = None  # type: ignore

#: Version pin for this module's record shape.
STATUS_PAGE_VERSION = "status-page.v1"

#: Schema pin carried by records and audit events.
STATUS_PAGE_SCHEMA = "northstar.status-page.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Pinned component statuses (Statuspage.io vocabulary; drift detectable).
STATUS_OPERATIONAL = "operational"
STATUS_DEGRADED = "degraded"
STATUS_PARTIAL_OUTAGE = "partial-outage"
STATUS_MAJOR_OUTAGE = "major-outage"
STATUS_MAINTENANCE = "maintenance"
COMPONENT_STATUSES = (
    STATUS_OPERATIONAL,
    STATUS_DEGRADED,
    STATUS_PARTIAL_OUTAGE,
    STATUS_MAJOR_OUTAGE,
    STATUS_MAINTENANCE,
)

#: Page-aggregate ordering: first match in this tuple wins.
_AGGREGATE_ORDER = (
    STATUS_MAJOR_OUTAGE,
    STATUS_PARTIAL_OUTAGE,
    STATUS_DEGRADED,
    STATUS_MAINTENANCE,
    STATUS_OPERATIONAL,
)

#: Pinned incident impact levels (Statuspage.io vocabulary).
IMPACT_NONE = "none"
IMPACT_MINOR = "minor"
IMPACT_MAJOR = "major"
IMPACT_CRITICAL = "critical"
IMPACTS = (IMPACT_NONE, IMPACT_MINOR, IMPACT_MAJOR, IMPACT_CRITICAL)

#: Pinned incident lifecycle statuses.
INCIDENT_INVESTIGATING = "investigating"
INCIDENT_IDENTIFIED = "identified"
INCIDENT_MONITORING = "monitoring"
INCIDENT_RESOLVED = "resolved"
INCIDENT_STATUSES = (
    INCIDENT_INVESTIGATING,
    INCIDENT_IDENTIFIED,
    INCIDENT_MONITORING,
    INCIDENT_RESOLVED,
)

#: Statuses allowed on ``update()`` (resolution goes through ``resolve()``).
UPDATABLE_STATUSES = (
    INCIDENT_INVESTIGATING,
    INCIDENT_IDENTIFIED,
    INCIDENT_MONITORING,
)

#: Audit event kinds.
KIND_COMPONENT_REGISTERED = "status.component-registered"
KIND_COMPONENT_STATUS_SET = "status.component-status-set"
KIND_INCIDENT_CREATED = "status.incident-created"
KIND_INCIDENT_UPDATED = "status.incident-updated"
KIND_INCIDENT_RESOLVED = "status.incident-resolved"
KIND_REJECTED = "status.rejected"
_KINDS = (
    KIND_COMPONENT_REGISTERED,
    KIND_COMPONENT_STATUS_SET,
    KIND_INCIDENT_CREATED,
    KIND_INCIDENT_UPDATED,
    KIND_INCIDENT_RESOLVED,
    KIND_REJECTED,
)

_GENESIS = "genesis"
_DIGEST_PREFIX = "sha256:"
_MAX_ID_LEN = 128
_MAX_TEXT_LEN = 4096


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class StatusPageError(ValueError):
    """Base error for the status page."""


class BadComponentError(StatusPageError):
    """Malformed component definition (bad id, name, status)."""


class DuplicateComponentError(StatusPageError):
    """A component with this id is already registered."""


class UnknownComponentError(StatusPageError):
    """No component with this id is registered."""


class BadStatusError(StatusPageError):
    """A status is not in the pinned vocabulary."""


class BadIncidentError(StatusPageError):
    """Malformed incident (bad id, title, impact, components)."""


class DuplicateIncidentError(StatusPageError):
    """An incident with this id already exists."""


class UnknownIncidentError(StatusPageError):
    """No incident with this id exists."""


class BadUpdateError(StatusPageError):
    """Malformed incident update (bad status, message)."""


class AlreadyResolvedError(StatusPageError):
    """The incident is resolved; it can no longer be updated."""


class SeqOrderError(StatusPageError):
    """Seq did not strictly increase."""


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _check_seq(value: Any, field_name: str = "seq") -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise StatusPageError(f"{field_name} must be a non-negative int")
    return value


def _check_nonempty_str(value: Any, field_name: str, max_len: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise StatusPageError(f"{field_name} must be a non-empty string")
    value = value.strip()
    if len(value) > max_len:
        raise StatusPageError(f"{field_name} must be at most {max_len} chars")
    return value


def _check_id(value: Any, field_name: str) -> str:
    value = _check_nonempty_str(value, field_name, _MAX_ID_LEN)
    if any(ch.isspace() for ch in value):
        raise StatusPageError(f"{field_name} must not contain whitespace")
    return value


def _canonical(payload: Any) -> bytes:
    if _cj is not None:
        return _cj.jcs_dumps(payload).encode("utf-8")  # type: ignore
    import json

    def _tag(v: Any) -> Any:
        if isinstance(v, bool):
            return {"t": "bool", "v": v}
        if isinstance(v, int):
            if abs(v) >= 2**53:
                raise StatusPageError("integer outside safe range")
            return {"t": "int", "v": v}
        if isinstance(v, float):
            if v != v or v in (float("inf"), float("-inf")):
                raise StatusPageError("non-finite float refused")
            return {"t": "float", "v": repr(v)}
        if isinstance(v, str):
            return {"t": "str", "v": v}
        if isinstance(v, (list, tuple)):
            return {"t": "list", "v": [_tag(i) for i in v]}
        if isinstance(v, dict):
            return {"t": "dict", "v": [[k, _tag(v[k])] for k in sorted(v)]}
        if v is None:
            return {"t": "null"}
        raise StatusPageError(f"unencodable type: {type(v).__name__}")

    return json.dumps(
        _tag(payload), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _pin(payload: Any, seed: str = "") -> str:
    return _DIGEST_PREFIX + hmac.new(
        seed.encode("utf-8"), _canonical(payload), hashlib.sha256
    ).hexdigest()


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ComponentRecord:
    """A pinned service component with its current status."""

    component_id: str
    name: str
    status: str
    group: str
    seq: int
    digest: str

    def verify(self, seed: str = "") -> bool:
        return hmac.compare_digest(
            self.digest,
            _pin(
                [
                    "component",
                    self.component_id,
                    self.name,
                    self.status,
                    self.group,
                    self.seq,
                ],
                seed,
            ),
        )


@dataclass(frozen=True)
class StatusChangeRecord:
    """One hash-chained component status change (history entry)."""

    change_id: str
    component_id: str
    old_status: str
    new_status: str
    seq: int
    prev_digest: str
    digest: str

    def verify(self, seed: str = "") -> bool:
        return hmac.compare_digest(
            self.digest,
            _pin(
                [
                    "status-change",
                    self.change_id,
                    self.component_id,
                    self.old_status,
                    self.new_status,
                    self.seq,
                    self.prev_digest,
                ],
                seed,
            ),
        )


@dataclass(frozen=True)
class IncidentRecord:
    """A pinned incident opened against one or more components."""

    incident_id: str
    title: str
    impact: str
    status: str
    component_ids: tuple
    seq: int
    digest: str

    def verify(self, seed: str = "") -> bool:
        return hmac.compare_digest(
            self.digest,
            _pin(
                [
                    "incident",
                    self.incident_id,
                    self.title,
                    self.impact,
                    self.status,
                    sorted(self.component_ids),
                    self.seq,
                ],
                seed,
            ),
        )


@dataclass(frozen=True)
class IncidentUpdate:
    """One host-authored incident update (hash-chained)."""

    update_id: str
    incident_id: str
    status: str
    message: str
    seq: int
    prev_digest: str
    digest: str

    def verify(self, seed: str = "") -> bool:
        return hmac.compare_digest(
            self.digest,
            _pin(
                [
                    "incident-update",
                    self.update_id,
                    self.incident_id,
                    self.status,
                    self.message,
                    self.seq,
                    self.prev_digest,
                ],
                seed,
            ),
        )


@dataclass(frozen=True)
class IncidentResolution:
    """The terminal resolution of an incident (one-way)."""

    resolution_id: str
    incident_id: str
    message: str
    seq: int
    digest: str

    def verify(self, seed: str = "") -> bool:
        return hmac.compare_digest(
            self.digest,
            _pin(
                [
                    "incident-resolution",
                    self.resolution_id,
                    self.incident_id,
                    self.message,
                    self.seq,
                ],
                seed,
            ),
        )


@dataclass(frozen=True)
class PageStatus:
    """A pure page-level aggregate view (data, never raised)."""

    overall: str
    counts: tuple  # ((status, count), ...) sorted by _AGGREGATE_ORDER
    component_count: int
    open_incidents: int
    seq: int
    digest: str

    def verify(self, seed: str = "") -> bool:
        return hmac.compare_digest(
            self.digest,
            _pin(
                [
                    "page-status",
                    self.overall,
                    [list(c) for c in self.counts],
                    self.component_count,
                    self.open_incidents,
                    self.seq,
                ],
                seed,
            ),
        )


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------


def status_page_audit_event(
    kind: str, seq: int, **detail: Any
) -> Mapping[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the status page.

    Update message text is banned here: ``status.message`` in the
    detail mapping raises — messages may carry operator PII and live
    only in module records, never in the audit feed.
    """
    if kind not in _KINDS:
        raise StatusPageError(f"unknown audit kind: {kind!r}")
    _check_seq(seq, "seq")
    if "message" in detail:
        raise StatusPageError("update message text must not cross the audit boundary")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": "status_page",
        "module_version": STATUS_PAGE_VERSION,
        "seq": seq,
        "detail": dict(detail),
    }


# ---------------------------------------------------------------------------
# StatusPage
# ---------------------------------------------------------------------------


class StatusPage:
    """Deterministic Statuspage.io-shaped incident bookkeeping.

    All mutations require a caller-supplied strictly increasing ``seq``.
    Failed mutations consume their seq (ledger position stays total).
    Reads (``page_status``, lookups) validate the seq shape but do not
    consume it and write no audit rows.
    """

    def __init__(self, seed: str = "") -> None:
        self._lock = threading.RLock()
        self._seed = seed
        self._last_seq = -1
        self._components: dict[str, ComponentRecord] = {}
        self._changes: list[StatusChangeRecord] = []
        self._last_change_digest = _GENESIS
        self._incidents: dict[str, IncidentRecord] = {}
        self._updates: dict[str, list[IncidentUpdate]] = {}
        self._resolutions: dict[str, IncidentResolution] = {}
        self._change_n = 0
        self._update_n = 0
        self._resolution_n = 0
        self._audit_log: list[Mapping[str, Any]] = []

    # -- internal ------------------------------------------------------

    def _next_seq(self, seq: int) -> int:
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must strictly increase (last={self._last_seq}, got={seq})"
            )
        self._last_seq = seq
        return seq

    def _emit(self, kind: str, seq: int, **detail: Any) -> None:
        self._audit_log.append(status_page_audit_event(kind, seq, **detail))

    def _reject(self, seq: int, reason: str) -> None:
        # Seq already consumed by _next_seq; only book the refusal.
        self._emit(KIND_REJECTED, seq, reason=reason)

    def _get_incident(self, incident_id: str) -> IncidentRecord:
        try:
            return self._incidents[incident_id]
        except KeyError:
            raise UnknownIncidentError(f"unknown incident: {incident_id!r}")

    # -- components ----------------------------------------------------

    def component(
        self,
        component_id: str,
        name: str,
        seq: int,
        group: str = "",
    ) -> ComponentRecord:
        """Register a component (starts ``operational``)."""
        with self._lock:
            seq = self._next_seq(seq)
            try:
                component_id = _check_id(component_id, "component_id")
                name = _check_nonempty_str(name, "name", _MAX_TEXT_LEN)
                if not isinstance(group, str):
                    raise BadComponentError("group must be a string")
                group = group.strip()
                if component_id in self._components:
                    raise DuplicateComponentError(
                        f"component already registered: {component_id!r}"
                    )
            except StatusPageError as exc:
                self._reject(seq, str(exc))
                raise
            rec = ComponentRecord(
                component_id=component_id,
                name=name,
                status=STATUS_OPERATIONAL,
                group=group,
                seq=seq,
                digest=_pin(
                    [
                        "component",
                        component_id,
                        name,
                        STATUS_OPERATIONAL,
                        group,
                        seq,
                    ],
                    self._seed,
                ),
            )
            self._components[component_id] = rec
            self._emit(
                KIND_COMPONENT_REGISTERED,
                seq,
                component_id=component_id,
                status=STATUS_OPERATIONAL,
            )
            return rec

    def set_status(
        self, component_id: str, status: str, seq: int
    ) -> StatusChangeRecord:
        """Book a host-reported component status change."""
        with self._lock:
            seq = self._next_seq(seq)
            try:
                if status not in COMPONENT_STATUSES:
                    raise BadStatusError(f"unknown component status: {status!r}")
                try:
                    current = self._components[component_id]
                except KeyError:
                    raise UnknownComponentError(
                        f"unknown component: {component_id!r}"
                    )
            except StatusPageError as exc:
                self._reject(seq, str(exc))
                raise
            self._change_n += 1
            change = StatusChangeRecord(
                change_id=f"chg-{self._change_n}",
                component_id=component_id,
                old_status=current.status,
                new_status=status,
                seq=seq,
                prev_digest=self._last_change_digest,
                digest=_pin(
                    [
                        "status-change",
                        f"chg-{self._change_n}",
                        component_id,
                        current.status,
                        status,
                        seq,
                        self._last_change_digest,
                    ],
                    self._seed,
                ),
            )
            self._last_change_digest = change.digest
            self._changes.append(change)
            self._components[component_id] = ComponentRecord(
                component_id=current.component_id,
                name=current.name,
                status=status,
                group=current.group,
                seq=seq,
                digest=_pin(
                    [
                        "component",
                        current.component_id,
                        current.name,
                        status,
                        current.group,
                        seq,
                    ],
                    self._seed,
                ),
            )
            self._emit(
                KIND_COMPONENT_STATUS_SET,
                seq,
                component_id=component_id,
                old_status=change.old_status,
                new_status=status,
            )
            return change

    # -- incidents -----------------------------------------------------

    def incident(
        self,
        incident_id: str,
        title: str,
        seq: int,
        component_ids: Any = (),
        impact: str = IMPACT_MINOR,
    ) -> IncidentRecord:
        """Open an incident (status ``investigating``)."""
        with self._lock:
            seq = self._next_seq(seq)
            try:
                incident_id = _check_id(incident_id, "incident_id")
                title = _check_nonempty_str(title, "title", _MAX_TEXT_LEN)
                if impact not in IMPACTS:
                    raise BadIncidentError(f"unknown impact: {impact!r}")
                if not isinstance(component_ids, (list, tuple)):
                    raise BadIncidentError("component_ids must be a list or tuple")
                component_ids = tuple(
                    _check_id(c, "component_id") for c in component_ids
                )
                if len(set(component_ids)) != len(component_ids):
                    raise BadIncidentError("duplicate component ids")
                unknown = [
                    c for c in component_ids if c not in self._components
                ]
                if unknown:
                    raise BadIncidentError(
                        f"unknown components: {', '.join(unknown)}"
                    )
                if incident_id in self._incidents:
                    raise DuplicateIncidentError(
                        f"incident already exists: {incident_id!r}"
                    )
            except StatusPageError as exc:
                self._reject(seq, str(exc))
                raise
            rec = IncidentRecord(
                incident_id=incident_id,
                title=title,
                impact=impact,
                status=INCIDENT_INVESTIGATING,
                component_ids=component_ids,
                seq=seq,
                digest=_pin(
                    [
                        "incident",
                        incident_id,
                        title,
                        impact,
                        INCIDENT_INVESTIGATING,
                        sorted(component_ids),
                        seq,
                    ],
                    self._seed,
                ),
            )
            self._incidents[incident_id] = rec
            self._updates[incident_id] = []
            self._emit(
                KIND_INCIDENT_CREATED,
                seq,
                incident_id=incident_id,
                impact=impact,
                component_ids=sorted(component_ids),
            )
            return rec

    def update(
        self, incident_id: str, status: str, message: str, seq: int
    ) -> IncidentUpdate:
        """Append a host-authored incident update."""
        with self._lock:
            seq = self._next_seq(seq)
            try:
                inc = self._get_incident(incident_id)
                if inc.status == INCIDENT_RESOLVED:
                    raise AlreadyResolvedError(
                        f"incident already resolved: {incident_id!r}"
                    )
                if status not in UPDATABLE_STATUSES:
                    raise BadUpdateError(
                        f"status must be one of {UPDATABLE_STATUSES}, got {status!r}"
                    )
                message = _check_nonempty_str(message, "message", _MAX_TEXT_LEN)
            except StatusPageError as exc:
                self._reject(seq, str(exc))
                raise
            prev = self._updates[incident_id][-1].digest if self._updates[
                incident_id
            ] else _GENESIS
            self._update_n += 1
            upd = IncidentUpdate(
                update_id=f"upd-{self._update_n}",
                incident_id=incident_id,
                status=status,
                message=message,
                seq=seq,
                prev_digest=prev,
                digest=_pin(
                    [
                        "incident-update",
                        f"upd-{self._update_n}",
                        incident_id,
                        status,
                        message,
                        seq,
                        prev,
                    ],
                    self._seed,
                ),
            )
            self._updates[incident_id].append(upd)
            self._incidents[incident_id] = IncidentRecord(
                incident_id=inc.incident_id,
                title=inc.title,
                impact=inc.impact,
                status=status,
                component_ids=inc.component_ids,
                seq=seq,
                digest=_pin(
                    [
                        "incident",
                        inc.incident_id,
                        inc.title,
                        inc.impact,
                        status,
                        sorted(inc.component_ids),
                        seq,
                    ],
                    self._seed,
                ),
            )
            self._emit(
                KIND_INCIDENT_UPDATED,
                seq,
                incident_id=incident_id,
                status=status,
                update_id=upd.update_id,
            )
            return upd

    def resolve(
        self, incident_id: str, message: str, seq: int
    ) -> IncidentResolution:
        """Resolve an incident (terminal; no further updates allowed)."""
        with self._lock:
            seq = self._next_seq(seq)
            try:
                inc = self._get_incident(incident_id)
                if inc.status == INCIDENT_RESOLVED:
                    raise AlreadyResolvedError(
                        f"incident already resolved: {incident_id!r}"
                    )
                message = _check_nonempty_str(message, "message", _MAX_TEXT_LEN)
            except StatusPageError as exc:
                self._reject(seq, str(exc))
                raise
            self._resolution_n += 1
            res = IncidentResolution(
                resolution_id=f"res-{self._resolution_n}",
                incident_id=incident_id,
                message=message,
                seq=seq,
                digest=_pin(
                    [
                        "incident-resolution",
                        f"res-{self._resolution_n}",
                        incident_id,
                        message,
                        seq,
                    ],
                    self._seed,
                ),
            )
            self._resolutions[incident_id] = res
            self._incidents[incident_id] = IncidentRecord(
                incident_id=inc.incident_id,
                title=inc.title,
                impact=inc.impact,
                status=INCIDENT_RESOLVED,
                component_ids=inc.component_ids,
                seq=seq,
                digest=_pin(
                    [
                        "incident",
                        inc.incident_id,
                        inc.title,
                        inc.impact,
                        INCIDENT_RESOLVED,
                        sorted(inc.component_ids),
                        seq,
                    ],
                    self._seed,
                ),
            )
            self._emit(
                KIND_INCIDENT_RESOLVED,
                seq,
                incident_id=incident_id,
                resolution_id=res.resolution_id,
            )
            return res

    # -- views ---------------------------------------------------------

    def page_status(self, seq: int) -> PageStatus:
        """Pure page-level aggregate view (worst status wins)."""
        with self._lock:
            _check_seq(seq, "seq")
            counts = {s: 0 for s in COMPONENT_STATUSES}
            for rec in self._components.values():
                counts[rec.status] += 1
            overall = STATUS_OPERATIONAL
            for status in _AGGREGATE_ORDER:
                if counts[status]:
                    overall = status
                    break
            open_incidents = sum(
                1
                for inc in self._incidents.values()
                if inc.status != INCIDENT_RESOLVED
            )
            counts_tuple = tuple(
                (s, counts[s]) for s in _AGGREGATE_ORDER
            )
            return PageStatus(
                overall=overall,
                counts=counts_tuple,
                component_count=len(self._components),
                open_incidents=open_incidents,
                seq=seq,
                digest=_pin(
                    [
                        "page-status",
                        overall,
                        [list(c) for c in counts_tuple],
                        len(self._components),
                        open_incidents,
                        seq,
                    ],
                    self._seed,
                ),
            )

    def component_record(self, component_id: str) -> ComponentRecord:
        """Lookup a component record (unknown id raises)."""
        try:
            return self._components[component_id]
        except KeyError:
            raise UnknownComponentError(
                f"unknown component: {component_id!r}"
            )

    def component_ids(self) -> tuple:
        """Sorted component ids."""
        return tuple(sorted(self._components))

    def status_history(self, component_id: str) -> tuple:
        """Hash-chained status changes for one component."""
        self.component_record(component_id)  # raises on unknown
        return tuple(
            c for c in self._changes if c.component_id == component_id
        )

    def incident_record(self, incident_id: str) -> IncidentRecord:
        """Lookup an incident record (unknown id raises)."""
        return self._get_incident(incident_id)

    def incident_ids(self) -> tuple:
        """Sorted incident ids."""
        return tuple(sorted(self._incidents))

    def updates_for(self, incident_id: str) -> tuple:
        """Update feed for one incident (chronological)."""
        self._get_incident(incident_id)
        return tuple(self._updates[incident_id])

    def resolution_for(self, incident_id: str) -> IncidentResolution:
        """The resolution record, or raise if unresolved."""
        try:
            return self._resolutions[incident_id]
        except KeyError:
            raise StatusPageError(f"incident not resolved: {incident_id!r}")

    def audit_log(self) -> tuple:
        """The audit event ledger (read-only)."""
        return tuple(self._audit_log)


def main() -> None:
    page = StatusPage(seed="selfcheck")
    page.component("api", "Public API", 0, group="core")
    chg = page.set_status("api", STATUS_PARTIAL_OUTAGE, 1)
    assert chg.verify(seed="selfcheck") and chg.old_status == STATUS_OPERATIONAL
    inc = page.incident("inc-1", "API elevated errors", 2, ("api",), IMPACT_MAJOR)
    assert inc.verify(seed="selfcheck") and inc.status == INCIDENT_INVESTIGATING
    upd = page.update("inc-1", INCIDENT_IDENTIFIED, "Bad deploy rolled back", 3)
    assert upd.verify(seed="selfcheck") and upd.update_id == "upd-1"
    res = page.resolve("inc-1", "Errors back to baseline", 4)
    assert res.verify(seed="selfcheck") and res.resolution_id == "res-1"
    view = page.page_status(5)
    assert view.overall == STATUS_PARTIAL_OUTAGE and view.verify(seed="selfcheck")
    print("status-page OK: component, set_status, incident, update, resolve, page_status, pins, audit")


if __name__ == "__main__":
    main()
