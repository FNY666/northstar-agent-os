"""Polygon geofence zones and entry/exit event bookkeeping, in-memory.

Research note: a geofence is a virtual perimeter over real-world geography.
The load-bearing production concerns, all kept here:

* **Polygon zones** -- a zone is a closed simple polygon: >=3 distinct
  vertices as ``(lat, lon)`` pairs. The polygon is pinned with a
  ``sha256:`` digest over the canonical vertex list, so a zone cannot be
  silently redefined.
* **Point-in-polygon** -- ray casting (even-odd rule). A point on the
  boundary counts as *inside* (deterministic, fail-closed: a fence that
  flickers at the edge is worse than one that is slightly generous).
* **Entry/exit events** -- ``check()`` with a ``subject_id`` compares the
  new containment against the subject's last observed state for that
  zone and appends an ``entered``/``exited`` event. First observation of
  a subject emits no event (there is no prior state to transition from).
* **Coordinate discipline** -- latitudes in ``[-90, 90]``, longitudes in
  ``[-180, 180]``; ``NaN``/``inf`` refused; bools refused (they are not
  numbers). Floats are the natural type for coordinates and are accepted
  -- unlike the money path in the billing modules, no exact-decimal
  promise is made here; the predicate is deterministic for a given
  (polygon, point) pair.

House style: frozen dataclasses, caller-supplied strictly-increasing int
seqs (no wall-clock), RLock-guarded, fail-closed error taxonomy, stdlib-only,
``audit.ndjson/1`` event shaping, ``main()`` self-check.

Honest scope: this books *reported* positions against *registered*
polygons. ``inside=True`` means "the host-reported coordinate falls
inside the pinned polygon" -- never "the subject is physically there"
(GIGO boundary: a lying GPS feed defeats any geofence).

Version pin: geofence-manager.v1
Schema pin: northstar.geofence-manager.v1
"""

from __future__ import annotations

import hashlib
import math
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Module version.
GEOFENCE_MANAGER_VERSION = "geofence-manager.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.geofence-manager.v1"

#: Coordinate bounds.
MIN_LAT, MAX_LAT = -90.0, 90.0
MIN_LON, MAX_LON = -180.0, 180.0

#: Minimum vertices for a polygon.
MIN_VERTICES = 3

#: Audit kinds for audit.ndjson/1 records.
_AUDIT_KINDS = ("zone-added", "zone-removed", "checked", "entered", "exited", "rejected")


class GeofenceError(Exception):
    """Base error for geofence misuse or constraint violations."""


class UnknownZoneError(GeofenceError):
    """An operation named a zone id that does not exist."""


class DuplicateZoneError(GeofenceError):
    """A zone id was registered twice."""


class InvalidPolygonError(GeofenceError):
    """A polygon failed strict validation."""


class InvalidCoordinateError(GeofenceError):
    """A latitude/longitude failed strict validation."""


class ValidationError(GeofenceError):
    """A field failed fail-closed validation."""


class SeqOrderError(GeofenceError):
    """A caller seq did not strictly increase."""


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise ValidationError("seq must be an int, not bool")
    if seq < 0:
        raise ValidationError("seq must be non-negative")
    return seq


def _check_id(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{what} must be a non-empty str")
    return value.strip()


def _check_coordinate(value: Any, what: str, lo: float, hi: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise InvalidCoordinateError(f"{what} must be a number, not {type(value).__name__}")
    fval = float(value)
    if math.isnan(fval) or math.isinf(fval):
        raise InvalidCoordinateError(f"{what} must be finite")
    if not (lo <= fval <= hi):
        raise InvalidCoordinateError(f"{what} {fval} out of range [{lo}, {hi}]")
    return fval


def _check_polygon(polygon: Any) -> Tuple[Tuple[float, float], ...]:
    """Validate a polygon into a tuple of (lat, lon) float pairs."""
    if not isinstance(polygon, (list, tuple)):
        raise InvalidPolygonError("polygon must be a list/tuple of (lat, lon) pairs")
    verts = list(polygon)
    if len(verts) < MIN_VERTICES:
        raise InvalidPolygonError(f"polygon needs at least {MIN_VERTICES} vertices, got {len(verts)}")
    out: List[Tuple[float, float]] = []
    for i, v in enumerate(verts):
        if not isinstance(v, (list, tuple)) or len(v) != 2:
            raise InvalidPolygonError(f"vertex {i} must be a (lat, lon) pair")
        lat = _check_coordinate(v[0], f"vertex {i} lat", MIN_LAT, MAX_LAT)
        lon = _check_coordinate(v[1], f"vertex {i} lon", MIN_LON, MAX_LON)
        if out and (lat, lon) == out[-1]:
            raise InvalidPolygonError(f"vertex {i} duplicates the previous vertex")
        out.append((lat, lon))
    if out[0] == out[-1]:
        raise InvalidPolygonError("first and last vertices must differ (the ring closes implicitly)")
    return tuple(out)


def _pin(body: Any) -> str:
    digest = hashlib.sha256(jcs_canonical_json(body)).hexdigest()
    return f"sha256:{digest}"


def _on_segment(px: float, py: float, ax: float, ay: float, bx: float, by: float) -> bool:
    """True when point P lies exactly on segment AB (here x=lon, y=lat)."""
    cross = (bx - ax) * (py - ay) - (by - ay) * (px - ax)
    if cross != 0.0:
        return False
    return min(ax, bx) <= px <= max(ax, bx) and min(ay, by) <= py <= max(ay, by)


def _point_in_polygon(lat: float, lon: float,
                      vertices: Tuple[Tuple[float, float], ...]) -> bool:
    """Even-odd ray casting. Points on the boundary count as inside."""
    # x = longitude, y = latitude
    px, py = lon, lat
    inside = False
    n = len(vertices)
    for i in range(n):
        alat, alon = vertices[i]
        blat, blon = vertices[(i + 1) % n]
        ax, ay = alon, alat
        bx, by = blon, blat
        if _on_segment(px, py, ax, ay, bx, by):
            return True
        # Ray to +infinity in x; count crossings of the y-span.
        if (ay > py) != (by > py):
            xinters = (bx - ax) * (py - ay) / (by - ay) + ax
            if px < xinters:
                inside = not inside
    return inside


@dataclass(frozen=True)
class ZoneRecord:
    """A registered polygon zone."""

    zone_id: str
    name: str
    vertices: Tuple[Tuple[float, float], ...]
    pin: str
    seq: int
    version: str = GEOFENCE_MANAGER_VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "zone_id": self.zone_id,
            "name": self.name,
            "vertices": [[lat, lon] for lat, lon in self.vertices],
            "pin": self.pin,
            "seq": self.seq,
            "version": self.version,
        }


@dataclass(frozen=True)
class CheckReport:
    """Result of a containment check."""

    zone_id: str
    subject_id: str
    lat: float
    lon: float
    inside: bool
    transition: str  # "entered" | "exited" | "none"
    pin: str
    seq: int

    def as_dict(self) -> Dict[str, Any]:
        return {
            "zone_id": self.zone_id,
            "subject_id": self.subject_id,
            "lat": self.lat,
            "lon": self.lon,
            "inside": self.inside,
            "transition": self.transition,
            "pin": self.pin,
            "seq": self.seq,
        }


@dataclass(frozen=True)
class ZoneEvent:
    """An entry/exit event appended to the event ledger."""

    event_id: str
    zone_id: str
    subject_id: str
    kind: str  # "entered" | "exited"
    at_seq: int
    pin: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "zone_id": self.zone_id,
            "subject_id": self.subject_id,
            "kind": self.kind,
            "at_seq": self.at_seq,
            "pin": self.pin,
        }


class GeofenceManager:
    """Polygon geofence registry with entry/exit event bookkeeping."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._zones: Dict[str, ZoneRecord] = {}
        self._state: Dict[Tuple[str, str], bool] = {}  # (zone_id, subject_id) -> inside
        self._events: List[ZoneEvent] = []
        self._event_n = 0
        self._last_seq = -1

    def _next_seq(self, seq: int) -> int:
        seq = _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(f"seq {seq} must exceed last seq {self._last_seq}")
        self._last_seq = seq
        return seq

    def add_zone(self, zone_id: str, polygon: Any, seq: int,
                 name: Optional[str] = None) -> ZoneRecord:
        """Register a polygon zone. Duplicate ids are refused fail-closed."""
        zone_id = _check_id(zone_id, "zone_id")
        vertices = _check_polygon(polygon)
        if name is not None and (not isinstance(name, str) or not name.strip()):
            raise ValidationError("name must be a non-empty str when given")
        with self._lock:
            seq = self._next_seq(seq)
            if zone_id in self._zones:
                raise DuplicateZoneError(f"zone {zone_id!r} already registered")
            pin = _pin({
                "zone_id": zone_id,
                "vertices": [[lat, lon] for lat, lon in vertices],
            })
            record = ZoneRecord(
                zone_id=zone_id,
                name=name.strip() if name else zone_id,
                vertices=vertices,
                pin=pin,
                seq=seq,
            )
            self._zones[zone_id] = record
            return record

    def remove_zone(self, zone_id: str, seq: int) -> ZoneRecord:
        """Remove a zone; its subject states are dropped (no retroactive events)."""
        zone_id = _check_id(zone_id, "zone_id")
        with self._lock:
            seq = self._next_seq(seq)
            try:
                record = self._zones.pop(zone_id)
            except KeyError:
                raise UnknownZoneError(f"unknown zone {zone_id!r}") from None
            for key in [k for k in self._state if k[0] == zone_id]:
                del self._state[key]
            return record

    def check(self, zone_id: str, subject_id: str, lat: Any, lon: Any,
              seq: int) -> CheckReport:
        """Test a subject's reported position against a zone.

        Compares against the subject's last observed state for this zone and
        emits an ``entered``/``exited`` event on transition. The first
        observation of a subject emits no event (``transition="none"``).
        """
        zone_id = _check_id(zone_id, "zone_id")
        subject_id = _check_id(subject_id, "subject_id")
        plat = _check_coordinate(lat, "lat", MIN_LAT, MAX_LAT)
        plon = _check_coordinate(lon, "lon", MIN_LON, MAX_LON)
        with self._lock:
            seq = self._next_seq(seq)
            try:
                zone = self._zones[zone_id]
            except KeyError:
                raise UnknownZoneError(f"unknown zone {zone_id!r}") from None
            inside = _point_in_polygon(plat, plon, zone.vertices)
            key = (zone_id, subject_id)
            prior = self._state.get(key)
            self._state[key] = inside
            transition = "none"
            if prior is not None and prior != inside:
                transition = "entered" if inside else "exited"
                self._event_n += 1
                self._events.append(ZoneEvent(
                    event_id=f"ev-{self._event_n}",
                    zone_id=zone_id,
                    subject_id=subject_id,
                    kind=transition,
                    at_seq=seq,
                    pin=_pin({
                        "event_n": self._event_n,
                        "zone_id": zone_id,
                        "subject_id": subject_id,
                        "kind": transition,
                        "at_seq": seq,
                        "zone_pin": zone.pin,
                    }),
                ))
            return CheckReport(
                zone_id=zone_id,
                subject_id=subject_id,
                lat=plat,
                lon=plon,
                inside=inside,
                transition=transition,
                pin=_pin({
                    "zone_id": zone_id,
                    "subject_id": subject_id,
                    "lat": plat,
                    "lon": plon,
                    "inside": inside,
                    "transition": transition,
                    "zone_pin": zone.pin,
                    "seq": seq,
                }),
                seq=seq,
            )

    def events(self, zone_id: Optional[str] = None,
               subject_id: Optional[str] = None) -> Tuple[ZoneEvent, ...]:
        """View the event ledger, optionally filtered. Oldest first."""
        with self._lock:
            out = self._events
            if zone_id is not None:
                zone_id = _check_id(zone_id, "zone_id")
                out = [e for e in out if e.zone_id == zone_id]
            if subject_id is not None:
                subject_id = _check_id(subject_id, "subject_id")
                out = [e for e in out if e.subject_id == subject_id]
            return tuple(out)

    def zones(self) -> Tuple[ZoneRecord, ...]:
        """View all registered zones, sorted by zone id."""
        with self._lock:
            return tuple(sorted(self._zones.values(), key=lambda z: z.zone_id))

    def zone(self, zone_id: str) -> ZoneRecord:
        """Look up one zone."""
        zone_id = _check_id(zone_id, "zone_id")
        with self._lock:
            try:
                return self._zones[zone_id]
            except KeyError:
                raise UnknownZoneError(f"unknown zone {zone_id!r}") from None


def geofence_manager_audit_event(kind: str, seq: int,
                                 detail: Mapping[str, Any]) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for this module."""
    _check_seq(seq)
    if kind not in _AUDIT_KINDS:
        raise ValidationError(f"unknown audit kind {kind!r}")
    if not isinstance(detail, Mapping):
        raise ValidationError("detail must be a mapping")
    return {
        "kind": kind,
        "seq": seq,
        "detail": dict(detail),
        "version": GEOFENCE_MANAGER_VERSION,
        "schema": SCHEMA_PIN,
    }


def main() -> None:
    m = GeofenceManager()
    # A unit square around (0, 0): lat/lon in [-1, 1].
    square = [(-1.0, -1.0), (-1.0, 1.0), (1.0, 1.0), (1.0, -1.0)]
    z = m.add_zone("hq", square, 0, name="HQ")
    assert z.pin.startswith("sha256:")
    r1 = m.check("hq", "van-1", 0.0, 0.0, 1)
    assert r1.inside and r1.transition == "none", r1
    r2 = m.check("hq", "van-1", 5.0, 5.0, 2)
    assert not r2.inside and r2.transition == "exited", r2
    evs = m.events()
    assert len(evs) == 1 and evs[0].kind == "exited" and evs[0].event_id == "ev-1"
    r3 = m.check("hq", "van-1", 0.5, 0.5, 3)
    assert r3.inside and r3.transition == "entered", r3
    assert len(m.events()) == 2
    assert geofence_manager_audit_event("entered", 4, {"zone_id": "hq"})["schema"] == SCHEMA_PIN
    print("geofence-manager OK: zones, point-in-polygon, enter/exit events, audit")


if __name__ == "__main__":
    main()
