"""Timezone resolver interface: lat/lon to IANA zone lookup.

Research note: converting (lat, lon) to an IANA time zone — the basis of
every scheduling, calendar, and "local time" feature — rests on one idea:
*space is partitioned by zone polygons* (the evzone/tzwhere shapefile
lookup, OS location services). The load-bearing behaviors this module
models as deterministic bookkeeping are:

1. **Nearest-anchor resolution** — ``resolve()`` matches (lat, lon)
   against a pinned table of IANA zone anchors (city coordinates) with
   haversine distance, and reports a match tier
   (``exact`` / ``near`` / ``regional``).
2. **Offset table** — ``offset()`` returns a zone's pinned (standard,
   DST) offset pair, in minutes east of UTC.
3. **DST rules** — ``dst()`` returns the zone's pinned DST transition
   rule (nth-weekday-of-month), and ``dst_active()`` evaluates it
   against a caller-supplied (year, month, day) — the host owns the
   clock; this module never touches wall time.

House style: frozen dataclasses, caller-supplied int seqs (strictly
increasing per resolver, no wall-clock, no RNG — record ids are
monotonic ``zr-<n>`` / ``or-<n>`` / ``dr-<n>`` / ``ds-<n>`` counters),
RLock-guarded, fail-closed (bad coordinates, unknown zones, impossible
dates, seq rewinds all raise a subclass of :class:`TimezoneError`),
stdlib-only, type-tagged canonical digest encoding
(``bool != int != str``; NaN/inf refused; |n| > 2**53 refused —
the batch-5 JCS discipline), ``main()`` self-check.

Honest scope: this is *simulated* bookkeeping, not a geodetic
authority. Nearest-anchor is a stand-in for a polygon boundary lookup;
anchors sit at city centers, so border regions may resolve to the
neighboring zone — a ``regional``-tier match is a hint, not a survey
(GIGO, same boundary as every other bookkeeping module). Offsets and
DST rules are pinned snapshots of IANA data; a zone that changes its
DST law needs a table update. Pair with an authoritative tzdata build
for production.
"""

from __future__ import annotations

import hashlib
import json
import math
import threading
from dataclasses import dataclass, field
from datetime import date, timedelta
from typing import Any, Dict, List, Optional, Tuple


#: Module version.
VERSION = "timezone-resolver.v1"

#: Schema pin for records produced by this module.
SCHEMA = "northstar.timezone-resolver.v1"


class TimezoneError(ValueError):
    """Base for all timezone-resolver errors. A malformed request, not a verdict."""


class UnknownZoneError(TimezoneError):
    """Zone name is not in the pinned IANA table."""


class InvalidCoordinateError(TimezoneError):
    """Latitude/longitude failed validation."""


class InvalidDateError(TimezoneError):
    """The supplied (year, month, day) is not a real calendar date."""


class SeqOrderError(TimezoneError):
    """Caller seq was not strictly increasing for this resolver."""


# ---------------------------------------------------------------------------
# Type-tagged canonical digest encoding (batch-5 JCS discipline)
# ---------------------------------------------------------------------------

def _canonical(value: Any) -> str:
    """Encode *value* with explicit type tags so digests distinguish
    ``1`` from ``True`` from ``"1"``. NaN/inf are refused; integral
    magnitudes > 2**53 are refused."""
    if isinstance(value, bool):
        return "bool:" + ("true" if value else "false")
    if isinstance(value, int):
        if abs(value) > 2**53:
            raise TimezoneError("integer magnitude exceeds 2^53 (digest safety)")
        return "int:" + str(value)
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise TimezoneError("NaN/inf cannot be digested")
        if value.is_integer() and abs(value) > 2**53:
            raise TimezoneError("integral float magnitude exceeds 2^53")
        return "float:" + repr(value)
    if isinstance(value, str):
        return "str:" + json.dumps(value, ensure_ascii=False)
    if value is None:
        return "null"
    if isinstance(value, (list, tuple)):
        return "list:[" + ",".join(_canonical(v) for v in value) + "]"
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda kv: str(kv[0]))
        return "dict:{" + ",".join(
            _canonical(k) + "=" + _canonical(v) for k, v in items) + "}"
    raise TimezoneError("non-canonicalizable value: %r" % (type(value).__name__,))


def _digest_pin(*parts: Any) -> str:
    body = "\x1f".join(_canonical(p) for p in parts)
    return "sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest()


def _check_seq(seq: Any, last: int) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError("seq must be an int, got %s" % type(seq).__name__)
    if seq < 0:
        raise SeqOrderError("seq must be non-negative, got %d" % seq)
    if seq <= last:
        raise SeqOrderError("seq must be strictly increasing (last=%d, got=%d)"
                            % (last, seq))
    return seq


# ---------------------------------------------------------------------------
# Pinned IANA zone table
# ---------------------------------------------------------------------------
# Each entry: (iana_name, anchor_lat, anchor_lon, std_offset_min,
#              dst_offset_min, observes_dst, rule_key).
# Anchors are representative city coordinates; offsets are the pinned
# IANA standard/DST offsets (minutes east of UTC).

_US = "us"   # 2nd Sunday of March -> 1st Sunday of November
_EU = "eu"   # last Sunday of March -> last Sunday of October
_AU = "au"   # 1st Sunday of October -> 1st Sunday of April
_NZ = "nz"   # last Sunday of September -> 1st Sunday of April
_EG = "eg"   # last Friday of April -> last Thursday of October

#: Transition rule per rule key: (start, end); each is a dict with
#: month, week (1..4 or -1 for "last"), weekday (Monday=0..Sunday=6).
_RULES: Dict[str, Dict[str, Dict[str, int]]] = {
    _US: {"start": {"month": 3, "week": 2, "weekday": 6},
          "end": {"month": 11, "week": 1, "weekday": 6}},
    _EU: {"start": {"month": 3, "week": -1, "weekday": 6},
          "end": {"month": 10, "week": -1, "weekday": 6}},
    _AU: {"start": {"month": 10, "week": 1, "weekday": 6},
          "end": {"month": 4, "week": 1, "weekday": 6}},
    _NZ: {"start": {"month": 9, "week": -1, "weekday": 6},
          "end": {"month": 4, "week": 1, "weekday": 6}},
    _EG: {"start": {"month": 4, "week": -1, "weekday": 4},
          "end": {"month": 10, "week": -1, "weekday": 3}},
}

_ZONE_ROWS: Tuple[Tuple[Any, ...], ...] = (
    ("UTC", 51.4769, 0.0005, 0, 0, False, None),
    ("America/New_York", 40.7128, -74.0060, -300, -240, True, _US),
    ("America/Chicago", 41.8781, -87.6298, -360, -300, True, _US),
    ("America/Denver", 39.7392, -104.9903, -420, -360, True, _US),
    ("America/Phoenix", 33.4484, -112.0740, -420, -420, False, None),
    ("America/Los_Angeles", 34.0522, -118.2437, -480, -420, True, _US),
    ("America/Anchorage", 61.2181, -149.9003, -540, -480, True, _US),
    ("Pacific/Honolulu", 21.3099, -157.8581, -600, -600, False, None),
    ("America/Toronto", 43.6532, -79.3832, -300, -240, True, _US),
    ("America/Vancouver", 49.2827, -123.1207, -480, -420, True, _US),
    ("America/Mexico_City", 19.4326, -99.1332, -360, -360, False, None),
    ("America/Sao_Paulo", -23.5558, -46.6396, -180, -180, False, None),
    ("America/Buenos_Aires", -34.6037, -58.3816, -180, -180, False, None),
    ("Europe/London", 51.5074, -0.1278, 0, 60, True, _EU),
    ("Europe/Paris", 48.8566, 2.3522, 60, 120, True, _EU),
    ("Europe/Berlin", 52.5200, 13.4050, 60, 120, True, _EU),
    ("Europe/Athens", 37.9838, 23.7275, 120, 180, True, _EU),
    ("Europe/Moscow", 55.7558, 37.6173, 180, 180, False, None),
    ("Africa/Cairo", 30.0444, 31.2357, 120, 180, True, _EG),
    ("Africa/Lagos", 6.5244, 3.3792, 60, 60, False, None),
    ("Africa/Johannesburg", -26.2041, 28.0473, 120, 120, False, None),
    ("Asia/Dubai", 25.2048, 55.2708, 240, 240, False, None),
    ("Asia/Kolkata", 28.6139, 77.2090, 330, 330, False, None),
    ("Asia/Shanghai", 31.2304, 121.4737, 480, 480, False, None),
    ("Asia/Tokyo", 35.6762, 139.6503, 540, 540, False, None),
    ("Asia/Seoul", 37.5665, 126.9780, 540, 540, False, None),
    ("Asia/Singapore", 1.3521, 103.8198, 480, 480, False, None),
    ("Australia/Sydney", -33.8688, 151.2093, 600, 660, True, _AU),
    ("Australia/Perth", -31.9505, 115.8605, 480, 480, False, None),
    ("Pacific/Auckland", -36.8485, 174.7633, 720, 780, True, _NZ),
)


@dataclass(frozen=True)
class _Zone:
    name: str
    anchor_lat: float
    anchor_lon: float
    std_offset_minutes: int
    dst_offset_minutes: int
    observes_dst: bool
    rule_key: Optional[str]


_ZONES: Tuple[_Zone, ...] = tuple(_Zone(*row) for row in _ZONE_ROWS)
_ZONE_BY_NAME: Dict[str, _Zone] = {z.name: z for z in _ZONES}

#: Match tiers for resolve().
TIERS = ("exact", "near", "regional")
_EXACT_KM = 1.0
_NEAR_KM = 150.0


def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    r = 6371.0088
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = (math.sin(dp / 2) ** 2
         + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2)
    return 2 * r * math.asin(math.sqrt(a))


def _nth_weekday(year: int, month: int, weekday: int, week: int) -> date:
    """Return the date of the nth (or last, week=-1) *weekday* in a month."""
    if week > 0:
        first = date(year, month, 1)
        delta = (weekday - first.weekday()) % 7
        return first + timedelta(days=delta + 7 * (week - 1))
    if month == 12:
        last = date(year, 12, 31)
    else:
        last = date(year, month + 1, 1) - timedelta(days=1)
    delta = (last.weekday() - weekday) % 7
    return last - timedelta(days=delta)


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ZoneRecord:
    zone_id: str
    tz_name: str
    latitude: float
    longitude: float
    anchor_latitude: float
    anchor_longitude: float
    distance_km: float
    match_tier: str
    std_offset_minutes: int
    dst_offset_minutes: int
    observes_dst: bool
    digest: str
    version: str = VERSION
    schema: str = SCHEMA

    def as_dict(self) -> Dict[str, Any]:
        return {f.name: getattr(self, f.name) for f in self.__dataclass_fields__.values()}


@dataclass(frozen=True)
class OffsetRecord:
    offset_id: str
    tz_name: str
    std_offset_minutes: int
    dst_offset_minutes: int
    observes_dst: bool
    digest: str
    version: str = VERSION
    schema: str = SCHEMA

    def as_dict(self) -> Dict[str, Any]:
        return {f.name: getattr(self, f.name) for f in self.__dataclass_fields__.values()}


@dataclass(frozen=True)
class DSTRecord:
    dst_id: str
    tz_name: str
    observes_dst: bool
    hemisphere: Optional[str]
    dst_start: Optional[Dict[str, int]]
    dst_end: Optional[Dict[str, int]]
    dst_offset_minutes: Optional[int]
    digest: str
    version: str = VERSION
    schema: str = SCHEMA

    def as_dict(self) -> Dict[str, Any]:
        return {f.name: getattr(self, f.name) for f in self.__dataclass_fields__.values()}


@dataclass(frozen=True)
class DSTStatus:
    status_id: str
    tz_name: str
    year: int
    month: int
    day: int
    dst_active: bool
    effective_offset_minutes: int
    digest: str
    version: str = VERSION
    schema: str = SCHEMA

    def as_dict(self) -> Dict[str, Any]:
        return {f.name: getattr(self, f.name) for f in self.__dataclass_fields__.values()}


# ---------------------------------------------------------------------------
# Resolver
# ---------------------------------------------------------------------------

class TimezoneResolver:
    """Pinned-table lat/lon -> IANA zone resolution and offset/DST lookup."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = -1
        self._resolve_n = 0
        self._offset_n = 0
        self._dst_n = 0
        self._status_n = 0

    def _next_seq(self, seq: Any) -> int:
        with self._lock:
            seq = _check_seq(seq, self._last_seq)
            self._last_seq = seq
            return seq

    @staticmethod
    def _check_coordinate(value: Any, what: str, lo: float, hi: float) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise InvalidCoordinateError(
                "%s must be a number, got %s" % (what, type(value).__name__))
        if isinstance(value, float) and (value != value
                                         or value in (float("inf"), float("-inf"))):
            raise InvalidCoordinateError("%s must be finite" % what)
        v = float(value)
        if not (lo <= v <= hi):
            raise InvalidCoordinateError(
                "%s out of range [%s, %s]: %r" % (what, lo, hi, value))
        return v

    def resolve(self, latitude: Any, longitude: Any, seq: int) -> ZoneRecord:
        """Resolve (lat, lon) to the nearest pinned IANA zone anchor."""
        seq = self._next_seq(seq)
        lat = self._check_coordinate(latitude, "latitude", -90.0, 90.0)
        lon = self._check_coordinate(longitude, "longitude", -180.0, 180.0)
        with self._lock:
            best: Optional[_Zone] = None
            best_km = math.inf
            for zone in _ZONES:
                km = _haversine_km(lat, lon, zone.anchor_lat, zone.anchor_lon)
                if km < best_km:
                    best_km = km
                    best = zone
            assert best is not None
            self._resolve_n += 1
            zone_id = "zr-%d" % self._resolve_n
        tier = ("exact" if best_km < _EXACT_KM
                else "near" if best_km < _NEAR_KM else "regional")
        digest = _digest_pin(zone_id, best.name, lat, lon,
                             round(best_km, 6), tier, seq)
        return ZoneRecord(
            zone_id=zone_id, tz_name=best.name,
            latitude=lat, longitude=lon,
            anchor_latitude=best.anchor_lat, anchor_longitude=best.anchor_lon,
            distance_km=best_km, match_tier=tier,
            std_offset_minutes=best.std_offset_minutes,
            dst_offset_minutes=best.dst_offset_minutes,
            observes_dst=best.observes_dst, digest=digest)

    def offset(self, zone_name: Any, seq: int) -> OffsetRecord:
        """Return the pinned (standard, DST) offset pair for a zone."""
        seq = self._next_seq(seq)
        zone = self._zone(zone_name)
        with self._lock:
            self._offset_n += 1
            offset_id = "or-%d" % self._offset_n
        digest = _digest_pin(offset_id, zone.name,
                             zone.std_offset_minutes,
                             zone.dst_offset_minutes,
                             zone.observes_dst, seq)
        return OffsetRecord(
            offset_id=offset_id, tz_name=zone.name,
            std_offset_minutes=zone.std_offset_minutes,
            dst_offset_minutes=zone.dst_offset_minutes,
            observes_dst=zone.observes_dst, digest=digest)

    def dst(self, zone_name: Any, seq: int) -> DSTRecord:
        """Describe the zone's DST rule (nth-weekday transitions)."""
        seq = self._next_seq(seq)
        zone = self._zone(zone_name)
        if zone.observes_dst and zone.rule_key is not None:
            rule = _RULES[zone.rule_key]
            start = dict(rule["start"])
            end = dict(rule["end"])
            hemisphere = ("southern" if rule["start"]["month"] > rule["end"]["month"]
                          else "northern")
            dst_minutes: Optional[int] = zone.dst_offset_minutes
        else:
            start = None
            end = None
            hemisphere = None
            dst_minutes = None
        with self._lock:
            self._dst_n += 1
            dst_id = "dr-%d" % self._dst_n
        digest = _digest_pin(dst_id, zone.name, zone.observes_dst,
                             hemisphere, start, end, dst_minutes, seq)
        return DSTRecord(
            dst_id=dst_id, tz_name=zone.name,
            observes_dst=zone.observes_dst, hemisphere=hemisphere,
            dst_start=start, dst_end=end, dst_offset_minutes=dst_minutes,
            digest=digest)

    def dst_active(self, zone_name: Any, year: Any, month: Any,
                   day: Any, seq: int) -> DSTStatus:
        """Evaluate the zone's DST rule for a caller-supplied calendar date.

        Zones that do not observe DST are always inactive. Transition
        days count as the new regime (start day is DST, end day is not).
        """
        seq = self._next_seq(seq)
        zone = self._zone(zone_name)
        d = self._check_date(year, month, day)
        active = False
        if zone.observes_dst and zone.rule_key is not None:
            rule = _RULES[zone.rule_key]
            s, e = rule["start"], rule["end"]
            start = _nth_weekday(d.year, s["month"], s["weekday"], s["week"])
            end = _nth_weekday(d.year, e["month"], e["weekday"], e["week"])
            if start <= end:
                active = start <= d < end
            else:  # southern hemisphere: wraps the year boundary
                active = d >= start or d < end
        effective = zone.dst_offset_minutes if active else zone.std_offset_minutes
        with self._lock:
            self._status_n += 1
            status_id = "ds-%d" % self._status_n
        digest = _digest_pin(status_id, zone.name, d.year, d.month, d.day,
                             active, effective, seq)
        return DSTStatus(
            status_id=status_id, tz_name=zone.name,
            year=d.year, month=d.month, day=d.day,
            dst_active=active, effective_offset_minutes=effective,
            digest=digest)

    @staticmethod
    def _zone(zone_name: Any) -> _Zone:
        if not isinstance(zone_name, str) or not zone_name:
            raise UnknownZoneError("zone name must be a non-empty string")
        zone = _ZONE_BY_NAME.get(zone_name)
        if zone is None:
            raise UnknownZoneError("unknown zone: %r" % (zone_name,))
        return zone

    @staticmethod
    def _check_date(year: Any, month: Any, day: Any) -> date:
        for label, v in (("year", year), ("month", month), ("day", day)):
            if isinstance(v, bool) or not isinstance(v, int):
                raise InvalidDateError(
                    "%s must be an int, got %s" % (label, type(v).__name__))
        try:
            return date(year, month, day)
        except ValueError as exc:
            raise InvalidDateError("invalid date %r-%r-%r: %s"
                                   % (year, month, day, exc))


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------

_AUDIT_KINDS = ("resolved", "offset-looked-up", "dst-described",
                "dst-evaluated", "rejected")


def timezone_resolver_audit_event(kind: str, seq: int, **detail: Any) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for timezone-resolver events."""
    if kind not in _AUDIT_KINDS:
        raise TimezoneError("unknown audit kind: %r" % (kind,))
    seq = _check_seq(seq, -1)
    return {
        "schema": "audit.ndjson/1",
        "module": "timezone_resolver",
        "moduleVersion": VERSION,
        "kind": kind,
        "seq": seq,
        "detail": dict(detail),
    }


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------

def main() -> None:
    r = TimezoneResolver()
    z = r.resolve(40.7128, -74.0060, seq=1)
    assert z.tz_name == "America/New_York", z.tz_name
    assert z.match_tier == "exact", z.match_tier
    assert z.std_offset_minutes == -300 and z.dst_offset_minutes == -240
    assert z.digest.startswith("sha256:")

    o = r.offset("Asia/Tokyo", seq=2)
    assert o.std_offset_minutes == 540 and not o.observes_dst

    d = r.dst("Europe/Paris", seq=3)
    assert d.observes_dst and d.hemisphere == "northern"
    assert d.dst_start == {"month": 3, "week": -1, "weekday": 6}

    s = r.dst_active("America/New_York", 2026, 7, 4, seq=4)
    assert s.dst_active and s.effective_offset_minutes == -240, s
    w = r.dst_active("America/New_York", 2026, 1, 15, seq=5)
    assert not w.dst_active and w.effective_offset_minutes == -300, w
    # Southern hemisphere: Sydney January is DST.
    syd = r.dst_active("Australia/Sydney", 2026, 1, 15, seq=6)
    assert syd.dst_active and syd.effective_offset_minutes == 660, syd
    # Non-observing zone is always standard.
    tyo = r.dst_active("Asia/Tokyo", 2026, 7, 4, seq=7)
    assert not tyo.dst_active and tyo.effective_offset_minutes == 540, tyo

    ev = timezone_resolver_audit_event("resolved", 8, zone=z.tz_name)
    assert ev["schema"] == "audit.ndjson/1"
    print("timezone-resolver OK: resolve, offset, dst, dst_active, audit")


if __name__ == "__main__":
    main()
