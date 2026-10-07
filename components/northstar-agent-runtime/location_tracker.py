"""Location tracker interface: GPS-fix ledger, trails, and speed reports.

Research note: a *GPS track* is a time-ordered sequence of *fixes* — each
fix binds a (latitude, longitude) pair to a device-reported epoch. The
load-bearing invariants for an agent's location subsystem are:
(1) *coordinate validity* — latitude must lie in [-90, 90] and longitude in
[-180, 180]; NaN/inf/bool/str values are refused at record time, never
coerced; (2) *device-clock monotonicity* — fixes for one device must arrive
with strictly increasing device epochs, because a rewind means the fix
stream is corrupted or replayed; (3) *immutability* — a recorded fix is
never edited or deleted, only superseded by newer fixes, so the trail is a
complete audit of where the device *claimed* to be; (4) *honest distances* —
trail distance is the haversine sum over the recorded fixes, rounded to
whole meters, and speed is distance over device-reported elapsed seconds
(the host/device owns the clock, so this is GIGO on a lying clock, same
boundary as every other bookkeeping module).

This module implements that shape as a deterministic, single-host ledger:

* **Fix** — :meth:`LocationTracker.fix` records a frozen
  :class:`FixRecord` (``fx-<n>`` id, device id, lat/lon, device epoch,
  optional accuracy/altitude, ``sha256:`` digest pin).
* **Trail** — :meth:`LocationTracker.trail` returns a frozen
  :class:`TrailReport` (fix ids in seq order, count, bounding box,
  haversine distance in whole meters).
* **Speed** — :meth:`LocationTracker.speed` returns a frozen
  :class:`SpeedReport` (window of fix ids, distance, device-reported
  duration in seconds, meters/second and km/h).

House style: frozen dataclasses, caller-supplied int seqs (strictly
increasing per tracker, no wall-clock, no RNG — ids are monotonic
``fx-<n>`` counters), RLock-guarded, fail-closed (out-of-range or
non-numeric coordinates, non-monotonic device epochs, unknown devices,
single-fix speed windows all raise a subclass of :class:`LocationError`),
stdlib-only, type-tagged canonical digest encoding (bool != int;
NaN/inf refused; integral floats *allowed* here — coordinates are
range-bounded fractional-domain values, so ``37.0`` is unambiguous and is
pinned via ``repr``; the >2^53 caveat cannot occur inside +/-180), audit
events shaped for ``audit.ndjson/1``, ``main()`` self-check.

Honest scope: this is a *claims ledger*, not a GNSS receiver. It cannot
observe the device, prove a fix is real, or detect spoofing — :meth:`fix`
pins what the host *reported*, and a lying host gets a consistent ledger
of lies. For production pair with an attested GNSS feed and
``remote_attestation`` for the host.

Version pin: location-tracker.v1
"""

from __future__ import annotations

import hashlib
import json
import math
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Tuple

VERSION = "location-tracker.v1"
SCHEMA = "northstar.location-tracker.v1"

__all__ = [
    "VERSION",
    "SCHEMA",
    "LocationError",
    "UnknownDeviceError",
    "UnknownFixError",
    "BadCoordinateError",
    "BadEpochError",
    "BadFieldError",
    "SeqOrderError",
    "TooFewFixesError",
    "FixRecord",
    "TrailReport",
    "SpeedReport",
    "LocationTracker",
    "location_tracker_audit_event",
]

_R_EARTH_M = 6371000.0  # WGS-84 mean radius, meters


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------

class LocationError(ValueError):
    """Base class for all location-tracker errors."""


class UnknownDeviceError(LocationError):
    pass


class UnknownFixError(LocationError):
    pass


class BadCoordinateError(LocationError):
    pass


class BadEpochError(LocationError):
    pass


class BadFieldError(LocationError):
    pass


class SeqOrderError(LocationError):
    pass


class TooFewFixesError(LocationError):
    pass


# ---------------------------------------------------------------------------
# Canonical digest
# ---------------------------------------------------------------------------

def _canon(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        if abs(value) >= 2 ** 53:
            raise LocationError(f"integer out of safe range: {value!r}")
        return f"int:{value}"
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise LocationError(f"non-finite float refused: {value!r}")
        # NOTE: integral floats are ALLOWED here, deliberately deviating
        # from the batch-line default. Coordinates are range-bounded
        # ([-90, 90] / [-180, 180]) fractional-domain values, so 37.0 is
        # unambiguous and pinned deterministically via repr.
        return f"float:{repr(value)}"
    if isinstance(value, str):
        return "str:" + json.dumps(value, ensure_ascii=True)
    if isinstance(value, (list, tuple)):
        return "list:[" + ",".join(_canon(v) for v in value) + "]"
    if isinstance(value, Mapping):
        items = sorted(value.items(), key=lambda kv: str(kv[0]))
        return "map:{" + ",".join(_canon(k) + "=>" + _canon(v) for k, v in items) + "}"
    raise LocationError(f"non-canonicalizable value: {type(value).__name__}")


def _pin(*parts: Any) -> str:
    body = "|".join(_canon(p) for p in parts)
    return "sha256:" + hashlib.sha256(body.encode("utf-8")).hexdigest()


def _haversine_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance in meters (float; callers round honestly)."""
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = (
        math.sin(dp / 2) ** 2
        + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    )
    return 2 * _R_EARTH_M * math.asin(math.sqrt(a))


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FixRecord:
    """One immutable GPS fix as reported by the host."""
    id: str
    device_id: str
    lat: float
    lon: float
    at: int  # device-reported epoch seconds
    accuracy_m: Optional[float]
    altitude_m: Optional[float]
    seq: int
    digest: str
    version: str = VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "device_id": self.device_id,
            "lat": self.lat,
            "lon": self.lon,
            "at": self.at,
            "accuracy_m": self.accuracy_m,
            "altitude_m": self.altitude_m,
            "seq": self.seq,
            "digest": self.digest,
            "version": self.version,
        }


@dataclass(frozen=True)
class TrailReport:
    """A device's recorded trail: fixes in seq order, bbox, distance."""
    device_id: str
    fix_ids: Tuple[str, ...]
    count: int
    min_lat: float
    max_lat: float
    min_lon: float
    max_lon: float
    distance_m: int  # whole meters, haversine sum rounded
    seq: int
    digest: str
    version: str = VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "device_id": self.device_id,
            "fix_ids": list(self.fix_ids),
            "count": self.count,
            "bbox": {
                "min_lat": self.min_lat,
                "max_lat": self.max_lat,
                "min_lon": self.min_lon,
                "max_lon": self.max_lon,
            },
            "distance_m": self.distance_m,
            "seq": self.seq,
            "digest": self.digest,
            "version": self.version,
        }


@dataclass(frozen=True)
class SpeedReport:
    """Speed over a window of fixes: distance / device-reported seconds."""
    device_id: str
    fix_ids: Tuple[str, ...]
    distance_m: int  # whole meters
    duration_s: int  # device-reported elapsed seconds
    speed_mps: float  # meters/second, 3-decimal rounding
    speed_kmh: float  # km/h, 3-decimal rounding
    seq: int
    digest: str
    version: str = VERSION

    def as_dict(self) -> Dict[str, Any]:
        return {
            "device_id": self.device_id,
            "fix_ids": list(self.fix_ids),
            "distance_m": self.distance_m,
            "duration_s": self.duration_s,
            "speed_mps": self.speed_mps,
            "speed_kmh": self.speed_kmh,
            "seq": self.seq,
            "digest": self.digest,
            "version": self.version,
        }


# ---------------------------------------------------------------------------
# Tracker
# ---------------------------------------------------------------------------

class LocationTracker:
    """Deterministic GPS-fix ledger."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq: int = -1
        self._fixes: Dict[str, FixRecord] = {}
        self._by_device: Dict[str, list] = {}  # device_id -> [FixRecord] in seq order
        self._last_at: Dict[str, int] = {}  # device_id -> last device epoch
        self._fx_n = 0

    # -- validation helpers ------------------------------------------------

    def _check_seq(self, seq: Any) -> int:
        if isinstance(seq, bool) or not isinstance(seq, int):
            raise SeqOrderError(f"seq must be int, got {type(seq).__name__}")
        if seq < 0:
            raise SeqOrderError(f"seq must be non-negative, got {seq}")
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq {seq} not strictly greater than {self._last_seq}"
            )
        self._last_seq = seq
        return seq

    @staticmethod
    def _check_device_id(value: Any) -> str:
        if not isinstance(value, str) or not value.strip():
            raise BadFieldError(f"device_id must be a non-empty string, got {value!r}")
        return value

    @staticmethod
    def _check_coord(value: Any, name: str, low: float, high: float) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise BadCoordinateError(
                f"{name} must be a number, got {value!r}"
            )
        fvalue = float(value)
        if math.isnan(fvalue) or math.isinf(fvalue):
            raise BadCoordinateError(f"{name} must be finite, got {value!r}")
        if not (low <= fvalue <= high):
            raise BadCoordinateError(
                f"{name} {fvalue} out of range [{low}, {high}]"
            )
        return fvalue

    @staticmethod
    def _check_at(value: Any) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise BadEpochError(f"at must be an int epoch, got {value!r}")
        if value < 0:
            raise BadEpochError(f"at must be non-negative, got {value}")
        return value

    @staticmethod
    def _check_optional_meter(value: Any, name: str) -> Optional[float]:
        if value is None:
            return None
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise BadFieldError(f"{name} must be a number or None, got {value!r}")
        fvalue = float(value)
        if math.isnan(fvalue) or math.isinf(fvalue):
            raise BadFieldError(f"{name} must be finite, got {value!r}")
        if name == "accuracy_m" and fvalue < 0:
            raise BadFieldError(f"accuracy_m must be non-negative, got {value!r}")
        return fvalue

    # -- fix ----------------------------------------------------------------

    def fix(
        self,
        device_id: str,
        lat: float,
        lon: float,
        seq: int,
        *,
        at: int,
        accuracy_m: Optional[float] = None,
        altitude_m: Optional[float] = None,
    ) -> FixRecord:
        """Record one GPS fix; returns the frozen record."""
        with self._lock:
            self._check_seq(seq)
            device_id = self._check_device_id(device_id)
            flat = self._check_coord(lat, "lat", -90.0, 90.0)
            flon = self._check_coord(lon, "lon", -180.0, 180.0)
            at = self._check_at(at)
            accuracy_m = self._check_optional_meter(accuracy_m, "accuracy_m")
            altitude_m = self._check_optional_meter(altitude_m, "altitude_m")

            # device clock must move forward: a rewind is a corrupted stream
            prev_at = self._last_at.get(device_id)
            if prev_at is not None and at <= prev_at:
                raise BadEpochError(
                    f"device {device_id!r} epoch {at} not strictly greater "
                    f"than {prev_at}"
                )

            self._fx_n += 1
            fx_id = f"fx-{self._fx_n}"
            digest = _pin(
                "fix", fx_id, device_id, flat, flon, at,
                accuracy_m, altitude_m, seq,
            )
            record = FixRecord(
                id=fx_id, device_id=device_id, lat=flat, lon=flon, at=at,
                accuracy_m=accuracy_m, altitude_m=altitude_m, seq=seq,
                digest=digest,
            )
            self._fixes[fx_id] = record
            self._by_device.setdefault(device_id, []).append(record)
            self._last_at[device_id] = at
            return record

    # -- trail ---------------------------------------------------------------

    def trail(
        self, device_id: str, seq: int, *, limit: Optional[int] = None
    ) -> TrailReport:
        """Build a trail report over a device's fixes (oldest first)."""
        with self._lock:
            self._check_seq(seq)
            device_id = self._check_device_id(device_id)
            fixes = self._by_device.get(device_id)
            if not fixes:
                raise UnknownDeviceError(f"unknown device: {device_id!r}")
            if limit is not None:
                if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
                    raise BadFieldError(f"limit must be a positive int, got {limit!r}")
                fixes = fixes[-limit:]

            fix_ids = tuple(f.id for f in fixes)
            lats = [f.lat for f in fixes]
            lons = [f.lon for f in fixes]
            distance = sum(
                _haversine_m(fixes[i].lat, fixes[i].lon,
                             fixes[i + 1].lat, fixes[i + 1].lon)
                for i in range(len(fixes) - 1)
            )
            distance_m = int(round(distance))
            digest = _pin(
                "trail", device_id, list(fix_ids), len(fixes),
                min(lats), max(lats), min(lons), max(lons), distance_m, seq,
            )
            return TrailReport(
                device_id=device_id, fix_ids=fix_ids, count=len(fixes),
                min_lat=min(lats), max_lat=max(lats),
                min_lon=min(lons), max_lon=max(lons),
                distance_m=distance_m, seq=seq, digest=digest,
            )

    # -- speed ---------------------------------------------------------------

    def speed(
        self, device_id: str, seq: int, *, last_n: Optional[int] = None
    ) -> SpeedReport:
        """Speed over the last-N fixes (default: all of the device's fixes)."""
        with self._lock:
            self._check_seq(seq)
            device_id = self._check_device_id(device_id)
            fixes = self._by_device.get(device_id)
            if not fixes:
                raise UnknownDeviceError(f"unknown device: {device_id!r}")
            if last_n is not None:
                if isinstance(last_n, bool) or not isinstance(last_n, int) or last_n < 2:
                    raise BadFieldError(
                        f"last_n must be an int >= 2, got {last_n!r}"
                    )
                fixes = fixes[-last_n:]
            if len(fixes) < 2:
                raise TooFewFixesError(
                    f"speed needs >= 2 fixes, device {device_id!r} has {len(fixes)}"
                )

            fix_ids = tuple(f.id for f in fixes)
            distance = sum(
                _haversine_m(fixes[i].lat, fixes[i].lon,
                             fixes[i + 1].lat, fixes[i + 1].lon)
                for i in range(len(fixes) - 1)
            )
            distance_m = int(round(distance))
            duration_s = fixes[-1].at - fixes[0].at
            if duration_s <= 0:
                # Unreachable given per-device epoch monotonicity, but
                # fail closed rather than divide by zero.
                raise BadEpochError("non-positive duration in speed window")
            speed_mps = round(distance / duration_s, 3)
            speed_kmh = round(speed_mps * 3.6, 3)
            digest = _pin(
                "speed", device_id, list(fix_ids), distance_m, duration_s,
                speed_mps, speed_kmh, seq,
            )
            return SpeedReport(
                device_id=device_id, fix_ids=fix_ids, distance_m=distance_m,
                duration_s=duration_s, speed_mps=speed_mps,
                speed_kmh=speed_kmh, seq=seq, digest=digest,
            )

    # -- views ----------------------------------------------------------------

    def fix_record(self, fix_id: str) -> FixRecord:
        try:
            return self._fixes[fix_id]
        except KeyError:
            raise UnknownFixError(f"unknown fix: {fix_id!r}")

    def fixes(self, device_id: str) -> Tuple[FixRecord, ...]:
        if device_id not in self._by_device:
            raise UnknownDeviceError(f"unknown device: {device_id!r}")
        return tuple(self._by_device[device_id])

    def device_ids(self) -> Tuple[str, ...]:
        return tuple(sorted(self._by_device))

    def fix_count(self) -> int:
        return len(self._fixes)


# ---------------------------------------------------------------------------
# Audit events (audit.ndjson/1 shaped)
# ---------------------------------------------------------------------------

_AUDIT_KINDS = ("fix-recorded", "trail-built", "speed-computed", "rejected")


def location_tracker_audit_event(
    kind: str, ref_id: str, digest: str, seq: int
) -> Dict[str, Any]:
    """Shape an audit event; carries ids and digest pins only — never raw
    coordinates (location data stays in the ledger, not the audit stream)."""
    if kind not in _AUDIT_KINDS:
        raise LocationError(f"unknown audit kind: {kind!r}")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SeqOrderError(f"seq must be a non-negative int, got {seq!r}")
    return {
        "schema": "audit.ndjson/1",
        "module": SCHEMA,
        "kind": kind,
        "ref_id": ref_id,
        "digest": digest,
        "seq": seq,
    }


def main() -> None:
    tr = LocationTracker()
    f1 = tr.fix("dev-1", 22.5431, 114.0579, 1, at=1000)  # Shenzhen
    assert f1.id == "fx-1" and f1.digest.startswith("sha256:")
    # ~1 degree east along the equator-ish latitude: ~101.8 km
    f2 = tr.fix("dev-1", 22.5431, 115.0579, 2, at=4600)
    trail = tr.trail("dev-1", 3)
    assert trail.count == 2 and 100000 < trail.distance_m < 104000
    sp = tr.speed("dev-1", 4)
    assert sp.duration_s == 3600 and sp.speed_mps > 27.0
    try:
        tr.fix("dev-1", 22.0, 114.0, 5, at=4000)  # epoch rewind
    except BadEpochError:
        pass
    else:
        raise AssertionError("expected BadEpochError")
    print("location-tracker OK: fix, trail, speed, epoch monotonicity")


if __name__ == "__main__":
    main()
