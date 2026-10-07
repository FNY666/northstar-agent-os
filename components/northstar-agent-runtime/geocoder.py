"""Geocoder interface: forward/reverse coordinate lookup as deterministic bookkeeping.

Research note: a *geocoder* sits between an agent's location reasoning and the
physical world. Real-world geocoders (Nominatim, OpenCage, Google Geocoding
API) share three properties that matter for a correct interface: (1)
*forward lookup is a match problem* — addresses are matched against a known
gazetteer with exact/alias/fuzzy tiers, and unmatched queries return
``ZERO_RESULTS`` (data, not an exception); (2) *reverse lookup is a distance
problem* — a coordinate resolves to the nearest known place via great-circle
distance, with a host-chosen tolerance deciding whether it counts as "at"
the place; (3) *batch work is a throughput problem* — bulk geocoding is one
ledger entry per item, each result self-describing.

The load-bearing invariants of this module are:

* **Exact coordinates** — latitudes/longitudes are ints in microdegrees
  (E6); *floats are refused fail-closed*, so no IEEE contamination enters
  the coordinate path (the batch-5 JCS float-loss caveat applies here too:
  a float degree value cannot round-trip through JSON canonicalization).
* **Match tiers, not guesses** — ``geocode()`` returns a frozen
  :class:`GeocodeResult` whose ``match_kind`` is ``exact`` (canonical name),
  ``alias`` (registered alternate), ``fuzzy`` (normalized Levenshtein match
  at or above the matcher's threshold), or ``none`` (no usable match — as
  *data*, never an exception, matching the ZERO_RESULTS discipline).
* **Reverse is nearest-with-distance** — ``reverse()`` returns the nearest
  registered place, the haversine distance in whole meters (int, pinned),
  and a ``within`` flag against the caller-supplied tolerance; nothing is
  invented when the registry is empty (fail-closed ``NoPlacesError``).
* **Batch is a ledger** — ``batch()`` takes a list of ``("geocode", addr)``
  / ``("reverse", lat_e6, lon_e6, tolerance_m)`` items and returns a frozen
  :class:`BatchResult` with one pinned per-item result; a malformed item is
  refused fail-closed before any work runs.

House style: frozen dataclasses, caller-supplied strictly increasing int
seqs (no wall-clock, no RNG), RLock-guarded, fail-closed (empty ids, dup
place ids, malformed coordinates, bad match thresholds, non-increasing seqs
all raise a subclass of :class:`GeocoderError`), stdlib-only
(``hashlib``, ``math``, ``re``, ``threading``, ``dataclasses``,
``typing``, ``unicodedata``), ``sha256:`` digest pins over type-tagged
canonical encodings, audit events shaped for ``audit.ndjson/1``
(ids + digest pins only — never address text or raw coordinates),
``main()`` self-check.

Honest scope: this is a *gazetteer interface*, not a planet. ``register_place``
pins what the host *reported* about a location; it cannot verify the place
exists, that the coordinates are correct, or that a matched address is the
real-world one — a host that registers lies gets a consistent ledger of
lies (GIGO, same boundary as every other bookkeeping module). Pair with an
attested gazetteer feed (``remote_attestation`` for the host) for
production use.

Version pin: geocoder.v1
"""

from __future__ import annotations

import hashlib
import math
import re
import threading
import unicodedata
from dataclasses import dataclass, field
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

VERSION = "geocoder.v1"
SCHEMA = "northstar.geocoder.v1"

__all__ = [
    "VERSION",
    "SCHEMA",
    "GeocoderError",
    "DuplicatePlaceError",
    "UnknownPlaceError",
    "InvalidPlaceError",
    "InvalidCoordinateError",
    "NoPlacesError",
    "BadMatchError",
    "SequenceError",
    "MICRODEGREES",
    "EARTH_RADIUS_M",
    "DEFAULT_FUZZY_THRESHOLD",
    "PlaceRecord",
    "GeocodeResult",
    "ReverseResult",
    "BatchItemResult",
    "BatchResult",
    "Geocoder",
    "geocoder_audit_event",
]

#: Coordinates are stored as ints in microdegrees (1e-6 degrees).
MICRODEGREES = 1_000_000
#: WGS-84 mean earth radius used for haversine, in meters.
EARTH_RADIUS_M = 6_371_000
#: Default normalized-Levenshtein threshold for the "fuzzy" match tier.
DEFAULT_FUZZY_THRESHOLD = 0.80


class GeocoderError(Exception):
    """Base for all geocoder errors (fail-closed taxonomy)."""


class DuplicatePlaceError(GeocoderError):
    """A place_id (or normalized alias) is already registered."""


class UnknownPlaceError(GeocoderError):
    """A place_id lookup found nothing."""


class InvalidPlaceError(GeocoderError):
    """Place registration payload is malformed (empty id/name, bad alias)."""


class InvalidCoordinateError(GeocoderError):
    """Latitude/longitude is not an int microdegree in range (floats refused)."""


class NoPlacesError(GeocoderError):
    """Reverse geocoding with an empty place registry (nothing to be near)."""


class BadMatchError(GeocoderError):
    """A batch item is malformed or a matcher parameter is out of range."""


class SequenceError(GeocoderError):
    """Caller-supplied seq did not strictly increase."""


_AUDIT_KINDS = (
    "place-registered",
    "geocoded",
    "reversed",
    "batched",
    "rejected",
)

_MATCH_KINDS = ("exact", "alias", "fuzzy", "none")

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


# ---------------------------------------------------------------------------
# Canonical encoding (type-tagged; bool != int; NaN/inf impossible here)
# ---------------------------------------------------------------------------

def _canon(value: object) -> str:
    """Type-tagged canonical encoding for digest pins (batch-5 JCS discipline)."""
    if isinstance(value, bool):
        return "bool:" + ("1" if value else "0")
    if isinstance(value, int):
        if abs(value) >= 2**53:
            raise GeocoderError("integer out of canonical range")
        return f"int:{value}"
    if isinstance(value, str):
        return f"str:{len(value)}:{value}"
    if isinstance(value, (tuple, list)):
        return "list:" + ",".join(_canon(v) for v in value)
    if value is None:
        return "none:"
    raise GeocoderError(f"non-canonical value: {type(value).__name__}")


def _pin(parts: Sequence[object]) -> str:
    body = "|".join(_canon(p) for p in parts).encode("utf-8")
    return "sha256:" + hashlib.sha256(body).hexdigest()


# ---------------------------------------------------------------------------
# Text normalization + Levenshtein (gazetteer matching)
# ---------------------------------------------------------------------------

def _normalize(text: str) -> str:
    """Case/diacritic/punctuation-folded normalization for matching."""
    folded = unicodedata.normalize("NFKD", text.casefold())
    folded = "".join(c for c in folded if not unicodedata.combining(c))
    folded = re.sub(r"[^\w\s]", " ", folded)
    return re.sub(r"\s+", " ", folded).strip()


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[len(b)]


def _similarity(a: str, b: str) -> float:
    """Normalized similarity in [0, 1] over normalized text."""
    na, nb = _normalize(a), _normalize(b)
    if not na and not nb:
        return 1.0
    if not na or not nb:
        return 0.0
    dist = _levenshtein(na, nb)
    return 1.0 - dist / max(len(na), len(nb))


# ---------------------------------------------------------------------------
# Coordinate discipline
# ---------------------------------------------------------------------------

def _check_seq(seq: int, last: int) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SequenceError("seq must be an int (bool refused)")
    if seq <= last:
        raise SequenceError("seq must strictly increase")
    return seq


def _check_lat(lat_e6: int, what: str = "latitude") -> int:
    if isinstance(lat_e6, bool) or not isinstance(lat_e6, int):
        raise InvalidCoordinateError(f"{what} must be int microdegrees (float refused)")
    if not -90 * MICRODEGREES <= lat_e6 <= 90 * MICRODEGREES:
        raise InvalidCoordinateError(f"{what} out of range [-90, 90] degrees")
    return lat_e6


def _check_lon(lon_e6: int, what: str = "longitude") -> int:
    if isinstance(lon_e6, bool) or not isinstance(lon_e6, int):
        raise InvalidCoordinateError(f"{what} must be int microdegrees (float refused)")
    if not -180 * MICRODEGREES <= lon_e6 <= 180 * MICRODEGREES:
        raise InvalidCoordinateError(f"{what} out of range [-180, 180] degrees")
    return lon_e6


def _check_place_id(place_id: str) -> str:
    if not isinstance(place_id, str) or not _ID_RE.match(place_id):
        raise InvalidPlaceError("place_id must match [A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
    return place_id


def _check_name(name: str, what: str = "name") -> str:
    if not isinstance(name, str) or not name.strip():
        raise InvalidPlaceError(f"{what} must be a non-empty string")
    if len(name) > 512:
        raise InvalidPlaceError(f"{what} exceeds 512 chars")
    return name.strip()


def _haversine_m(lat1_e6: int, lon1_e6: int, lat2_e6: int, lon2_e6: int) -> int:
    """Great-circle distance in whole meters (int; no float pins)."""
    p1 = math.pi / 180.0 / MICRODEGREES
    dlat = (lat2_e6 - lat1_e6) * p1
    dlon = (lon2_e6 - lon1_e6) * p1
    a = (
        math.sin(dlat / 2.0) ** 2
        + math.cos(lat1_e6 * p1)
        * math.cos(lat2_e6 * p1)
        * math.sin(dlon / 2.0) ** 2
    )
    return int(round(2.0 * EARTH_RADIUS_M * math.asin(math.sqrt(a))))


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PlaceRecord:
    """A registered place: id, canonical name, aliases, exact coordinates."""
    place_id: str
    display_name: str
    lat_e6: int
    lon_e6: int
    aliases: Tuple[str, ...]
    country: str
    pin: str

    def as_dict(self) -> Dict[str, object]:
        return {
            "place_id": self.place_id,
            "display_name": self.display_name,
            "lat_e6": self.lat_e6,
            "lon_e6": self.lon_e6,
            "lat_deg": self.lat_e6 / MICRODEGREES,
            "lon_deg": self.lon_e6 / MICRODEGREES,
            "aliases": list(self.aliases),
            "country": self.country,
            "pin": self.pin,
        }


@dataclass(frozen=True)
class GeocodeResult:
    """Forward lookup result: match tier + pinned coordinates (or none)."""
    query: str
    match_kind: str  # exact | alias | fuzzy | none
    place_id: str
    display_name: str
    lat_e6: Optional[int]
    lon_e6: Optional[int]
    similarity: float
    pin: str

    def as_dict(self) -> Dict[str, object]:
        return {
            "query": self.query,
            "match_kind": self.match_kind,
            "place_id": self.place_id,
            "display_name": self.display_name,
            "lat_e6": self.lat_e6,
            "lon_e6": self.lon_e6,
            "similarity": self.similarity,
            "pin": self.pin,
        }


@dataclass(frozen=True)
class ReverseResult:
    """Reverse lookup result: nearest place, whole-meter distance, tolerance flag."""
    lat_e6: int
    lon_e6: int
    place_id: str
    display_name: str
    distance_m: int
    within: bool
    tolerance_m: int
    pin: str

    def as_dict(self) -> Dict[str, object]:
        return {
            "lat_e6": self.lat_e6,
            "lon_e6": self.lon_e6,
            "place_id": self.place_id,
            "display_name": self.display_name,
            "distance_m": self.distance_m,
            "within": self.within,
            "tolerance_m": self.tolerance_m,
            "pin": self.pin,
        }


@dataclass(frozen=True)
class BatchItemResult:
    """One pinned per-item result inside a BatchResult."""
    index: int
    op: str  # "geocode" | "reverse"
    result_pin: str
    match_kind: str  # geocode tier, or "within"/"outside" for reverse
    pin: str

    def as_dict(self) -> Dict[str, object]:
        return {
            "index": self.index,
            "op": self.op,
            "result_pin": self.result_pin,
            "match_kind": self.match_kind,
            "pin": self.pin,
        }


@dataclass(frozen=True)
class BatchResult:
    """A pinned ledger of one batch() call."""
    batch_id: str
    item_count: int
    items: Tuple[BatchItemResult, ...]
    pin: str

    def as_dict(self) -> Dict[str, object]:
        return {
            "batch_id": self.batch_id,
            "item_count": self.item_count,
            "items": [i.as_dict() for i in self.items],
            "pin": self.pin,
        }


# ---------------------------------------------------------------------------
# Geocoder
# ---------------------------------------------------------------------------

class Geocoder:
    """Deterministic gazetteer: register places, forward/reverse lookup, batch."""

    def __init__(self, fuzzy_threshold: float = DEFAULT_FUZZY_THRESHOLD) -> None:
        if isinstance(fuzzy_threshold, bool) or not isinstance(fuzzy_threshold, (int, float)):
            raise BadMatchError("fuzzy_threshold must be a number")
        if not 0.0 < float(fuzzy_threshold) <= 1.0:
            raise BadMatchError("fuzzy_threshold must be in (0, 1]")
        self._lock = threading.RLock()
        self._fuzzy_threshold = float(fuzzy_threshold)
        self._places: Dict[str, PlaceRecord] = {}
        self._norm_index: Dict[str, str] = {}  # normalized name/alias -> place_id
        self._last_seq = 0
        self._batch_n = 0

    # -- mutation: register ---------------------------------------------

    def register_place(
        self,
        place_id: str,
        display_name: str,
        lat_e6: int,
        lon_e6: int,
        seq: int,
        aliases: Sequence[str] = (),
        country: str = "",
    ) -> PlaceRecord:
        """Register a place; pins the host-reported coordinates."""
        with self._lock:
            self._last_seq = _check_seq(seq, self._last_seq)
            _check_place_id(place_id)
            _check_name(display_name)
            _check_lat(lat_e6)
            _check_lon(lon_e6)
            if not isinstance(country, str) or len(country) > 64:
                raise InvalidPlaceError("country must be a string <= 64 chars")
            clean_aliases: List[str] = []
            for alias in aliases:
                a = _check_name(alias, "alias")
                if a == display_name or a in clean_aliases:
                    raise InvalidPlaceError("duplicate or redundant alias")
                clean_aliases.append(a)
            if place_id in self._places:
                raise DuplicatePlaceError(f"place already registered: {place_id!r}")
            norm_name = _normalize(display_name)
            if norm_name in self._norm_index:
                raise DuplicatePlaceError("normalized display name already registered")
            for alias in clean_aliases:
                if _normalize(alias) in self._norm_index:
                    raise DuplicatePlaceError(f"normalized alias already registered: {alias!r}")
            rec = PlaceRecord(
                place_id=place_id,
                display_name=display_name,
                lat_e6=lat_e6,
                lon_e6=lon_e6,
                aliases=tuple(clean_aliases),
                country=country,
                pin=_pin(("place", place_id, display_name, lat_e6, lon_e6,
                          tuple(clean_aliases), country, seq)),
            )
            self._places[place_id] = rec
            self._norm_index[norm_name] = place_id
            for alias in clean_aliases:
                self._norm_index[_normalize(alias)] = place_id
            return rec

    def place(self, place_id: str) -> PlaceRecord:
        """Read a registered place (metadata view)."""
        with self._lock:
            try:
                return self._places[_check_place_id(place_id)]
            except KeyError:
                raise UnknownPlaceError(f"unknown place: {place_id!r}") from None

    def place_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._places))

    # -- forward lookup ---------------------------------------------------

    def geocode(self, address: str, seq: int) -> GeocodeResult:
        """Forward lookup: address text -> pinned coordinates or kind 'none'."""
        with self._lock:
            self._last_seq = _check_seq(seq, self._last_seq)
            if not isinstance(address, str) or not address.strip():
                raise BadMatchError("address must be a non-empty string")
            query = address.strip()
            norm_q = _normalize(query)

            # Tier 1: normalized exact hit against names + aliases.
            hit_id = self._norm_index.get(norm_q)
            if hit_id is not None:
                rec = self._places[hit_id]
                kind = "exact" if norm_q == _normalize(rec.display_name) else "alias"
                sim = 1.0
                lat, lon = rec.lat_e6, rec.lon_e6
                pid, name = rec.place_id, rec.display_name
            else:
                # Tier 2: best fuzzy candidate at/above threshold.
                best: Optional[Tuple[float, PlaceRecord]] = None
                for rec in self._places.values():
                    sim = _similarity(query, rec.display_name)
                    if sim >= self._fuzzy_threshold and (best is None or sim > best[0]):
                        best = (sim, rec)
                if best is not None:
                    sim, rec = best
                    kind, lat, lon = "fuzzy", rec.lat_e6, rec.lon_e6
                    pid, name = rec.place_id, rec.display_name
                else:
                    kind, lat, lon, sim = "none", None, None, 0.0
                    pid, name = "", ""
            sim_q = int(round(sim * 1_000_000))
            return GeocodeResult(
                query=query,
                match_kind=kind,
                place_id=pid,
                display_name=name,
                lat_e6=lat,
                lon_e6=lon,
                similarity=sim,
                pin=_pin(("geocode", query, kind, pid, name, lat, lon, sim_q, seq)),
            )

    # -- reverse lookup ---------------------------------------------------

    def reverse(self, lat_e6: int, lon_e6: int, seq: int, tolerance_m: int = 1000) -> ReverseResult:
        """Reverse lookup: coordinates -> nearest place + whole-meter distance."""
        with self._lock:
            self._last_seq = _check_seq(seq, self._last_seq)
            _check_lat(lat_e6)
            _check_lon(lon_e6)
            if isinstance(tolerance_m, bool) or not isinstance(tolerance_m, int) or tolerance_m < 0:
                raise BadMatchError("tolerance_m must be a non-negative int")
            if not self._places:
                raise NoPlacesError("no places registered")
            best_rec: Optional[PlaceRecord] = None
            best_d: Optional[int] = None
            for rec in self._places.values():
                d = _haversine_m(lat_e6, lon_e6, rec.lat_e6, rec.lon_e6)
                if best_d is None or d < best_d:
                    best_d, best_rec = d, rec
            assert best_rec is not None and best_d is not None
            within = best_d <= tolerance_m
            return ReverseResult(
                lat_e6=lat_e6,
                lon_e6=lon_e6,
                place_id=best_rec.place_id,
                display_name=best_rec.display_name,
                distance_m=best_d,
                within=within,
                tolerance_m=tolerance_m,
                pin=_pin(("reverse", lat_e6, lon_e6, best_rec.place_id,
                          best_d, within, tolerance_m, seq)),
            )

    # -- batch --------------------------------------------------------------

    def batch(self, items: Sequence[object], seq: int) -> BatchResult:
        """Bulk lookup: list of ("geocode", addr) / ("reverse", lat, lon[, tol])."""
        with self._lock:
            self._last_seq = _check_seq(seq, self._last_seq)
            if not isinstance(items, (list, tuple)) or not items:
                raise BadMatchError("items must be a non-empty list/tuple")
            parsed: List[Tuple[str, tuple]] = []
            for i, item in enumerate(items):
                if not isinstance(item, (list, tuple)) or not item:
                    raise BadMatchError(f"item {i}: must be a non-empty tuple")
                op = item[0]
                if op == "geocode" and len(item) == 2 and isinstance(item[1], str):
                    parsed.append(("geocode", (item[1],)))
                elif op == "reverse" and len(item) in (3, 4):
                    lat, lon = item[1], item[2]
                    tol = item[3] if len(item) == 4 else 1000
                    if isinstance(lat, bool) or not isinstance(lat, int):
                        raise BadMatchError(f"item {i}: lat must be int microdegrees")
                    if isinstance(lon, bool) or not isinstance(lon, int):
                        raise BadMatchError(f"item {i}: lon must be int microdegrees")
                    if isinstance(tol, bool) or not isinstance(tol, int) or tol < 0:
                        raise BadMatchError(f"item {i}: tolerance must be non-negative int")
                    parsed.append(("reverse", (lat, lon, tol)))
                else:
                    raise BadMatchError(f"item {i}: malformed (op, args)")
            # All items validated: now execute, one pinned result per item.
            self._batch_n += 1
            batch_id = f"batch-{self._batch_n}"
            results: List[BatchItemResult] = []
            item_pins: List[str] = []
            for index, (op, args) in enumerate(parsed):
                if op == "geocode":
                    res = self.geocode(args[0], self._last_seq + 1)
                    self._last_seq += 1
                    tier = res.match_kind
                    rpin = res.pin
                else:
                    lat, lon, tol = args
                    res = self.reverse(lat, lon, self._last_seq + 1, tol)
                    self._last_seq += 1
                    tier = "within" if res.within else "outside"
                    rpin = res.pin
                item_pins.append(rpin)
                results.append(BatchItemResult(
                    index=index,
                    op=op,
                    result_pin=rpin,
                    match_kind=tier,
                    pin=_pin(("batch-item", batch_id, index, op, tier, rpin, seq)),
                ))
            return BatchResult(
                batch_id=batch_id,
                item_count=len(results),
                items=tuple(results),
                pin=_pin(("batch", batch_id, len(results), tuple(item_pins), seq)),
            )


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------

def geocoder_audit_event(kind: str, seq: int, place_id: str = "") -> Dict[str, object]:
    """Shape an audit.ndjson/1 record. Ids + pins only; never address text
    or raw coordinates."""
    if kind not in _AUDIT_KINDS:
        raise GeocoderError(f"unknown audit kind: {kind!r}")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq <= 0:
        raise SequenceError("audit seq must be a positive int")
    if place_id:
        _check_place_id(place_id)
    return {
        "kind": kind,
        "seq": seq,
        "place_id": place_id,
        "version": VERSION,
        "schema": SCHEMA,
    }


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------

def main() -> None:
    g = Geocoder()
    r = g.register_place("sf", "San Francisco", 37774900, -122419400, 1,
                         aliases=["SF", "Frisco"], country="US")
    assert r.pin.startswith("sha256:")
    exact = g.geocode("san francisco", 2)
    assert exact.match_kind == "exact" and exact.lat_e6 == 37774900
    alias = g.geocode("frisco", 3)
    assert alias.match_kind == "alias"
    fuzzy = g.geocode("San Fransisco", 4)  # typo
    assert fuzzy.match_kind == "fuzzy"
    none = g.geocode("Nowhere XYZ 123", 5)
    assert none.match_kind == "none" and none.lat_e6 is None
    rev = g.reverse(37774900, -122419400, 6)
    assert rev.place_id == "sf" and rev.distance_m == 0 and rev.within
    batched = g.batch([("geocode", "SF"), ("reverse", 37774900, -122419400)], 7)
    assert batched.item_count == 2
    ev = geocoder_audit_event("geocoded", 8, place_id="sf")
    assert ev["schema"] == SCHEMA
    print("geocoder OK: register, geocode tiers, reverse, batch, audit")


if __name__ == "__main__":
    main()
