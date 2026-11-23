"""Points-of-interest search interface (Places-API shaped bookkeeping).

Research motivation: agent runtimes routinely need "what is near here" --
dispatch, delivery, field service, safety checks. Industry practice
(Google Places API, OSM Nominatim, Mapbox Geocoding, Foursquare Places)
converges on the same three bookkeeping primitives this module pins:

- *index*: a place_id -> POI record ledger (name, category, coordinates,
  address, rating, price level), digest-pinned so the ledger is
  auditable;
- *nearby*: a radius query over caller-supplied coordinates returning
  hits ordered by ascending distance (deterministic tie-break on
  place_id);
- *details*: full-record fetch for a pinned place_id.

This module is the *bookkeeping* half of that shape, following the
runtime's house discipline:

- ``POISearch`` -- ``index()`` registers an immutable POI,
  ``nearby()`` runs a deterministic radius query, ``details()``
  returns the full frozen record. ``remove()`` unlists a POI;
  ``places()`` / ``place_ids()`` are read views.
- ``poi_search_audit_event(kind, ...)`` -- ``audit.ndjson/1`` records
  (``indexed`` / ``queried`` / ``details-fetched`` / ``removed`` /
  ``rejected``); caller-supplied seqs only.

Fail-closed edges (fail loudly, never guess):

- place_id, name are non-empty ``str``; duplicates on ``index()``
  raise ``DuplicatePlaceError``.
- ``category`` must be a member of the pinned ``CATEGORIES`` set
  (Google-Places-style type vocabulary); unknown categories raise
  ``UnknownCategoryError`` at index time *and* at query time.
- Coordinates are finite floats (``NaN``/``inf`` refused, ``bool``
  refused); latitude in [-90, 90], longitude in [-180, 180]; radius
  must be positive and finite.
- ``rating`` (when given) in [0.0, 5.0]; ``price_level`` (when given)
  in [0, 4] ints (not bool).
- ``seq`` is a caller-supplied strictly-increasing ``int`` (no
  wall clock anywhere); bool/negative/non-int seqs refused with
  ``SeqOrderError``.
- ``nearby()`` never invents places: an empty radius result is an
  empty result, not an error; an unknown place_id on ``details()``
  raises ``UnknownPlaceError`` (fail-closed, never a fabricated
  record).

Honest scope:

- This module books *host-reported* places and coordinates. It cannot
  verify that a POI really exists at the claimed coordinates; a lying
  host gets a lying index. The digests bind the *reported* places to
  the decisions, not ground truth.
- Distances are great-circle (haversine) approximations on a sphere;
  no projection, no routing, no travel time -- pair with
  ``routing_engine`` for pathing and ``geocoder`` for address
  resolution.
- Everything is in-memory; pair with the durable audit writer if the
  index must survive a restart. ``main()`` self-checks the shape.
"""

from __future__ import annotations

import hashlib
import math
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        raw = _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

import canonical_json  # noqa: F401,E402  (documents the canonical path)

POI_SEARCH_VERSION = "poi-search.v1"
POI_SEARCH_SCHEMA = "northstar.poi-search.v1"
AUDIT_SCHEMA = "audit.ndjson/1"

# Google-Places-style type vocabulary, pinned as a closed set so the
# index never holds an unspellchecked category.
CATEGORIES = (
    "restaurant",
    "cafe",
    "bar",
    "bakery",
    "hotel",
    "gas_station",
    "charging_station",
    "parking",
    "hospital",
    "pharmacy",
    "clinic",
    "dentist",
    "atm",
    "bank",
    "supermarket",
    "convenience_store",
    "department_store",
    "museum",
    "park",
    "gym",
    "school",
    "library",
    "airport",
    "train_station",
    "bus_station",
    "subway_station",
    "post_office",
    "police",
    "fire_station",
    "church",
    "mosque",
    "synagogue",
    "temple",
    "cinema",
    "theater",
    "zoo",
    "aquarium",
    "stadium",
    "car_repair",
    "car_wash",
    "laundry",
    "hair_salon",
    "spa",
    "veterinary",
    "pet_store",
    "hardware_store",
    "furniture_store",
    "electronics_store",
    "clothing_store",
    "book_store",
    "florist",
)

_ALLOWED_CATEGORIES = frozenset(CATEGORIES)

# Mean Earth radius in metres (WGS-84 volumetric mean); pinned so
# distances replay byte-identically.
EARTH_RADIUS_M = 6_371_008.8

MAX_LIMIT = 100


# ---------------------------------------------------------------------------
# errors
# ---------------------------------------------------------------------------


class POIError(Exception):
    """Base error for the POI search module."""


class DuplicatePlaceError(POIError):
    """Raised when a place_id is indexed twice."""


class UnknownPlaceError(POIError):
    """Raised for a place_id that was never indexed (or was removed)."""


class UnknownCategoryError(POIError):
    """Raised for a category outside the pinned vocabulary."""


class InvalidCoordinateError(POIError):
    """Raised for out-of-range or non-finite coordinates."""


class InvalidRadiusError(POIError):
    """Raised for a non-positive or non-finite radius."""


class InvalidPOIError(POIError):
    """Raised when a POI record fails shape validation."""


class SeqOrderError(POIError):
    """Raised when a caller seq is not strictly increasing."""


# ---------------------------------------------------------------------------
# frozen records
# ---------------------------------------------------------------------------


def _digest(payload: Mapping[str, Any]) -> str:
    return "sha256:" + jcs_sha256_hex(payload)


@dataclass(frozen=True)
class POIRecord:
    """An immutable indexed place of interest."""

    place_id: str
    name: str
    category: str
    latitude: float
    longitude: float
    address: str
    rating: Optional[float]
    price_level: Optional[int]
    digest: str
    version: str = POI_SEARCH_VERSION
    schema: str = POI_SEARCH_SCHEMA


@dataclass(frozen=True)
class POIHit:
    """One nearby-query hit: the place plus its distance."""

    place: POIRecord
    distance_m: float


@dataclass(frozen=True)
class NearbyResult:
    """Frozen result of a ``nearby()`` query."""

    latitude: float
    longitude: float
    radius_m: float
    category: Optional[str]
    hits: Tuple[POIHit, ...]
    digest: str
    version: str = POI_SEARCH_VERSION
    schema: str = POI_SEARCH_SCHEMA


@dataclass(frozen=True)
class POIDetails:
    """Full detail view for a single place."""

    place: POIRecord
    digest: str
    version: str = POI_SEARCH_VERSION
    schema: str = POI_SEARCH_SCHEMA


# ---------------------------------------------------------------------------
# validation helpers
# ---------------------------------------------------------------------------


def _check_seq(seq: Any, last: int) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SeqOrderError("seq must be an int, not %r" % (type(seq).__name__,))
    if seq < 0:
        raise SeqOrderError("seq must be non-negative")
    if seq <= last:
        raise SeqOrderError("seq must be strictly increasing (last=%d)" % last)
    return seq


def _check_coord(value: Any, name: str, lo: float, hi: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise InvalidCoordinateError("%s must be a number" % name)
    f = float(value)
    if not math.isfinite(f):
        raise InvalidCoordinateError("%s must be finite" % name)
    if not (lo <= f <= hi):
        raise InvalidCoordinateError(
            "%s %r out of range [%s, %s]" % (name, f, lo, hi))
    return f


def _haversine_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    r = math.radians
    dlat = r(lat2 - lat1)
    dlon = r(lon2 - lon1)
    a = (math.sin(dlat / 2) ** 2
         + math.cos(r(lat1)) * math.cos(r(lat2)) * math.sin(dlon / 2) ** 2)
    return 2 * EARTH_RADIUS_M * math.asin(math.sqrt(a))


def _check_rating(value: Any) -> Optional[float]:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise InvalidPOIError("rating must be a number in [0.0, 5.0]")
    f = float(value)
    if not math.isfinite(f) or not (0.0 <= f <= 5.0):
        raise InvalidPOIError("rating %r out of range [0.0, 5.0]" % (value,))
    return f


def _check_price_level(value: Any) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise InvalidPOIError("price_level must be an int in [0, 4]")
    if not (0 <= value <= 4):
        raise InvalidPOIError("price_level %r out of range [0, 4]" % (value,))
    return value


# ---------------------------------------------------------------------------
# audit events
# ---------------------------------------------------------------------------


AUDIT_KINDS = ("indexed", "queried", "details-fetched", "removed", "rejected")


def poi_search_audit_event(kind: str, seq: int, detail: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    """Build an ``audit.ndjson/1`` event record for POI search.

    Only ids, categories and digest pins cross the audit boundary --
    never names, addresses, or ratings.
    """
    if kind not in AUDIT_KINDS:
        raise POIError("unknown audit kind %r" % (kind,))
    _check_seq(seq, -1)  # shape check only; ordering is the caller's
    event: Dict[str, Any] = {
        "kind": kind,
        "seq": seq,
        "schema": AUDIT_SCHEMA,
        "module": POI_SEARCH_SCHEMA,
    }
    if detail:
        event["detail"] = dict(detail)
    return event


# ---------------------------------------------------------------------------
# POI search
# ---------------------------------------------------------------------------


class POISearch:
    """Deterministic in-memory POI index with radius queries.

    House discipline: frozen dataclasses out, caller-supplied strictly
    increasing int seqs, RLock-guarded, fail-closed, stdlib-only.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._places: Dict[str, POIRecord] = {}
        self._last_seq = -1

    # -- views ----------------------------------------------------------

    def place_ids(self) -> Tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._places))

    def place_count(self) -> int:
        with self._lock:
            return len(self._places)

    # -- mutations ------------------------------------------------------

    def index(
        self,
        place_id: str,
        name: str,
        category: str,
        latitude: Any,
        longitude: Any,
        seq: int,
        *,
        address: str = "",
        rating: Any = None,
        price_level: Any = None,
    ) -> POIRecord:
        """Register a POI. Returns the frozen, digest-pinned record."""
        with self._lock:
            self._last_seq = _check_seq(seq, self._last_seq)
            if not isinstance(place_id, str) or not place_id:
                raise InvalidPOIError("place_id must be a non-empty str")
            if place_id in self._places:
                raise DuplicatePlaceError("place_id %r already indexed" % place_id)
            if not isinstance(name, str) or not name:
                raise InvalidPOIError("name must be a non-empty str")
            if category not in _ALLOWED_CATEGORIES:
                raise UnknownCategoryError("unknown category %r" % (category,))
            lat = _check_coord(latitude, "latitude", -90.0, 90.0)
            lon = _check_coord(longitude, "longitude", -180.0, 180.0)
            if not isinstance(address, str):
                raise InvalidPOIError("address must be a str")
            r = _check_rating(rating)
            p = _check_price_level(price_level)
            digest = _digest({
                "place_id": place_id,
                "name": name,
                "category": category,
                "latitude": lat,
                "longitude": lon,
                "address": address,
                "rating": r,
                "price_level": p,
                "module": POI_SEARCH_SCHEMA,
                "version": POI_SEARCH_VERSION,
            })
            record = POIRecord(
                place_id=place_id, name=name, category=category,
                latitude=lat, longitude=lon, address=address,
                rating=r, price_level=p, digest=digest,
            )
            self._places[place_id] = record
            return record

    def remove(self, place_id: str, seq: int) -> None:
        """Unlist a POI. Unknown ids raise fail-closed."""
        with self._lock:
            self._last_seq = _check_seq(seq, self._last_seq)
            if place_id not in self._places:
                raise UnknownPlaceError("unknown place_id %r" % (place_id,))
            del self._places[place_id]

    # -- queries --------------------------------------------------------

    def nearby(
        self,
        latitude: Any,
        longitude: Any,
        radius_m: Any,
        seq: int,
        *,
        category: Optional[str] = None,
        min_rating: Any = None,
        limit: int = 20,
    ) -> NearbyResult:
        """Radius query. Hits sorted by ascending distance, ties by place_id."""
        with self._lock:
            self._last_seq = _check_seq(seq, self._last_seq)
            lat = _check_coord(latitude, "latitude", -90.0, 90.0)
            lon = _check_coord(longitude, "longitude", -180.0, 180.0)
            if (isinstance(radius_m, bool) or not isinstance(radius_m, (int, float))
                    or not math.isfinite(float(radius_m)) or float(radius_m) <= 0):
                raise InvalidRadiusError("radius_m must be a positive finite number")
            radius = float(radius_m)
            if category is not None and category not in _ALLOWED_CATEGORIES:
                raise UnknownCategoryError("unknown category %r" % (category,))
            rating_floor = _check_rating(min_rating)
            if isinstance(limit, bool) or not isinstance(limit, int) or not (1 <= limit <= MAX_LIMIT):
                raise InvalidPOIError("limit must be an int in [1, %d]" % MAX_LIMIT)

            hits: List[POIHit] = []
            for place in self._places.values():
                if category is not None and place.category != category:
                    continue
                if rating_floor is not None and (place.rating is None or place.rating < rating_floor):
                    continue
                dist = _haversine_m(lat, lon, place.latitude, place.longitude)
                if dist <= radius:
                    hits.append(POIHit(place=place, distance_m=dist))
            hits.sort(key=lambda h: (h.distance_m, h.place.place_id))
            hits = hits[:limit]
            digest = _digest({
                "latitude": lat,
                "longitude": lon,
                "radius_m": radius,
                "category": category,
                "min_rating": rating_floor,
                "limit": limit,
                "hit_ids": [h.place.place_id for h in hits],
                "module": POI_SEARCH_SCHEMA,
                "version": POI_SEARCH_VERSION,
            })
            return NearbyResult(
                latitude=lat, longitude=lon, radius_m=radius,
                category=category, hits=tuple(hits), digest=digest,
            )

    def details(self, place_id: str, seq: int) -> POIDetails:
        """Full detail view for one place. Unknown ids raise fail-closed."""
        with self._lock:
            self._last_seq = _check_seq(seq, self._last_seq)
            place = self._places.get(place_id)
            if place is None:
                raise UnknownPlaceError("unknown place_id %r" % (place_id,))
            digest = _digest({
                "place_id": place_id,
                "place_digest": place.digest,
                "module": POI_SEARCH_SCHEMA,
                "version": POI_SEARCH_VERSION,
            })
            return POIDetails(place=place, digest=digest)


def main() -> None:
    """Self-check the module shape."""
    ps = POISearch()
    ps.index("p1", "Noodle House", "restaurant", 22.30, 114.17, 1,
             address="1 Main St", rating=4.5, price_level=2)
    ps.index("p2", "City Hospital", "hospital", 22.31, 114.18, 2,
             address="2 Health Rd")
    res = ps.nearby(22.30, 114.17, 5000.0, 3)
    assert len(res.hits) == 2, "both POIs within 5km"
    assert res.hits[0].place.place_id == "p1", "nearest first"
    det = ps.details("p1", 4)
    assert det.place.name == "Noodle House"
    ps.remove("p2", 5)
    assert ps.place_count() == 1
    print("poi-search OK: index, nearby, details, remove")


if __name__ == "__main__":
    main()
