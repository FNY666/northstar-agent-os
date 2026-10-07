"""Slippy-map tile addressing, in-memory.

Research note: slippy tiles (OpenStreetMap/Google "Slippy map tilenames") cut
the Web Mercator projection into a z-ordered quadtree. At zoom ``z`` the
world is ``2**z`` x ``2**z`` square tiles of 256 px; a tile is addressed by
``(z, x, y)`` where ``x`` grows east and ``y`` grows south from the northwest
corner. Quadkeys interleave the x/y bits into a base-4 string ("t", "q", "r",
"s" in the Bing convention; here plain digits). The load-bearing production
concerns, all kept here:

* **Fail-closed geometry** -- lat is clamped to the Web Mercator limit
  (+/-85.05112878 deg) and out-of-range latitudes, |lon| > 180, and zoom
  outside the pinned range raise instead of producing a wrong tile.
* **Deterministic addressing** -- every address is a pure function of
  (lat, lon, zoom); identical inputs replay to byte-identical tile ids,
  bboxes, and digest pins.
* **Pins, not claims** -- each record carries a ``sha256:`` pin over the
  canonical address triple, so a tampered tile no longer verifies. The pin
  proves internal consistency, never that a host rendered those pixels.
* **Enumerations are bounded** -- ``tiles_for_bbox()`` refuses to enumerate
  more than ``MAX_TILES_ENUM`` tiles fail-closed instead of materializing a
  denial-of-service-sized list.
* **Strict seqs** -- every call takes a caller-supplied strictly increasing
  int seq; the module never touches the wall clock.

Honest scope: this is *address bookkeeping* for slippy tiles, not a tile
renderer -- it emits no PNGs, serves no HTTP, and cannot prove a tile was
rendered. Geo inherently needs floats (lat/lon/bbox bounds): they are
accepted, NaN/inf are refused fail-closed, and pins bind the exact float
bits (two hosts computing with the same IEEE-754 inputs pin identically).
``lon == 180`` maps to the last tile of the row (``x = 2**z - 1``), i.e. the
antimeridian is clamped, not wrapped; east/west neighbor wrap-around does
wrap (the world is a cylinder), while north/south neighbors clamp at the
poles. Real deployments hand the pinned addresses to a tile renderer and
record its digest here.

Version pin: tile-server.v1
Schema pin: northstar.tile-server.v1
"""

from __future__ import annotations

import hashlib
import math
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
TILE_SERVER_VERSION = "tile-server.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.tile-server.v1"

#: Web Mercator latitude limit: the projection diverges at the poles.
MAX_LAT = 85.0511287798066

#: Lowest and highest zoom this module will address (pinned).
MIN_ZOOM = 0
MAX_ZOOM = 22

#: Simulated pixel edge of one tile.
TILE_PX = 256

#: Fail-closed cap on bbox enumeration so a world-zoom query cannot be
#: materialized into a memory bomb.
MAX_TILES_ENUM = 1024

#: Audit event kinds emitted by this module.
AUDIT_KINDS: FrozenSet[str] = frozenset(
    {
        "tiled",
        "bbox-built",
        "zoom-validated",
        "quadkey-built",
        "neighbors-listed",
        "tiles-enumerated",
        "rejected",
    }
)


# ---------------------------------------------------------------------------
# Fail-closed error taxonomy.
# ---------------------------------------------------------------------------


class TileError(ValueError):
    """Base class for every fail-closed refusal in this module."""


class BadCoordinateError(TileError):
    """A latitude/longitude or bbox bound is out of range or non-finite."""


class BadZoomError(TileError):
    """A zoom level is outside the pinned [MIN_ZOOM, MAX_ZOOM] range."""


class BadTileError(TileError):
    """A (z, x, y) address is outside the valid range for its zoom."""


class TilesCapError(TileError):
    """A bbox enumeration would exceed MAX_TILES_ENUM tiles."""


class SeqOrderError(TileError):
    """A caller seq did not strictly increase (or was not an int)."""


class BadKindError(TileError):
    """An unknown audit kind was requested."""


def _pin(*parts: Any) -> str:
    """Return a ``sha256:`` digest pin over type-tagged canonical parts."""
    tagged: List[Any] = []
    for p in parts:
        if isinstance(p, bool):
            tagged.append(("bool", p))
        elif isinstance(p, int):
            tagged.append(("int", p))
        elif isinstance(p, float):
            # Bind the exact IEEE-754 bits; NaN/inf never reach here.
            tagged.append(("float", repr(p)))
        elif isinstance(p, str):
            tagged.append(("str", p))
        elif isinstance(p, (tuple, list)):
            tagged.append(("list", list(p)))
        elif p is None:
            tagged.append(("none", 0))
        else:  # pragma: no cover - defensive
            raise TileError(f"unpinable part: {type(p).__name__}")
    return "sha256:" + hashlib.sha256(jcs_canonical_json(tagged)).hexdigest()


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SeqOrderError(f"seq must be a non-negative int, got {seq!r}")
    return seq


def _check_finite(name: str, value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise BadCoordinateError(f"{name} must be a number, got {value!r}")
    fval = float(value)
    if not math.isfinite(fval):
        raise BadCoordinateError(f"{name} must be finite, got {value!r}")
    return fval


def _check_zoom(zoom: Any) -> int:
    if isinstance(zoom, bool) or not isinstance(zoom, int):
        raise BadZoomError(f"zoom must be an int, got {zoom!r}")
    if not (MIN_ZOOM <= zoom <= MAX_ZOOM):
        raise BadZoomError(f"zoom {zoom} outside [{MIN_ZOOM}, {MAX_ZOOM}]")
    return zoom


# ---------------------------------------------------------------------------
# Core Web Mercator math (pure).
# ---------------------------------------------------------------------------


def _latlon_to_xy(lat: float, lon: float, zoom: int) -> Tuple[int, int]:
    n = 1 << zoom
    x = int(math.floor((lon + 180.0) / 360.0 * n))
    lat_rad = math.radians(lat)
    merc = math.log(math.tan(lat_rad) + 1.0 / math.cos(lat_rad))
    y = int(math.floor((1.0 - merc / math.pi) / 2.0 * n))
    return min(max(x, 0), n - 1), min(max(y, 0), n - 1)


def _xy_to_bbox(zoom: int, x: int, y: int) -> Tuple[float, float, float, float]:
    """Return (west, south, east, north) in degrees for tile (z, x, y)."""
    n = 1 << zoom
    west = x / n * 360.0 - 180.0
    east = (x + 1) / n * 360.0 - 180.0

    def _lat_for(ty: int) -> float:
        merc = math.pi * (1.0 - 2.0 * ty / n)
        return math.degrees(math.atan(math.sinh(merc)))

    north = _lat_for(y)
    south = _lat_for(y + 1)
    return west, south, east, north


def _encode_quadkey(zoom: int, x: int, y: int) -> str:
    digits = []
    for z in range(zoom, 0, -1):
        digit = 0
        mask = 1 << (z - 1)
        if x & mask:
            digit |= 1
        if y & mask:
            digit |= 2
        digits.append(str(digit))
    return "".join(digits)


# ---------------------------------------------------------------------------
# Frozen records.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TileRecord:
    """The tile containing a (lat, lon) point at a zoom."""

    zoom: int
    x: int
    y: int
    quadkey: str
    lat: float
    lon: float
    pin: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "zoom": self.zoom,
            "x": self.x,
            "y": self.y,
            "quadkey": self.quadkey,
            "lat": self.lat,
            "lon": self.lon,
            "pin": self.pin,
        }


@dataclass(frozen=True)
class BBoxRecord:
    """Geographic bounds of one tile, in degrees."""

    zoom: int
    x: int
    y: int
    west: float
    south: float
    east: float
    north: float
    pin: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "zoom": self.zoom,
            "x": self.x,
            "y": self.y,
            "west": self.west,
            "south": self.south,
            "east": self.east,
            "north": self.north,
            "pin": self.pin,
        }


@dataclass(frozen=True)
class ZoomRecord:
    """Validation + metadata for a zoom level."""

    zoom: int
    tiles_per_side: int
    total_tiles: int
    tile_px: int
    pin: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "zoom": self.zoom,
            "tiles_per_side": self.tiles_per_side,
            "total_tiles": self.total_tiles,
            "tile_px": self.tile_px,
            "pin": self.pin,
        }


@dataclass(frozen=True)
class QuadkeyRecord:
    """Quadkey string for a tile address, plus its decomposition."""

    zoom: int
    x: int
    y: int
    quadkey: str
    pin: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "zoom": self.zoom,
            "x": self.x,
            "y": self.y,
            "quadkey": self.quadkey,
            "pin": self.pin,
        }


@dataclass(frozen=True)
class NeighborsRecord:
    """The 8 neighbors of a tile; x wraps at the antimeridian, y clamps."""

    zoom: int
    x: int
    y: int
    neighbors: Tuple[Tuple[int, int], ...]
    pin: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "zoom": self.zoom,
            "x": self.x,
            "y": self.y,
            "neighbors": [list(p) for p in self.neighbors],
            "pin": self.pin,
        }


@dataclass(frozen=True)
class TilesEnumRecord:
    """The tile set intersecting a bbox at a zoom, with a digest pin."""

    zoom: int
    west: float
    south: float
    east: float
    north: float
    count: int
    tiles: Tuple[Tuple[int, int], ...]
    pin: str

    def as_dict(self) -> Dict[str, Any]:
        return {
            "zoom": self.zoom,
            "west": self.west,
            "south": self.south,
            "east": self.east,
            "north": self.north,
            "count": self.count,
            "tiles": [list(p) for p in self.tiles],
            "pin": self.pin,
        }


# ---------------------------------------------------------------------------
# The server.
# ---------------------------------------------------------------------------


class TileServer:
    """Deterministic slippy-tile addressing with a monotonic seq ledger."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = -1
        self._audit: List[Dict[str, Any]] = []

    # -- internals ------------------------------------------------------

    def _consume_seq(self, seq: Any) -> int:
        seq = _check_seq(seq)
        with self._lock:
            if seq <= self._last_seq:
                self._audit.append(tile_server_audit_event("rejected", seq, "seq-rewind"))
                raise SeqOrderError(
                    f"seq {seq} does not exceed last seq {self._last_seq}"
                )
            self._last_seq = seq
        return seq

    def _validate_address(self, zoom: int, x: int, y: int) -> None:
        n = 1 << zoom
        for name, v in (("x", x), ("y", y)):
            if isinstance(v, bool) or not isinstance(v, int):
                raise BadTileError(f"{name} must be an int, got {v!r}")
            if not (0 <= v < n):
                raise BadTileError(
                    f"{name}={v} outside [0, {n}) for zoom {zoom}"
                )

    # -- public API -----------------------------------------------------

    def tile(self, lat: Any, lon: Any, zoom: Any, seq: Any) -> TileRecord:
        """Return the tile containing (lat, lon) at zoom."""
        seq = self._consume_seq(seq)
        z = _check_zoom(zoom)
        flat = _check_finite("lat", lat)
        flon = _check_finite("lon", lon)
        if not (-MAX_LAT <= flat <= MAX_LAT):
            raise BadCoordinateError(
                f"lat {flat} outside Web Mercator limit +/-{MAX_LAT}"
            )
        if not (-180.0 <= flon <= 180.0):
            raise BadCoordinateError(f"lon {flon} outside [-180, 180]")
        if flon == 180.0:  # clamp the antimeridian into the last tile
            flon = -180.0 + (360.0 - 1e-9)
        x, y = _latlon_to_xy(flat, flon, z)
        qk = _encode_quadkey(z, x, y)
        pin = _pin(("tile",), z, x, y, qk, flat, flon)
        rec = TileRecord(zoom=z, x=x, y=y, quadkey=qk, lat=flat, lon=flon, pin=pin)
        with self._lock:
            self._audit.append(tile_server_audit_event("tiled", seq, pin))
        return rec

    def bbox(self, zoom: Any, x: Any, y: Any, seq: Any) -> BBoxRecord:
        """Return the geographic bounds of tile (z, x, y)."""
        seq = self._consume_seq(seq)
        z = _check_zoom(zoom)
        self._validate_address(z, x, y)
        west, south, east, north = _xy_to_bbox(z, x, y)
        pin = _pin(("bbox",), z, x, y, west, south, east, north)
        rec = BBoxRecord(
            zoom=z, x=x, y=y,
            west=west, south=south, east=east, north=north, pin=pin,
        )
        with self._lock:
            self._audit.append(tile_server_audit_event("bbox-built", seq, pin))
        return rec

    def zoom(self, zoom: Any, seq: Any) -> ZoomRecord:
        """Validate a zoom level and return its metadata."""
        seq = self._consume_seq(seq)
        z = _check_zoom(zoom)
        side = 1 << z
        total = side * side
        pin = _pin(("zoom",), z, side, total, TILE_PX)
        rec = ZoomRecord(zoom=z, tiles_per_side=side, total_tiles=total,
                         tile_px=TILE_PX, pin=pin)
        with self._lock:
            self._audit.append(tile_server_audit_event("zoom-validated", seq, pin))
        return rec

    def quadkey(self, zoom: Any, x: Any, y: Any, seq: Any) -> QuadkeyRecord:
        """Return the quadkey string for tile (z, x, y)."""
        seq = self._consume_seq(seq)
        z = _check_zoom(zoom)
        self._validate_address(z, x, y)
        qk = _encode_quadkey(z, x, y)
        pin = _pin(("quadkey",), z, x, y, qk)
        rec = QuadkeyRecord(zoom=z, x=x, y=y, quadkey=qk, pin=pin)
        with self._lock:
            self._audit.append(tile_server_audit_event("quadkey-built", seq, pin))
        return rec

    def neighbors(self, zoom: Any, x: Any, y: Any, seq: Any) -> NeighborsRecord:
        """Return the 8 neighbors of (z, x, y): x wraps, y clamps."""
        seq = self._consume_seq(seq)
        z = _check_zoom(zoom)
        self._validate_address(z, x, y)
        n = 1 << z
        found = set()
        for dy in (-1, 0, 1):
            for dx in (-1, 0, 1):
                if dx == 0 and dy == 0:
                    continue
                nx = (x + dx) % n  # the world is a cylinder east-west
                ny = min(max(y + dy, 0), n - 1)  # clamped at the poles
                found.add((nx, ny))
        nbrs = tuple(sorted(found))
        pin = _pin(("neighbors",), z, x, y, list(nbrs))
        rec = NeighborsRecord(zoom=z, x=x, y=y, neighbors=nbrs, pin=pin)
        with self._lock:
            self._audit.append(tile_server_audit_event("neighbors-listed", seq, pin))
        return rec

    def tiles_for_bbox(
        self,
        west: Any,
        south: Any,
        east: Any,
        north: Any,
        zoom: Any,
        seq: Any,
    ) -> TilesEnumRecord:
        """Enumerate the tiles intersecting a bbox at zoom (fail-closed cap)."""
        seq = self._consume_seq(seq)
        z = _check_zoom(zoom)
        fwest = _check_finite("west", west)
        fsouth = _check_finite("south", south)
        feast = _check_finite("east", east)
        fnorth = _check_finite("north", north)
        if not (-180.0 <= fwest <= 180.0 and -180.0 <= feast <= 180.0):
            raise BadCoordinateError("bbox longitudes must be in [-180, 180]")
        if not (-MAX_LAT <= fsouth <= MAX_LAT and -MAX_LAT <= fnorth <= MAX_LAT):
            raise BadCoordinateError(
                f"bbox latitudes must be in [-{MAX_LAT}, {MAX_LAT}]"
            )
        if fsouth > fnorth:
            raise BadCoordinateError("south must not exceed north")
        if fwest > feast:
            raise BadCoordinateError(
                "west must not exceed east (antimeridian-spanning boxes unsupported)"
            )
        n = 1 << z
        x0, y0 = _latlon_to_xy(fnorth, fwest, z)   # northwest corner
        x1, y1 = _latlon_to_xy(fsouth, feast, z)   # southeast corner
        count = (x1 - x0 + 1) * (y1 - y0 + 1)
        if count > MAX_TILES_ENUM:
            raise TilesCapError(
                f"{count} tiles exceed cap {MAX_TILES_ENUM}"
            )
        tiles = tuple(
            (x, y) for y in range(y0, y1 + 1) for x in range(x0, x1 + 1)
        )
        pin = _pin(("tiles-enum",), z, fwest, fsouth, feast, fnorth,
                   list(tiles))
        rec = TilesEnumRecord(
            zoom=z, west=fwest, south=fsouth, east=feast, north=fnorth,
            count=len(tiles), tiles=tiles, pin=pin,
        )
        with self._lock:
            self._audit.append(
                tile_server_audit_event("tiles-enumerated", seq, pin)
            )
        return rec

    # -- views ----------------------------------------------------------

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            return tuple(dict(e) for e in self._audit)


# ---------------------------------------------------------------------------
# Audit events shaped for audit.ndjson/1.
# ---------------------------------------------------------------------------


def tile_server_audit_event(
    kind: str, seq: int, detail: str
) -> Dict[str, Any]:
    """Build an audit event record (ids/digest pins only, never geometry)."""
    if kind not in AUDIT_KINDS:
        raise BadKindError(f"unknown audit kind: {kind!r}")
    seq = _check_seq(seq)
    if not isinstance(detail, str):
        raise TileError("detail must be a string")
    body = {
        "schema": SCHEMA_PIN,
        "version": TILE_SERVER_VERSION,
        "kind": kind,
        "seq": seq,
        "detail": detail,
    }
    body["pin"] = _pin(("audit",), kind, seq, detail)
    return body


def main() -> None:
    srv = TileServer()
    t = srv.tile(0.0, 0.0, 0, 1)
    assert (t.x, t.y) == (0, 0) and t.quadkey == ""
    b = srv.bbox(0, 0, 0, 2)
    assert abs(b.west + 180.0) < 1e-9 and abs(b.east - 180.0) < 1e-9
    z = srv.zoom(3, 3)
    assert z.tiles_per_side == 8 and z.total_tiles == 64
    q = srv.quadkey(1, 1, 1, 4)
    assert q.quadkey == "3"
    n = srv.neighbors(1, 0, 0, 5)
    assert (1, 0) in n.neighbors  # wraps east-west
    e = srv.tiles_for_bbox(-180.0, -MAX_LAT, 180.0, MAX_LAT, 1, 6)
    assert e.count == 4
    print("tile-server OK: tile, bbox, zoom, quadkey, neighbors, enum")
    print(f"  pins: {t.pin[:20]}... {b.pin[:20]}...")


if __name__ == "__main__":
    main()
