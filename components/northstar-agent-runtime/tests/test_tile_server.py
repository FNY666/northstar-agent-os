"""Tests for tile_server: slippy-map tile addressing bookkeeping."""

import ast
import unittest

from tile_server import (
    TILE_SERVER_VERSION,
    SCHEMA_PIN,
    MAX_LAT,
    MAX_ZOOM,
    MAX_TILES_ENUM,
    TILE_PX,
    AUDIT_KINDS,
    TileServer,
    BadCoordinateError,
    BadKindError,
    BadTileError,
    BadZoomError,
    SeqOrderError,
    TilesCapError,
    TileError,
    tile_server_audit_event,
)


class TestPins(unittest.TestCase):
    def test_version_and_schema(self):
        self.assertEqual(TILE_SERVER_VERSION, "tile-server.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.tile-server.v1")

    def test_stdlib_only(self):
        tree = ast.parse(open("tile_server.py").read())
        allowed = {
            "hashlib", "math", "threading", "dataclasses", "typing",
            "__future__", "json", "canonical_json",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn(node.module.split(".")[0], allowed)


class TestTile(unittest.TestCase):
    def test_world_tile_at_zero_zoom(self):
        t = TileServer().tile(0.0, 0.0, 0, 1)
        self.assertEqual((t.x, t.y), (0, 0))
        self.assertEqual(t.quadkey, "")

    def test_known_tile_london(self):
        # 51.5 N, 0.12 W at z=10 -> x = floor(179.88/360*1024) = 511
        t = TileServer().tile(51.5, -0.12, 10, 1)
        self.assertEqual(t.x, 511)
        self.assertGreaterEqual(t.y, 0)
        self.assertLess(t.y, 1 << 10)

    def test_antimeridian_clamps_to_last_tile(self):
        t = TileServer().tile(0.0, 180.0, 2, 1)
        self.assertEqual(t.x, 3)

    def test_pin_determinism(self):
        a = TileServer().tile(10.0, 20.0, 5, 1)
        b = TileServer().tile(10.0, 20.0, 5, 2)
        self.assertEqual(a.pin, b.pin)
        self.assertTrue(a.pin.startswith("sha256:"))


class TestRefusals(unittest.TestCase):
    def setUp(self):
        self.s = TileServer()

    def test_lat_outside_mercator_limit(self):
        with self.assertRaises(BadCoordinateError):
            self.s.tile(90.0, 0.0, 3, 1)

    def test_lon_beyond_180(self):
        with self.assertRaises(BadCoordinateError):
            self.s.tile(0.0, 181.0, 3, 1)

    def test_nan_lat_refused(self):
        with self.assertRaises(BadCoordinateError):
            self.s.tile(float("nan"), 0.0, 3, 1)

    def test_bad_zoom(self):
        with self.assertRaises(BadZoomError):
            self.s.tile(0.0, 0.0, MAX_ZOOM + 1, 1)
        with self.assertRaises(BadZoomError):
            self.s.zoom(-1, 2)

    def test_seq_rewind(self):
        self.s.tile(0.0, 0.0, 0, 5)
        with self.assertRaises(SeqOrderError):
            self.s.tile(0.0, 0.0, 0, 5)
        with self.assertRaises(SeqOrderError):
            self.s.tile(0.0, 0.0, 0, True)

    def test_bad_tile_address(self):
        with self.assertRaises(BadTileError):
            self.s.bbox(1, 2, 0, 1)  # x=2 invalid at z=1

    def test_enum_cap(self):
        # whole world at z=10 -> 2^20 tiles, over the cap
        with self.assertRaises(TilesCapError):
            self.s.tiles_for_bbox(-180.0, -MAX_LAT, 180.0, MAX_LAT, 10, 1)


class TestBbox(unittest.TestCase):
    def test_world_bbox(self):
        b = TileServer().bbox(0, 0, 0, 1)
        self.assertAlmostEqual(b.west, -180.0)
        self.assertAlmostEqual(b.east, 180.0)
        self.assertAlmostEqual(b.north, MAX_LAT, places=6)
        self.assertAlmostEqual(b.south, -MAX_LAT, places=6)

    def test_tile_center_roundtrip(self):
        s = TileServer()
        t = s.tile(37.77, -122.41, 12, 1)
        b = s.bbox(12, t.x, t.y, 2)
        self.assertLessEqual(b.west, -122.41)
        self.assertGreaterEqual(b.east, -122.41)
        self.assertLessEqual(b.south, 37.77)
        self.assertGreaterEqual(b.north, 37.77)

    def test_zoom_record(self):
        z = TileServer().zoom(3, 1)
        self.assertEqual(z.tiles_per_side, 8)
        self.assertEqual(z.total_tiles, 64)
        self.assertEqual(z.tile_px, TILE_PX)


class TestQuadkeyNeighborsEnum(unittest.TestCase):
    def test_quadkey_digits(self):
        s = TileServer()
        self.assertEqual(s.quadkey(1, 0, 0, 1).quadkey, "0")
        self.assertEqual(s.quadkey(1, 1, 0, 2).quadkey, "1")
        self.assertEqual(s.quadkey(1, 0, 1, 3).quadkey, "2")
        self.assertEqual(s.quadkey(1, 1, 1, 4).quadkey, "3")
        self.assertEqual(len(s.quadkey(5, 3, 7, 5).quadkey), 5)

    def test_neighbors_wrap_east_west(self):
        n = TileServer().neighbors(1, 0, 0, 1)
        self.assertIn((1, 0), n.neighbors)  # wraps across antimeridian
        self.assertIn((0, 1), n.neighbors)  # south neighbor exists

    def test_neighbors_clamp_poles(self):
        n = TileServer().neighbors(2, 1, 0, 1)  # northern edge
        for nx, ny in n.neighbors:
            self.assertGreaterEqual(ny, 0)

    def test_enum_count(self):
        e = TileServer().tiles_for_bbox(-180.0, -MAX_LAT, 180.0, MAX_LAT, 1, 1)
        self.assertEqual(e.count, 4)
        self.assertEqual(len(e.tiles), 4)


class TestAudit(unittest.TestCase):
    def test_shapes(self):
        ev = tile_server_audit_event("tiled", 7, "sha256:abc")
        self.assertEqual(ev["schema"], SCHEMA_PIN)
        self.assertEqual(ev["kind"], "tiled")
        self.assertEqual(ev["seq"], 7)
        self.assertTrue(ev["pin"].startswith("sha256:"))

    def test_bad_kind(self):
        with self.assertRaises(BadKindError):
            tile_server_audit_event("nope", 1, "x")

    def test_kinds_set(self):
        self.assertIn("tiled", AUDIT_KINDS)
        self.assertIn("tiles-enumerated", AUDIT_KINDS)


class TestFrozenAndMain(unittest.TestCase):
    def test_records_frozen(self):
        t = TileServer().tile(0.0, 0.0, 0, 1)
        with self.assertRaises(Exception):
            t.x = 5  # type: ignore[misc]

    def test_error_hierarchy(self):
        for cls in (BadCoordinateError, BadZoomError, BadTileError,
                    TilesCapError, SeqOrderError):
            self.assertTrue(issubclass(cls, TileError))

    def test_audit_log_accumulates(self):
        s = TileServer()
        s.tile(0.0, 0.0, 0, 1)
        s.bbox(0, 0, 0, 2)
        self.assertEqual(len(s.audit_log()), 2)


if __name__ == "__main__":
    unittest.main()
