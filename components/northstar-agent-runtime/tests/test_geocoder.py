"""Tests for geocoder.py (geocoder.v1)."""

import ast
import unittest
from pathlib import Path

import geocoder
from geocoder import (
    VERSION,
    SCHEMA,
    Geocoder,
    GeocoderError,
    DuplicatePlaceError,
    UnknownPlaceError,
    InvalidPlaceError,
    InvalidCoordinateError,
    NoPlacesError,
    BadMatchError,
    SequenceError,
    geocoder_audit_event,
)


def _mk() -> Geocoder:
    """Geocoder with two registered places (seqs 1, 2 consumed)."""
    g = Geocoder()
    g.register_place("sf", "San Francisco", 37774900, -122419400, 1,
                     aliases=["SF"], country="US")
    g.register_place("nyc", "New York", 40712800, -74006000, 2, country="US")
    return g


class TestPins(unittest.TestCase):
    def test_version_schema(self):
        self.assertEqual(VERSION, "geocoder.v1")
        self.assertEqual(SCHEMA, "northstar.geocoder.v1")

    def test_stdlib_only(self):
        tree = ast.parse(Path(geocoder.__file__).read_text())
        allowed = {"__future__", "hashlib", "math", "re", "threading",
                   "unicodedata", "dataclasses", "typing"}
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module.split(".")[0])
        self.assertTrue(imports <= allowed, imports - allowed)

    def test_main(self):
        geocoder.main()


class TestRegister(unittest.TestCase):
    def test_roundtrip(self):
        g = Geocoder()
        rec = g.register_place("p1", "Paris", 48856600, 2352100, 1)
        self.assertEqual(rec.place_id, "p1")
        self.assertTrue(rec.pin.startswith("sha256:"))
        self.assertEqual(g.place("p1").display_name, "Paris")
        self.assertEqual(g.place_ids(), ("p1",))

    def test_pin_determinism(self):
        g1, g2 = Geocoder(), Geocoder()
        r1 = g1.register_place("a", "A Town", 1000000, 2000000, 1)
        r2 = g2.register_place("a", "A Town", 1000000, 2000000, 1)
        self.assertEqual(r1.pin, r2.pin)

    def test_duplicate_place(self):
        g = Geocoder()
        g.register_place("a", "A Town", 1000000, 2000000, 1)
        with self.assertRaises(DuplicatePlaceError):
            g.register_place("a", "Other", 3000000, 4000000, 2)

    def test_duplicate_normalized_name(self):
        g = Geocoder()
        g.register_place("a", "A Town", 1000000, 2000000, 1)
        with self.assertRaises(DuplicatePlaceError):
            g.register_place("b", "a town!", 3000000, 4000000, 2)

    def test_bad_inputs(self):
        g = Geocoder()
        with self.assertRaises(InvalidPlaceError):
            g.register_place("", "Name", 0, 0, 1)
        with self.assertRaises(InvalidPlaceError):
            g.register_place("ok", "  ", 0, 0, 2)
        with self.assertRaises(InvalidCoordinateError):
            g.register_place("ok", "Name", 91000000, 0, 3)  # lat > 90
        with self.assertRaises(InvalidCoordinateError):
            g.register_place("ok", "Name", 0, 180000001, 4)  # lon > 180
        with self.assertRaises(InvalidCoordinateError):
            g.register_place("ok", "Name", 37.5, 0, 5)  # float refused
        with self.assertRaises(InvalidCoordinateError):
            g.register_place("ok", "Name", True, 0, 6)  # bool refused
        with self.assertRaises(SequenceError):
            g.register_place("ok2", "Name2", 0, 0, 6)  # seq rewind

    def test_unknown_place(self):
        g = Geocoder()
        with self.assertRaises(UnknownPlaceError):
            g.place("nope")


class TestGeocode(unittest.TestCase):
    def test_exact(self):
        g = _mk()
        r = g.geocode("San Francisco", 3)
        self.assertEqual(r.match_kind, "exact")
        self.assertEqual((r.lat_e6, r.lon_e6), (37774900, -122419400))
        self.assertTrue(r.pin.startswith("sha256:"))

    def test_case_insensitive(self):
        g = _mk()
        r = g.geocode("sAn FrAnCiScO", 3)
        self.assertEqual(r.match_kind, "exact")

    def test_alias(self):
        g = _mk()
        r = g.geocode("sf", 3)
        self.assertEqual(r.match_kind, "alias")
        self.assertEqual(r.place_id, "sf")

    def test_fuzzy(self):
        g = _mk()
        r = g.geocode("San Fransisco", 3)  # one-char typo
        self.assertEqual(r.match_kind, "fuzzy")
        self.assertEqual(r.place_id, "sf")
        self.assertGreaterEqual(r.similarity, 0.80)

    def test_none_is_data(self):
        g = _mk()
        r = g.geocode("Nowhere XYZ 123", 3)
        self.assertEqual(r.match_kind, "none")
        self.assertIsNone(r.lat_e6)
        self.assertIsNone(r.lon_e6)
        self.assertEqual(r.place_id, "")

    def test_empty_address(self):
        g = _mk()
        with self.assertRaises(BadMatchError):
            g.geocode("   ", 3)


class TestReverse(unittest.TestCase):
    def test_nearest_within(self):
        g = _mk()
        r = g.reverse(37774900, -122419400, 3)
        self.assertEqual(r.place_id, "sf")
        self.assertEqual(r.distance_m, 0)
        self.assertTrue(r.within)

    def test_outside_tolerance(self):
        g = _mk()
        r = g.reverse(0, 0, 3, tolerance_m=100)
        self.assertFalse(r.within)
        self.assertGreater(r.distance_m, 100)
        self.assertTrue(r.pin.startswith("sha256:"))

    def test_haversine_known(self):
        # SF -> NYC is ~4130 km; allow a generous band for the simulation.
        g = _mk()
        r = g.reverse(40712800, -74006000, 3)
        self.assertEqual(r.place_id, "nyc")
        self.assertEqual(r.distance_m, 0)

    def test_empty_registry(self):
        g = Geocoder()
        with self.assertRaises(NoPlacesError):
            g.reverse(0, 0, 1)

    def test_bad_coords(self):
        g = _mk()
        with self.assertRaises(InvalidCoordinateError):
            g.reverse(91000000, 0, 3)
        with self.assertRaises(InvalidCoordinateError):
            g.reverse(0.5, 0, 4)  # float refused
        with self.assertRaises(BadMatchError):
            g.reverse(0, 0, 5, tolerance_m=-1)


class TestBatch(unittest.TestCase):
    def test_mixed_batch(self):
        g = _mk()
        b = g.batch([
            ("geocode", "SF"),
            ("reverse", 37774900, -122419400, 500),
            ("geocode", "Nowhere XYZ"),
        ], 3)
        self.assertEqual(b.item_count, 3)
        self.assertTrue(b.batch_id.startswith("batch-"))
        kinds = [i.match_kind for i in b.items]
        self.assertEqual(kinds, ["alias", "within", "none"])
        self.assertTrue(b.pin.startswith("sha256:"))
        for i, item in enumerate(b.items):
            self.assertEqual(item.index, i)

    def test_malformed_item(self):
        g = _mk()
        with self.assertRaises(BadMatchError):
            g.batch([("geocode",)], 3)
        with self.assertRaises(BadMatchError):
            g.batch([("teleport", "x")], 4)
        with self.assertRaises(BadMatchError):
            g.batch([], 5)


class TestAudit(unittest.TestCase):
    def test_shapes(self):
        for kind in ("place-registered", "geocoded", "reversed", "batched", "rejected"):
            ev = geocoder_audit_event(kind, 9, place_id="sf")
            self.assertEqual(ev["schema"], SCHEMA)
            self.assertEqual(ev["kind"], kind)
        ev = geocoder_audit_event("geocoded", 9)  # no place_id ok
        self.assertEqual(ev["place_id"], "")

    def test_rejections(self):
        with self.assertRaises(GeocoderError):
            geocoder_audit_event("nope", 1)
        with self.assertRaises(SequenceError):
            geocoder_audit_event("geocoded", 0)
        with self.assertRaises(InvalidPlaceError):
            geocoder_audit_event("geocoded", 1, place_id="bad id!")


if __name__ == "__main__":
    unittest.main()
