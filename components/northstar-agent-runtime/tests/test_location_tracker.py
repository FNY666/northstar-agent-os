"""Tests for location_tracker.py."""

import ast
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path

from location_tracker import (
    VERSION,
    SCHEMA,
    LocationError,
    UnknownDeviceError,
    UnknownFixError,
    BadCoordinateError,
    BadEpochError,
    BadFieldError,
    SeqOrderError,
    TooFewFixesError,
    FixRecord,
    TrailReport,
    SpeedReport,
    LocationTracker,
    location_tracker_audit_event,
)


def make_tracker():
    tr = LocationTracker()
    tr.fix("dev-1", 22.5431, 114.0579, 1, at=1000)
    tr.fix("dev-1", 22.5431, 115.0579, 2, at=4600)
    tr.fix("dev-2", 31.2304, 121.4737, 3, at=2000)
    return tr


class TestPins(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(VERSION, "location-tracker.v1")
        self.assertEqual(SCHEMA, "northstar.location-tracker.v1")

    def test_fix_digest_shape(self):
        tr = LocationTracker()
        rec = tr.fix("d", 10.0, 20.0, 1, at=5)
        self.assertEqual(rec.id, "fx-1")
        self.assertTrue(rec.digest.startswith("sha256:"))
        self.assertEqual(rec.version, VERSION)


class TestFix(unittest.TestCase):
    def test_fix_roundtrip(self):
        tr = LocationTracker()
        rec = tr.fix("d", 22.5, 114.0, 1, at=100,
                     accuracy_m=5.0, altitude_m=12.5)
        self.assertEqual(rec.device_id, "d")
        self.assertEqual(rec.lat, 22.5)
        self.assertEqual(rec.lon, 114.0)
        self.assertEqual(rec.at, 100)
        self.assertEqual(rec.accuracy_m, 5.0)
        self.assertEqual(rec.altitude_m, 12.5)
        self.assertEqual(rec.seq, 1)

    def test_fix_monotonic_ids(self):
        tr = make_tracker()
        ids = [f.id for f in tr.fixes("dev-1")]
        self.assertEqual(ids, ["fx-1", "fx-2"])

    def test_bad_lat(self):
        tr = LocationTracker()
        for i, bad in enumerate((91.0, -90.1, "22", None, True)):
            with self.assertRaises(BadCoordinateError):
                tr.fix("d", bad, 114.0, i + 1, at=1)

    def test_bad_lon(self):
        tr = LocationTracker()
        for i, bad in enumerate((180.1, -181.0, "114", None, False)):
            with self.assertRaises(BadCoordinateError):
                tr.fix("d", 22.0, bad, i + 1, at=1)

    def test_nonfinite_coord(self):
        tr = LocationTracker()
        i = 0
        for bad in (float("nan"), float("inf"), float("-inf")):
            i += 1
            with self.assertRaises(BadCoordinateError):
                tr.fix("d", bad, 114.0, i, at=1)
            i += 1
            with self.assertRaises(BadCoordinateError):
                tr.fix("d", 22.0, bad, i, at=1)

    def test_bad_at(self):
        tr = LocationTracker()
        for i, bad in enumerate((-1, 1.5, True, "100", None)):
            with self.assertRaises(BadEpochError):
                tr.fix("d", 22.0, 114.0, i + 1, at=bad)

    def test_epoch_rewind_refused(self):
        tr = LocationTracker()
        tr.fix("d", 22.0, 114.0, 1, at=100)
        with self.assertRaises(BadEpochError):
            tr.fix("d", 22.1, 114.1, 2, at=100)  # equal: not strictly greater
        with self.assertRaises(BadEpochError):
            tr.fix("d", 22.1, 114.1, 3, at=50)

    def test_epoch_independent_per_device(self):
        tr = LocationTracker()
        tr.fix("a", 22.0, 114.0, 1, at=500)
        tr.fix("b", 22.0, 114.0, 2, at=100)  # lower epoch, different device: fine
        self.assertEqual(tr.fix_count(), 2)

    def test_bad_device_id(self):
        tr = LocationTracker()
        for i, bad in enumerate(("", "   ", None, 42)):
            with self.assertRaises(BadFieldError):
                tr.fix(bad, 22.0, 114.0, i + 1, at=1)

    def test_seq_order(self):
        tr = LocationTracker()
        tr.fix("d", 22.0, 114.0, 1, at=1)
        with self.assertRaises(SeqOrderError):
            tr.fix("d", 22.1, 114.1, 1, at=2)  # not greater
        with self.assertRaises(SeqOrderError):
            tr.fix("d", 22.1, 114.1, True, at=2)

    def test_integral_float_coord_allowed(self):
        # Deliberate deviation from the batch-line default: coordinates are
        # range-bounded, so 37.0 is unambiguous.
        tr = LocationTracker()
        rec = tr.fix("d", 37.0, -122.0, 1, at=1)
        self.assertEqual(rec.lat, 37.0)
        self.assertEqual(rec.lon, -122.0)


class TestTrail(unittest.TestCase):
    def test_trail_shape(self):
        tr = make_tracker()
        rep = tr.trail("dev-1", 4)
        self.assertIsInstance(rep, TrailReport)
        self.assertEqual(rep.device_id, "dev-1")
        self.assertEqual(rep.fix_ids, ("fx-1", "fx-2"))
        self.assertEqual(rep.count, 2)
        self.assertTrue(rep.digest.startswith("sha256:"))

    def test_trail_bbox(self):
        tr = make_tracker()
        rep = tr.trail("dev-1", 4)
        self.assertEqual(rep.min_lat, 22.5431)
        self.assertEqual(rep.max_lat, 22.5431)
        self.assertEqual(rep.min_lon, 114.0579)
        self.assertEqual(rep.max_lon, 115.0579)

    def test_trail_distance(self):
        tr = LocationTracker()
        tr.fix("d", 0.0, 0.0, 1, at=1)
        tr.fix("d", 0.0, 1.0, 2, at=2)
        rep = tr.trail("d", 3)
        # 1 degree of longitude at the equator ~= 111.19 km
        self.assertTrue(111000 < rep.distance_m < 111400, rep.distance_m)

    def test_trail_single_fix_zero_distance(self):
        tr = LocationTracker()
        tr.fix("d", 22.0, 114.0, 1, at=1)
        rep = tr.trail("d", 2)
        self.assertEqual(rep.count, 1)
        self.assertEqual(rep.distance_m, 0)
        self.assertEqual(rep.min_lat, rep.max_lat)

    def test_trail_limit(self):
        tr = LocationTracker()
        for i in range(4):
            tr.fix("d", 22.0 + i * 0.01, 114.0, i + 1, at=100 + i)
        rep = tr.trail("d", 5, limit=2)
        self.assertEqual(rep.count, 2)
        self.assertEqual(rep.fix_ids, ("fx-3", "fx-4"))

    def test_trail_unknown_device(self):
        tr = make_tracker()
        with self.assertRaises(UnknownDeviceError):
            tr.trail("nope", 9)


class TestSpeed(unittest.TestCase):
    def test_speed_happy(self):
        tr = LocationTracker()
        tr.fix("d", 0.0, 0.0, 1, at=0)
        tr.fix("d", 0.0, 1.0, 2, at=3600)
        rep = tr.speed("d", 3)
        self.assertIsInstance(rep, SpeedReport)
        self.assertEqual(rep.duration_s, 3600)
        self.assertTrue(111000 < rep.distance_m < 111400)
        self.assertAlmostEqual(rep.speed_mps, rep.distance_m / 3600, places=3)
        self.assertAlmostEqual(rep.speed_kmh, rep.speed_mps * 3.6, places=2)

    def test_speed_last_n(self):
        tr = LocationTracker()
        tr.fix("d", 0.0, 0.0, 1, at=0)
        tr.fix("d", 0.0, 0.5, 2, at=1800)
        tr.fix("d", 0.0, 1.0, 3, at=3600)
        rep = tr.speed("d", 4, last_n=2)
        self.assertEqual(rep.fix_ids, ("fx-2", "fx-3"))
        self.assertEqual(rep.duration_s, 1800)

    def test_speed_too_few(self):
        tr = LocationTracker()
        tr.fix("d", 0.0, 0.0, 1, at=1)
        with self.assertRaises(TooFewFixesError):
            tr.speed("d", 2)

    def test_speed_unknown_device(self):
        tr = LocationTracker()
        with self.assertRaises(UnknownDeviceError):
            tr.speed("ghost", 1)

    def test_speed_bad_last_n(self):
        tr = make_tracker()
        with self.assertRaises(BadFieldError):
            tr.speed("dev-1", 9, last_n=1)
        with self.assertRaises(BadFieldError):
            tr.speed("dev-1", 10, last_n=True)


class TestViews(unittest.TestCase):
    def test_fix_record_lookup(self):
        tr = make_tracker()
        rec = tr.fix_record("fx-1")
        self.assertEqual(rec.device_id, "dev-1")
        with self.assertRaises(UnknownFixError):
            tr.fix_record("fx-999")

    def test_fixes_unknown_device(self):
        tr = make_tracker()
        with self.assertRaises(UnknownDeviceError):
            tr.fixes("ghost")

    def test_device_ids_and_count(self):
        tr = make_tracker()
        self.assertEqual(tr.device_ids(), ("dev-1", "dev-2"))
        self.assertEqual(tr.fix_count(), 3)


class TestRecordsFrozen(unittest.TestCase):
    def test_records_immutable(self):
        tr = make_tracker()
        rec = tr.fix_record("fx-1")
        with self.assertRaises(FrozenInstanceError):
            rec.lat = 0.0
        rep = tr.trail("dev-1", 9)
        with self.assertRaises(FrozenInstanceError):
            rep.distance_m = 0

    def test_digest_determinism(self):
        a = LocationTracker()
        b = LocationTracker()
        ra = a.fix("d", 22.5, 114.0, 1, at=100)
        rb = b.fix("d", 22.5, 114.0, 1, at=100)
        self.assertEqual(ra.digest, rb.digest)


class TestAudit(unittest.TestCase):
    def test_audit_shapes(self):
        ev = location_tracker_audit_event("fix-recorded", "fx-1", "sha256:abc", 1)
        self.assertEqual(ev["schema"], "audit.ndjson/1")
        self.assertEqual(ev["module"], SCHEMA)
        self.assertEqual(ev["kind"], "fix-recorded")
        self.assertEqual(ev["ref_id"], "fx-1")

    def test_audit_bad_kind(self):
        with self.assertRaises(LocationError):
            location_tracker_audit_event("nope", "fx-1", "sha256:abc", 1)

    def test_audit_bad_seq(self):
        with self.assertRaises(SeqOrderError):
            location_tracker_audit_event("fix-recorded", "fx-1", "sha256:abc", -1)

    def test_audit_carries_no_coords(self):
        ev = location_tracker_audit_event("fix-recorded", "fx-1", "sha256:abc", 1)
        self.assertNotIn("lat", ev)
        self.assertNotIn("lon", ev)


class TestStdlibOnly(unittest.TestCase):
    def test_stdlib_only(self):
        src = (Path(__file__).resolve().parent.parent / "location_tracker.py").read_text()
        tree = ast.parse(src)
        allowed = {
            "hashlib", "json", "math", "threading", "dataclasses", "typing",
            "__future__",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertIn(alias.name.split(".")[0], allowed, alias.name)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed, node.module)


class TestMain(unittest.TestCase):
    def test_main(self):
        import location_tracker as lt
        lt.main()


if __name__ == "__main__":
    unittest.main()
