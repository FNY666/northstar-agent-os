"""Tests for timezone_resolver: lat/lon to IANA zone lookup."""

import ast
import dataclasses
import unittest

from timezone_resolver import (
    SCHEMA,
    VERSION,
    DSTRecord,
    DSTStatus,
    InvalidCoordinateError,
    InvalidDateError,
    OffsetRecord,
    SeqOrderError,
    TimezoneError,
    TimezoneResolver,
    UnknownZoneError,
    ZoneRecord,
    timezone_resolver_audit_event,
)


class VersionPinTests(unittest.TestCase):
    def test_version_pins(self):
        self.assertEqual(VERSION, "timezone-resolver.v1")
        self.assertEqual(SCHEMA, "northstar.timezone-resolver.v1")

    def test_stdlib_only(self):
        import pathlib
        tree = ast.parse(pathlib.Path(
            __file__).parent.parent.joinpath(
            "timezone_resolver.py").read_text())
        allowed = {"hashlib", "json", "math", "threading", "dataclasses",
                   "datetime", "typing", "__future__", "annotations"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], allowed, a.name)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed,
                              node.module)


class ResolveTests(unittest.TestCase):
    def test_resolve_exact_new_york(self):
        r = TimezoneResolver()
        z = r.resolve(40.7128, -74.0060, seq=1)
        self.assertIsInstance(z, ZoneRecord)
        self.assertEqual(z.zone_id, "zr-1")
        self.assertEqual(z.tz_name, "America/New_York")
        self.assertEqual(z.match_tier, "exact")
        self.assertAlmostEqual(z.distance_km, 0.0, places=6)
        self.assertEqual(z.std_offset_minutes, -300)
        self.assertEqual(z.dst_offset_minutes, -240)
        self.assertTrue(z.observes_dst)
        self.assertTrue(z.digest.startswith("sha256:"))
        self.assertEqual(z.version, VERSION)
        self.assertEqual(z.schema, SCHEMA)

    def test_resolve_near_tier(self):
        r = TimezoneResolver()
        # ~50 km from the NYC anchor: still NYC, "near" tier.
        z = r.resolve(40.3, -73.8, seq=1)
        self.assertEqual(z.tz_name, "America/New_York")
        self.assertEqual(z.match_tier, "near")
        self.assertLess(z.distance_km, 150.0)

    def test_resolve_regional_tier_mid_atlantic(self):
        r = TimezoneResolver()
        z = r.resolve(30.0, -40.0, seq=1)
        self.assertEqual(z.match_tier, "regional")
        self.assertEqual(z.tz_name, "America/New_York")
        self.assertGreater(z.distance_km, 150.0)

    def test_resolve_determinism_across_instances(self):
        a = TimezoneResolver().resolve(35.6762, 139.6503, seq=1)
        b = TimezoneResolver().resolve(35.6762, 139.6503, seq=1)
        self.assertEqual(a.tz_name, "Asia/Tokyo")
        self.assertEqual(a.digest, b.digest)

    def test_resolve_int_coordinates_accepted(self):
        r = TimezoneResolver()
        z = r.resolve(52, 13, seq=1)  # near Berlin
        self.assertEqual(z.tz_name, "Europe/Berlin")
        self.assertEqual(z.match_tier, "near")

    def test_resolve_latitude_out_of_range(self):
        r = TimezoneResolver()
        with self.assertRaises(InvalidCoordinateError):
            r.resolve(91.0, 0.0, seq=1)
        with self.assertRaises(InvalidCoordinateError):
            r.resolve(-90.5, 0.0, seq=2)

    def test_resolve_longitude_out_of_range(self):
        r = TimezoneResolver()
        with self.assertRaises(InvalidCoordinateError):
            r.resolve(0.0, 181.0, seq=1)

    def test_resolve_nan_inf_refused(self):
        r = TimezoneResolver()
        with self.assertRaises(InvalidCoordinateError):
            r.resolve(float("nan"), 0.0, seq=1)
        with self.assertRaises(InvalidCoordinateError):
            r.resolve(0.0, float("inf"), seq=2)

    def test_resolve_bool_and_str_refused(self):
        r = TimezoneResolver()
        with self.assertRaises(InvalidCoordinateError):
            r.resolve(True, 0.0, seq=1)
        with self.assertRaises(InvalidCoordinateError):
            r.resolve("40.7", -74.0, seq=2)

    def test_zone_ids_monotonic(self):
        r = TimezoneResolver()
        a = r.resolve(40.7128, -74.0060, seq=1)
        b = r.resolve(48.8566, 2.3522, seq=2)
        self.assertEqual((a.zone_id, b.zone_id), ("zr-1", "zr-2"))
        self.assertEqual(b.tz_name, "Europe/Paris")


class OffsetTests(unittest.TestCase):
    def test_offset_kolkata_half_hour(self):
        r = TimezoneResolver()
        o = r.offset("Asia/Kolkata", seq=1)
        self.assertIsInstance(o, OffsetRecord)
        self.assertEqual(o.offset_id, "or-1")
        self.assertEqual(o.std_offset_minutes, 330)
        self.assertEqual(o.dst_offset_minutes, 330)
        self.assertFalse(o.observes_dst)
        self.assertTrue(o.digest.startswith("sha256:"))

    def test_offset_auckland_dst_pair(self):
        r = TimezoneResolver()
        o = r.offset("Pacific/Auckland", seq=1)
        self.assertEqual((o.std_offset_minutes, o.dst_offset_minutes),
                         (720, 780))
        self.assertTrue(o.observes_dst)

    def test_offset_unknown_zone(self):
        r = TimezoneResolver()
        with self.assertRaises(UnknownZoneError):
            r.offset("Mars/Olympus_Mons", seq=1)
        with self.assertRaises(UnknownZoneError):
            r.offset("", seq=2)
        with self.assertRaises(UnknownZoneError):
            r.offset(None, seq=3)

    def test_offset_determinism(self):
        a = TimezoneResolver().offset("UTC", seq=1)
        b = TimezoneResolver().offset("UTC", seq=1)
        self.assertEqual(a.digest, b.digest)


class DSTDescribeTests(unittest.TestCase):
    def test_dst_paris_eu_rule(self):
        r = TimezoneResolver()
        d = r.dst("Europe/Paris", seq=1)
        self.assertIsInstance(d, DSTRecord)
        self.assertEqual(d.dst_id, "dr-1")
        self.assertTrue(d.observes_dst)
        self.assertEqual(d.hemisphere, "northern")
        self.assertEqual(d.dst_start, {"month": 3, "week": -1, "weekday": 6})
        self.assertEqual(d.dst_end, {"month": 10, "week": -1, "weekday": 6})
        self.assertEqual(d.dst_offset_minutes, 120)

    def test_dst_cairo_egypt_rule(self):
        r = TimezoneResolver()
        d = r.dst("Africa/Cairo", seq=1)
        self.assertTrue(d.observes_dst)
        self.assertEqual(d.dst_start, {"month": 4, "week": -1, "weekday": 4})
        self.assertEqual(d.dst_end, {"month": 10, "week": -1, "weekday": 3})

    def test_dst_sydney_southern_rule(self):
        r = TimezoneResolver()
        d = r.dst("Australia/Sydney", seq=1)
        self.assertEqual(d.hemisphere, "southern")
        self.assertEqual(d.dst_start, {"month": 10, "week": 1, "weekday": 6})
        self.assertEqual(d.dst_end, {"month": 4, "week": 1, "weekday": 6})

    def test_dst_non_observing_has_no_rule(self):
        r = TimezoneResolver()
        d = r.dst("Asia/Tokyo", seq=1)
        self.assertFalse(d.observes_dst)
        self.assertIsNone(d.hemisphere)
        self.assertIsNone(d.dst_start)
        self.assertIsNone(d.dst_end)
        self.assertIsNone(d.dst_offset_minutes)

    def test_dst_unknown_zone(self):
        r = TimezoneResolver()
        with self.assertRaises(UnknownZoneError):
            r.dst("Nope/Nowhere", seq=1)


class DSTActiveTests(unittest.TestCase):
    def test_new_york_summer_active(self):
        r = TimezoneResolver()
        s = r.dst_active("America/New_York", 2026, 7, 4, seq=1)
        self.assertIsInstance(s, DSTStatus)
        self.assertEqual(s.status_id, "ds-1")
        self.assertTrue(s.dst_active)
        self.assertEqual(s.effective_offset_minutes, -240)

    def test_new_york_winter_inactive(self):
        r = TimezoneResolver()
        s = r.dst_active("America/New_York", 2026, 1, 15, seq=1)
        self.assertFalse(s.dst_active)
        self.assertEqual(s.effective_offset_minutes, -300)

    def test_us_transition_boundaries_2026(self):
        r = TimezoneResolver()
        # 2026: 2nd Sunday of March is Mar 8; 1st Sunday of November is Nov 1.
        before = r.dst_active("America/New_York", 2026, 3, 7, seq=1)
        start_day = r.dst_active("America/New_York", 2026, 3, 8, seq=2)
        last_dst_day = r.dst_active("America/New_York", 2026, 10, 31, seq=3)
        end_day = r.dst_active("America/New_York", 2026, 11, 1, seq=4)
        self.assertFalse(before.dst_active)
        self.assertTrue(start_day.dst_active)
        self.assertTrue(last_dst_day.dst_active)
        self.assertFalse(end_day.dst_active)

    def test_sydney_southern_summer_active(self):
        r = TimezoneResolver()
        jan = r.dst_active("Australia/Sydney", 2026, 1, 15, seq=1)
        jul = r.dst_active("Australia/Sydney", 2026, 7, 4, seq=2)
        self.assertTrue(jan.dst_active)
        self.assertEqual(jan.effective_offset_minutes, 660)
        self.assertFalse(jul.dst_active)
        self.assertEqual(jul.effective_offset_minutes, 600)

    def test_non_observing_always_standard(self):
        r = TimezoneResolver()
        s = r.dst_active("Asia/Tokyo", 2026, 7, 4, seq=1)
        self.assertFalse(s.dst_active)
        self.assertEqual(s.effective_offset_minutes, 540)

    def test_cairo_summer_active_winter_inactive(self):
        r = TimezoneResolver()
        summer = r.dst_active("Africa/Cairo", 2026, 6, 15, seq=1)
        winter = r.dst_active("Africa/Cairo", 2026, 12, 15, seq=2)
        self.assertTrue(summer.dst_active)
        self.assertEqual(summer.effective_offset_minutes, 180)
        self.assertFalse(winter.dst_active)
        self.assertEqual(winter.effective_offset_minutes, 120)

    def test_impossible_date_refused(self):
        r = TimezoneResolver()
        with self.assertRaises(InvalidDateError):
            r.dst_active("UTC", 2026, 2, 30, seq=1)
        with self.assertRaises(InvalidDateError):
            r.dst_active("UTC", 2026, 13, 1, seq=2)
        with self.assertRaises(InvalidDateError):
            r.dst_active("UTC", True, 1, 1, seq=3)
        with self.assertRaises(InvalidDateError):
            r.dst_active("UTC", 2026.5, 1, 1, seq=4)

    def test_dst_active_unknown_zone(self):
        r = TimezoneResolver()
        with self.assertRaises(UnknownZoneError):
            r.dst_active("Nope/Nowhere", 2026, 1, 1, seq=1)


class SeqTests(unittest.TestCase):
    def test_seq_must_increase(self):
        r = TimezoneResolver()
        r.resolve(0.0, 0.0, seq=1)
        with self.assertRaises(SeqOrderError):
            r.offset("UTC", seq=1)
        with self.assertRaises(SeqOrderError):
            r.dst("UTC", seq=0)

    def test_seq_bool_and_negative_refused(self):
        r = TimezoneResolver()
        with self.assertRaises(SeqOrderError):
            r.resolve(0.0, 0.0, seq=True)
        with self.assertRaises(SeqOrderError):
            r.resolve(0.0, 0.0, seq=-1)

    def test_seq_shared_across_methods(self):
        r = TimezoneResolver()
        r.resolve(0.0, 0.0, seq=5)
        o = r.offset("UTC", seq=6)  # continues the same counter
        self.assertEqual(o.offset_id, "or-1")


class RecordShapeTests(unittest.TestCase):
    def test_records_frozen(self):
        r = TimezoneResolver()
        z = r.resolve(0.0, 0.0, seq=1)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            z.zone_id = "zr-9"  # type: ignore[misc]

    def test_as_dict_roundtrip(self):
        r = TimezoneResolver()
        z = r.resolve(40.7128, -74.0060, seq=1)
        d = z.as_dict()
        self.assertEqual(d["tz_name"], "America/New_York")
        self.assertEqual(d["match_tier"], "exact")

    def test_error_taxonomy(self):
        self.assertTrue(issubclass(UnknownZoneError, TimezoneError))
        self.assertTrue(issubclass(InvalidCoordinateError, TimezoneError))
        self.assertTrue(issubclass(InvalidDateError, TimezoneError))
        self.assertTrue(issubclass(SeqOrderError, TimezoneError))
        self.assertTrue(issubclass(TimezoneError, ValueError))


class AuditTests(unittest.TestCase):
    def test_audit_shapes(self):
        for kind in ("resolved", "offset-looked-up", "dst-described",
                     "dst-evaluated", "rejected"):
            ev = timezone_resolver_audit_event(kind, 1, zone="UTC")
            self.assertEqual(ev["schema"], "audit.ndjson/1")
            self.assertEqual(ev["module"], "timezone_resolver")
            self.assertEqual(ev["moduleVersion"], VERSION)
            self.assertEqual(ev["kind"], kind)
            self.assertEqual(ev["seq"], 1)
            self.assertEqual(ev["detail"]["zone"], "UTC")

    def test_audit_unknown_kind_rejected(self):
        with self.assertRaises(TimezoneError):
            timezone_resolver_audit_event("nope", 1)


class MainTests(unittest.TestCase):
    def test_main_self_check(self):
        import timezone_resolver as m
        self.assertIsNone(m.main())


if __name__ == "__main__":
    unittest.main()
