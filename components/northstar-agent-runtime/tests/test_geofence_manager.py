"""Tests for geofence_manager: polygon zones, containment, entry/exit events."""

import ast
import unittest

import geofence_manager as gm
from geofence_manager import GeofenceManager

SQUARE = [(-1.0, -1.0), (-1.0, 1.0), (1.0, 1.0), (1.0, -1.0)]
TRIANGLE = [(0.0, 0.0), (0.0, 4.0), (4.0, 0.0)]


def make_zone(seq_start=0):
    m = GeofenceManager()
    z = m.add_zone("hq", SQUARE, seq_start, name="HQ")
    return m, z


class TestVersionPins(unittest.TestCase):
    def test_pins(self):
        self.assertEqual(gm.GEOFENCE_MANAGER_VERSION, "geofence-manager.v1")
        self.assertEqual(gm.SCHEMA_PIN, "northstar.geofence-manager.v1")


class TestAddZone(unittest.TestCase):
    def test_happy_path(self):
        m, z = make_zone()
        self.assertEqual(z.zone_id, "hq")
        self.assertEqual(z.name, "HQ")
        self.assertTrue(z.pin.startswith("sha256:"))
        self.assertEqual(len(z.vertices), 4)

    def test_default_name(self):
        m = GeofenceManager()
        z = m.add_zone("z2", TRIANGLE, 0)
        self.assertEqual(z.name, "z2")

    def test_pin_determinism(self):
        m1, z1 = make_zone()
        m2, z2 = make_zone()
        self.assertEqual(z1.pin, z2.pin)

    def test_duplicate_zone(self):
        m, _ = make_zone()
        with self.assertRaises(gm.DuplicateZoneError):
            m.add_zone("hq", TRIANGLE, 1)

    def test_too_few_vertices(self):
        m = GeofenceManager()
        with self.assertRaises(gm.InvalidPolygonError):
            m.add_zone("z", [(0.0, 0.0), (1.0, 1.0)], 0)

    def test_not_a_polygon(self):
        m = GeofenceManager()
        with self.assertRaises(gm.InvalidPolygonError):
            m.add_zone("z", "nope", 0)

    def test_bad_vertex_shape(self):
        m = GeofenceManager()
        with self.assertRaises(gm.InvalidPolygonError):
            m.add_zone("z", [(0.0, 0.0), (1.0,), (2.0, 2.0), (0.0, 2.0)], 0)

    def test_consecutive_duplicate_vertex(self):
        m = GeofenceManager()
        with self.assertRaises(gm.InvalidPolygonError):
            m.add_zone("z", [(0.0, 0.0), (0.0, 0.0), (1.0, 0.0), (1.0, 1.0)], 0)

    def test_closed_ring_refused(self):
        m = GeofenceManager()
        ring = SQUARE + [SQUARE[0]]
        with self.assertRaises(gm.InvalidPolygonError):
            m.add_zone("z", ring, 0)

    def test_lat_out_of_range(self):
        m = GeofenceManager()
        with self.assertRaises(gm.InvalidCoordinateError):
            m.add_zone("z", [(91.0, 0.0), (0.0, 1.0), (1.0, 0.0)], 0)

    def test_lon_out_of_range(self):
        m = GeofenceManager()
        with self.assertRaises(gm.InvalidCoordinateError):
            m.add_zone("z", [(0.0, 181.0), (0.0, 1.0), (1.0, 0.0)], 0)

    def test_nan_refused(self):
        m = GeofenceManager()
        with self.assertRaises(gm.InvalidCoordinateError):
            m.add_zone("z", [(float("nan"), 0.0), (0.0, 1.0), (1.0, 0.0)], 0)

    def test_bool_refused(self):
        m = GeofenceManager()
        with self.assertRaises(gm.InvalidCoordinateError):
            m.add_zone("z", [(True, 0.0), (0.0, 1.0), (1.0, 0.0)], 0)

    def test_empty_zone_id(self):
        m = GeofenceManager()
        with self.assertRaises(gm.ValidationError):
            m.add_zone("  ", TRIANGLE, 0)

    def test_bad_name(self):
        m = GeofenceManager()
        with self.assertRaises(gm.ValidationError):
            m.add_zone("z", TRIANGLE, 0, name="   ")


class TestCheck(unittest.TestCase):
    def test_inside(self):
        m, _ = make_zone()
        r = m.check("hq", "s1", 0.0, 0.0, 1)
        self.assertTrue(r.inside)
        self.assertEqual(r.transition, "none")

    def test_outside(self):
        m, _ = make_zone()
        r = m.check("hq", "s1", 5.0, 5.0, 1)
        self.assertFalse(r.inside)

    def test_boundary_counts_as_inside(self):
        m, _ = make_zone()
        r = m.check("hq", "s1", 0.0, 1.0, 1)  # on the east edge
        self.assertTrue(r.inside)
        r2 = m.check("hq", "s2", -1.0, -1.0, 2)  # corner vertex
        self.assertTrue(r2.inside)

    def test_triangle(self):
        m = GeofenceManager()
        m.add_zone("tri", TRIANGLE, 0)
        self.assertTrue(m.check("tri", "s", 1.0, 1.0, 1).inside)
        self.assertFalse(m.check("tri", "s", 3.0, 3.0, 2).inside)

    def test_unknown_zone(self):
        m = GeofenceManager()
        with self.assertRaises(gm.UnknownZoneError):
            m.check("nope", "s", 0.0, 0.0, 0)

    def test_bad_lat(self):
        m, _ = make_zone()
        with self.assertRaises(gm.InvalidCoordinateError):
            m.check("hq", "s", float("inf"), 0.0, 1)

    def test_bad_seq_bool(self):
        m, _ = make_zone()
        with self.assertRaises(gm.ValidationError):
            m.check("hq", "s", 0.0, 0.0, True)

    def test_report_pin(self):
        m, _ = make_zone()
        r = m.check("hq", "s", 0.0, 0.0, 1)
        self.assertTrue(r.pin.startswith("sha256:"))
        self.assertEqual(r.seq, 1)


class TestTransitions(unittest.TestCase):
    def test_enter(self):
        m, _ = make_zone()
        m.check("hq", "s", 5.0, 5.0, 1)
        r = m.check("hq", "s", 0.0, 0.0, 2)
        self.assertEqual(r.transition, "entered")
        evs = m.events()
        self.assertEqual(len(evs), 1)
        self.assertEqual(evs[0].kind, "entered")
        self.assertEqual(evs[0].event_id, "ev-1")
        self.assertEqual(evs[0].subject_id, "s")

    def test_exit(self):
        m, _ = make_zone()
        m.check("hq", "s", 0.0, 0.0, 1)
        r = m.check("hq", "s", 5.0, 5.0, 2)
        self.assertEqual(r.transition, "exited")
        self.assertEqual(m.events()[0].kind, "exited")

    def test_no_event_on_first_sighting(self):
        m, _ = make_zone()
        m.check("hq", "s", 0.0, 0.0, 1)
        self.assertEqual(m.events(), ())

    def test_no_event_without_change(self):
        m, _ = make_zone()
        m.check("hq", "s", 0.0, 0.0, 1)
        r = m.check("hq", "s", 0.5, 0.5, 2)
        self.assertEqual(r.transition, "none")
        self.assertEqual(m.events(), ())

    def test_subjects_tracked_independently(self):
        m, _ = make_zone()
        m.check("hq", "a", 5.0, 5.0, 1)
        m.check("hq", "b", 0.0, 0.0, 2)
        r = m.check("hq", "a", 0.0, 0.0, 3)
        self.assertEqual(r.transition, "entered")
        # b's first sighting emitted nothing
        self.assertEqual([e.subject_id for e in m.events()], ["a"])

    def test_event_pin_binds_zone(self):
        m, _ = make_zone()
        m.check("hq", "s", 5.0, 5.0, 1)
        m.check("hq", "s", 0.0, 0.0, 2)
        self.assertTrue(m.events()[0].pin.startswith("sha256:"))

    def test_events_filter(self):
        m = GeofenceManager()
        m.add_zone("a", SQUARE, 0)
        m.add_zone("b", TRIANGLE, 1)
        m.check("a", "s", 5.0, 5.0, 2)
        m.check("a", "s", 0.0, 0.0, 3)
        m.check("b", "s", 5.0, 5.0, 4)
        m.check("b", "s", 1.0, 1.0, 5)
        self.assertEqual(len(m.events()), 2)
        self.assertEqual(len(m.events(zone_id="a")), 1)
        self.assertEqual(len(m.events(subject_id="s")), 2)


class TestRemoveZone(unittest.TestCase):
    def test_remove(self):
        m, z = make_zone()
        r = m.remove_zone("hq", 1)
        self.assertEqual(r.zone_id, "hq")
        with self.assertRaises(gm.UnknownZoneError):
            m.check("hq", "s", 0.0, 0.0, 2)

    def test_remove_unknown(self):
        m = GeofenceManager()
        with self.assertRaises(gm.UnknownZoneError):
            m.remove_zone("nope", 0)

    def test_zones_view(self):
        m = GeofenceManager()
        m.add_zone("b", TRIANGLE, 0)
        m.add_zone("a", SQUARE, 1)
        self.assertEqual([z.zone_id for z in m.zones()], ["a", "b"])
        self.assertEqual(m.zone("b").zone_id, "b")
        with self.assertRaises(gm.UnknownZoneError):
            m.zone("nope")


class TestSeqDiscipline(unittest.TestCase):
    def test_rewind_refused(self):
        m, _ = make_zone()
        with self.assertRaises(gm.SeqOrderError):
            m.check("hq", "s", 0.0, 0.0, 0)

    def test_failed_mutation_consumes_seq(self):
        m, _ = make_zone()
        with self.assertRaises(gm.DuplicateZoneError):
            m.add_zone("hq", TRIANGLE, 1)
        # seq 1 was consumed; next valid seq is 2
        with self.assertRaises(gm.SeqOrderError):
            m.check("hq", "s", 0.0, 0.0, 1)


class TestAuditAndMisc(unittest.TestCase):
    def test_audit_shapes(self):
        for kind in ("zone-added", "zone-removed", "checked", "entered", "exited", "rejected"):
            rec = gm.geofence_manager_audit_event(kind, 7, {"zone_id": "hq"})
            self.assertEqual(rec["schema"], gm.SCHEMA_PIN)
            self.assertEqual(rec["version"], gm.GEOFENCE_MANAGER_VERSION)

    def test_audit_bad_kind(self):
        with self.assertRaises(gm.ValidationError):
            gm.geofence_manager_audit_event("bogus", 0, {})

    def test_frozen_records(self):
        m, z = make_zone()
        r = m.check("hq", "s", 0.0, 0.0, 1)
        for rec in (z, r):
            with self.assertRaises(Exception):
                rec.seq = 999  # type: ignore[misc]

    def test_stdlib_only(self):
        tree = ast.parse(open(gm.__file__).read())
        allowed = {"__future__", "hashlib", "math", "threading", "dataclasses",
                   "typing", "json", "canonical_json"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed)

    def test_main(self):
        gm.main()

    def test_concave_polygon(self):
        # L-shape: covers (0,0)-(2,2) minus (1,1)-(2,2)
        m = GeofenceManager()
        lshape = [(0.0, 0.0), (0.0, 2.0), (1.0, 2.0), (1.0, 1.0),
                  (2.0, 1.0), (2.0, 0.0)]
        m.add_zone("ell", lshape, 0)
        self.assertTrue(m.check("ell", "s", 0.5, 0.5, 1).inside)
        self.assertFalse(m.check("ell", "s", 1.5, 1.5, 2).inside)


if __name__ == "__main__":
    unittest.main()
