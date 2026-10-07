"""Tests for poi_search.py (15 tests)."""

import math
import threading
import unittest

from poi_search import (
    POISearch,
    DuplicatePlaceError,
    UnknownPlaceError,
    UnknownCategoryError,
    InvalidCoordinateError,
    InvalidRadiusError,
    InvalidPOIError,
    SeqOrderError,
    POI_SEARCH_VERSION,
    POI_SEARCH_SCHEMA,
    AUDIT_SCHEMA,
    poi_search_audit_event,
)


class TestVersionPins(unittest.TestCase):
    def test_version_pins(self):
        self.assertEqual(POI_SEARCH_VERSION, "poi-search.v1")
        self.assertEqual(POI_SEARCH_SCHEMA, "northstar.poi-search.v1")


class TestIndex(unittest.TestCase):
    def test_index_roundtrip(self):
        ps = POISearch()
        rec = ps.index("p1", "Noodle House", "restaurant", 22.3, 114.17, 1,
                       address="1 Main St", rating=4.5, price_level=2)
        self.assertEqual(rec.place_id, "p1")
        self.assertTrue(rec.digest.startswith("sha256:"))
        self.assertEqual(rec.version, POI_SEARCH_VERSION)
        self.assertEqual(rec.schema, POI_SEARCH_SCHEMA)
        self.assertEqual(ps.place_ids(), ("p1",))

    def test_index_digest_deterministic(self):
        a, b = POISearch(), POISearch()
        r1 = a.index("p1", "N", "cafe", 1.0, 2.0, 1)
        r2 = b.index("p1", "N", "cafe", 1.0, 2.0, 1)
        self.assertEqual(r1.digest, r2.digest)

    def test_index_duplicate_place_id(self):
        ps = POISearch()
        ps.index("p1", "N", "cafe", 1.0, 2.0, 1)
        with self.assertRaises(DuplicatePlaceError):
            ps.index("p1", "N", "cafe", 1.0, 2.0, 2)

    def test_index_unknown_category(self):
        ps = POISearch()
        with self.assertRaises(UnknownCategoryError):
            ps.index("p1", "N", "spaceship_port", 1.0, 2.0, 1)

    def test_index_bad_coordinates(self):
        ps = POISearch()
        with self.assertRaises(InvalidCoordinateError):
            ps.index("p1", "N", "cafe", 91.0, 2.0, 1)
        with self.assertRaises(InvalidCoordinateError):
            ps.index("p2", "N", "cafe", 1.0, float("nan"), 2)
        with self.assertRaises(InvalidCoordinateError):
            ps.index("p3", "N", "cafe", True, 2.0, 3)

    def test_index_bad_rating_and_price(self):
        ps = POISearch()
        with self.assertRaises(InvalidPOIError):
            ps.index("p1", "N", "cafe", 1.0, 2.0, 1, rating=5.5)
        with self.assertRaises(InvalidPOIError):
            ps.index("p2", "N", "cafe", 1.0, 2.0, 2, price_level=7)
        with self.assertRaises(InvalidPOIError):
            ps.index("p3", "N", "cafe", 1.0, 2.0, 3, price_level=True)

    def test_index_seq_order(self):
        ps = POISearch()
        ps.index("p1", "N", "cafe", 1.0, 2.0, 5)
        with self.assertRaises(SeqOrderError):
            ps.index("p2", "N", "cafe", 1.0, 2.0, 5)


class TestNearby(unittest.TestCase):
    def _seeded(self):
        ps = POISearch()
        ps.index("near", "Near Cafe", "cafe", 22.3000, 114.1700, 1, rating=4.0)
        ps.index("far", "Far Hotel", "hotel", 22.3100, 114.1800, 2, rating=4.8)
        return ps

    def test_nearby_order_and_radius(self):
        ps = self._seeded()
        res = ps.nearby(22.30, 114.17, 500.0, 3)
        self.assertEqual([h.place.place_id for h in res.hits], ["near"])
        self.assertLess(res.hits[0].distance_m, 1.0)  # same spot
        res2 = ps.nearby(22.30, 114.17, 5000.0, 4)
        ids = [h.place.place_id for h in res2.hits]
        self.assertEqual(ids, ["near", "far"])  # ascending distance

    def test_nearby_category_and_rating_filter(self):
        ps = self._seeded()
        res = ps.nearby(22.30, 114.17, 5000.0, 3, category="hotel")
        self.assertEqual([h.place.place_id for h in res.hits], ["far"])
        res2 = ps.nearby(22.30, 114.17, 5000.0, 4, min_rating=4.5)
        self.assertEqual([h.place.place_id for h in res2.hits], ["far"])

    def test_nearby_unknown_category_and_bad_radius(self):
        ps = self._seeded()
        with self.assertRaises(UnknownCategoryError):
            ps.nearby(22.30, 114.17, 5000.0, 3, category="nope")
        with self.assertRaises(InvalidRadiusError):
            ps.nearby(22.30, 114.17, 0.0, 4)
        with self.assertRaises(InvalidRadiusError):
            ps.nearby(22.30, 114.17, float("inf"), 5)

    def test_nearby_empty_result_is_data(self):
        ps = self._seeded()
        res = ps.nearby(0.0, 0.0, 10.0, 3)
        self.assertEqual(res.hits, ())


class TestDetailsAndRemove(unittest.TestCase):
    def test_details_and_unknown(self):
        ps = POISearch()
        ps.index("p1", "N", "cafe", 1.0, 2.0, 1)
        det = ps.details("p1", 2)
        self.assertEqual(det.place.place_id, "p1")
        self.assertTrue(det.digest.startswith("sha256:"))
        with self.assertRaises(UnknownPlaceError):
            ps.details("ghost", 3)

    def test_remove(self):
        ps = POISearch()
        ps.index("p1", "N", "cafe", 1.0, 2.0, 1)
        ps.remove("p1", 2)
        self.assertEqual(ps.place_count(), 0)
        with self.assertRaises(UnknownPlaceError):
            ps.remove("p1", 3)


class TestAuditAndMisc(unittest.TestCase):
    def test_audit_shapes(self):
        ev = poi_search_audit_event("indexed", 1, {"place_id": "p1"})
        self.assertEqual(ev["schema"], AUDIT_SCHEMA)
        self.assertEqual(ev["kind"], "indexed")
        with self.assertRaises(Exception):
            poi_search_audit_event("hacked", 2)

    def test_thread_safety(self):
        ps = POISearch()
        errs = []
        seq_lock = threading.Lock()
        seq_counter = [0]

        def worker(i):
            try:
                with seq_lock:
                    seq_counter[0] += 1
                    s = seq_counter[0]
                ps.index("p%d" % i, "N", "cafe", 1.0, 2.0, s)
            except Exception as e:  # noqa: BLE001
                errs.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(1, 9)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errs, [])
        self.assertEqual(ps.place_count(), 8)


if __name__ == "__main__":
    unittest.main()
