"""Tests for t_digest.py."""

import math
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from t_digest import (  # noqa: E402
    TDIGEST_VERSION,
    SCHEMA_PIN,
    DEFAULT_COMPRESSION,
    TDigest,
    TDigestError,
    Centroid,
    DigestSummary,
    t_digest_audit_event,
)


def make_range(n: int, compression: float = 100.0) -> TDigest:
    d = TDigest(compression=compression)
    for v in range(1, n + 1):
        d.add(float(v))
    return d


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(TDIGEST_VERSION, "t-digest.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.t-digest.v1")

    def test_default_compression(self):
        self.assertEqual(DEFAULT_COMPRESSION, 100.0)


class TestAdd(unittest.TestCase):
    def test_count(self):
        d = TDigest()
        for v in range(10):
            d.add(v)
        self.assertEqual(d.count(), 10)

    def test_add_int_accepted(self):
        d = TDigest()
        d.add(5)
        self.assertEqual(d.count(), 1)

    def test_add_bool_rejected(self):
        d = TDigest()
        with self.assertRaises(TypeError):
            d.add(True)

    def test_add_nan_rejected(self):
        d = TDigest()
        with self.assertRaises(ValueError):
            d.add(math.nan)

    def test_add_inf_rejected(self):
        d = TDigest()
        with self.assertRaises(ValueError):
            d.add(math.inf)

    def test_add_str_rejected(self):
        d = TDigest()
        with self.assertRaises(TypeError):
            d.add("5")

    def test_bad_compression(self):
        with self.assertRaises(ValueError):
            TDigest(compression=0)
        with self.assertRaises(ValueError):
            TDigest(compression=-3)
        with self.assertRaises(TypeError):
            TDigest(compression=True)

    def test_bad_buffer_size(self):
        with self.assertRaises(ValueError):
            TDigest(buffer_size=0)
        with self.assertRaises(TypeError):
            TDigest(buffer_size="x")


class TestQuantile(unittest.TestCase):
    def test_empty_raises(self):
        with self.assertRaises(TDigestError):
            TDigest().quantile(0.5)

    def test_q_out_of_range(self):
        d = make_range(10)
        with self.assertRaises(ValueError):
            d.quantile(-0.1)
        with self.assertRaises(ValueError):
            d.quantile(1.1)
        with self.assertRaises(ValueError):
            d.quantile(math.nan)

    def test_q_type_rejected(self):
        d = make_range(10)
        with self.assertRaises(TypeError):
            d.quantile("0.5")
        with self.assertRaises(TypeError):
            d.quantile(True)

    def test_median_accuracy(self):
        d = make_range(100)
        self.assertTrue(45.0 <= d.quantile(0.5) <= 56.0, d.quantile(0.5))

    def test_tail_accuracy(self):
        d = make_range(100)
        self.assertTrue(0.5 <= d.quantile(0.01) <= 6.0, d.quantile(0.01))
        self.assertTrue(95.0 <= d.quantile(0.99) <= 100.0, d.quantile(0.99))

    def test_monotone(self):
        d = make_range(100)
        prev = d.quantile(0.0)
        for q in (0.1, 0.25, 0.5, 0.75, 0.9, 1.0):
            cur = d.quantile(q)
            self.assertGreaterEqual(cur, prev)
            prev = cur

    def test_single_value(self):
        d = TDigest()
        d.add(42.0)
        self.assertEqual(d.quantile(0.0), 42.0)
        self.assertEqual(d.quantile(0.5), 42.0)
        self.assertEqual(d.quantile(1.0), 42.0)

    def test_exact_small(self):
        # With compression high relative to n, centroids stay singletons.
        d = TDigest(compression=10000.0)
        for v in (1.0, 2.0, 3.0, 4.0, 5.0):
            d.add(v)
        self.assertAlmostEqual(d.quantile(0.5), 3.0, places=6)

    def test_deterministic(self):
        d1 = make_range(200)
        d2 = make_range(200)
        self.assertEqual(d1.quantile(0.5), d2.quantile(0.5))
        self.assertEqual(d1.quantile(0.99), d2.quantile(0.99))

    def test_compression_bound(self):
        d = TDigest(compression=20.0)
        for v in range(10000):
            d.add(float(v))
        n_centroids = len(d.centroids())
        self.assertLess(n_centroids, 10000)
        self.assertGreater(n_centroids, 0)


class TestCdf(unittest.TestCase):
    def test_empty_raises(self):
        with self.assertRaises(TDigestError):
            TDigest().cdf(1.0)

    def test_below_min_zero(self):
        d = make_range(100)
        self.assertEqual(d.cdf(0.0), 0.0)

    def test_above_max_one(self):
        d = make_range(100)
        self.assertEqual(d.cdf(101.0), 1.0)

    def test_midpoint(self):
        d = make_range(100)
        self.assertTrue(0.45 <= d.cdf(50.0) <= 0.56, d.cdf(50.0))

    def test_cdf_type_rejected(self):
        d = make_range(10)
        with self.assertRaises(TypeError):
            d.cdf("x")
        with self.assertRaises(ValueError):
            d.cdf(math.nan)


class TestMerge(unittest.TestCase):
    def test_merge_combines(self):
        a = TDigest()
        b = TDigest()
        for v in range(1, 51):
            a.add(float(v))
        for v in range(51, 101):
            b.add(float(v))
        a.merge(b)
        self.assertEqual(a.count(), 100)
        self.assertTrue(45.0 <= a.quantile(0.5) <= 56.0)

    def test_merge_type_rejected(self):
        with self.assertRaises(TypeError):
            TDigest().merge("nope")

    def test_merge_compression_mismatch(self):
        a = TDigest(compression=50.0)
        b = TDigest(compression=100.0)
        with self.assertRaises(TDigestError):
            a.merge(b)

    def test_merge_empty(self):
        a = make_range(10)
        a.merge(TDigest())
        self.assertEqual(a.count(), 10)


class TestRecords(unittest.TestCase):
    def test_centroids_sorted(self):
        d = make_range(50)
        means = [c.mean for c in d.centroids()]
        self.assertEqual(means, sorted(means))

    def test_centroid_frozen(self):
        c = Centroid(mean=1.0, count=2)
        with self.assertRaises(Exception):
            c.mean = 3.0  # type: ignore

    def test_centroid_as_dict_schema(self):
        self.assertEqual(Centroid(1.0, 2).as_dict()["schema"], SCHEMA_PIN)

    def test_summary(self):
        d = make_range(100)
        s = d.summary()
        self.assertIsInstance(s, DigestSummary)
        self.assertEqual(s.count, 100)
        self.assertEqual(s.min, 1.0)
        self.assertEqual(s.max, 100.0)
        self.assertEqual(s.compression, 100.0)
        self.assertGreater(s.centroid_count, 0)

    def test_summary_empty_raises(self):
        with self.assertRaises(TDigestError):
            TDigest().summary()

    def test_summary_frozen(self):
        d = make_range(5)
        s = d.summary()
        with self.assertRaises(Exception):
            s.count = 9  # type: ignore


class TestAudit(unittest.TestCase):
    def test_audit_event_shape(self):
        d = make_range(10)
        ev = t_digest_audit_event(d.summary(), "observed", 3)
        self.assertEqual(ev["event"], "t-digest")
        self.assertEqual(ev["outcome"], "observed")
        self.assertEqual(ev["audit_seq"], 3)
        self.assertEqual(ev["schema"], "audit.ndjson/1")

    def test_bad_outcome(self):
        d = make_range(10)
        with self.assertRaises(ValueError):
            t_digest_audit_event(d.summary(), "hacked", 0)

    def test_bad_seq(self):
        d = make_range(10)
        with self.assertRaises(ValueError):
            t_digest_audit_event(d.summary(), "observed", -1)
        with self.assertRaises(ValueError):
            t_digest_audit_event(d.summary(), "observed", True)

    def test_bad_summary_type(self):
        with self.assertRaises(TypeError):
            t_digest_audit_event("x", "observed", 0)  # type: ignore


class TestMain(unittest.TestCase):
    def test_main_runs(self):
        import t_digest

        t_digest.main()


if __name__ == "__main__":
    unittest.main()
