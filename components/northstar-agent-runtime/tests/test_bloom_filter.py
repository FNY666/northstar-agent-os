"""Targeted tests for bloom_filter.py."""

import unittest

from bloom_filter import (
    BLOOM_FILTER_SCHEMA,
    BLOOM_FILTER_VERSION,
    BloomFilter,
    BloomFilterConfig,
    BloomFilterError,
    CapacityExceeded,
    _optimal_bits,
    _optimal_hashes,
)


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(BLOOM_FILTER_VERSION, "bloom-filter.v1")
        self.assertEqual(BLOOM_FILTER_SCHEMA, "northstar.bloom-filter.v1")

    def test_config_as_dict_pins(self):
        f = BloomFilter.create(100, 0.01)
        d = f.config.as_dict()
        self.assertEqual(d["schema"], BLOOM_FILTER_SCHEMA)
        self.assertEqual(d["version"], BLOOM_FILTER_VERSION)
        self.assertEqual(d["capacity"], 100)
        self.assertEqual(d["error_rate"], 0.01)

    def test_config_frozen(self):
        f = BloomFilter.create(100, 0.01)
        with self.assertRaises(Exception):
            f.config.capacity = 5  # type: ignore


class TestConstructor(unittest.TestCase):
    def test_happy_path(self):
        f = BloomFilter.create(1000, 0.01)
        self.assertEqual(f.capacity, 1000)
        self.assertGreater(f.bits, 0)
        self.assertGreater(f.hashes, 0)
        self.assertEqual(f.inserted, 0)
        self.assertEqual(f.theoretical_error_rate(), 0.01)

    def test_zero_capacity_rejected(self):
        with self.assertRaises(ValueError):
            BloomFilter.create(0, 0.01)

    def test_negative_capacity_rejected(self):
        with self.assertRaises(ValueError):
            BloomFilter.create(-5, 0.01)

    def test_bool_capacity_rejected(self):
        with self.assertRaises(TypeError):
            BloomFilter.create(True, 0.01)

    def test_nonint_capacity_rejected(self):
        with self.assertRaises(TypeError):
            BloomFilter.create("100", 0.01)

    def test_guardrail_rejected(self):
        with self.assertRaises(ValueError):
            BloomFilter.create(10_000_001, 0.01)

    def test_error_rate_bounds(self):
        for bad in (0.0, 1.0, -0.1, 2.0):
            with self.assertRaises(ValueError):
                BloomFilter.create(100, bad)

    def test_bool_error_rate_rejected(self):
        with self.assertRaises(TypeError):
            BloomFilter.create(100, True)

    def test_optimal_params_sane(self):
        # n=1000, p=0.01 -> m ~ 9586 bits, k ~ 7
        self.assertGreater(_optimal_bits(1000, 0.01), 9000)
        self.assertGreaterEqual(_optimal_hashes(_optimal_bits(1000, 0.01), 1000), 1)


class TestMembership(unittest.TestCase):
    def test_clean_miss(self):
        f = BloomFilter.create(1000, 0.01)
        self.assertFalse(f.might_contain("never added"))

    def test_no_false_negatives(self):
        f = BloomFilter.create(500, 0.001)
        items = [f"item-{i}" for i in range(200)]
        for item in items:
            f.add(item)
        for item in items:
            self.assertTrue(f.might_contain(item), f"false negative on {item}")

    def test_add_returns_definitely_new(self):
        f = BloomFilter.create(1000, 0.01)
        self.assertTrue(f.add("fresh"))
        self.assertFalse(f.add("fresh"))

    def test_types_are_tagged(self):
        f = BloomFilter.create(1000, 0.01)
        f.add("1")
        self.assertFalse(f.might_contain(1))
        self.assertFalse(f.might_contain(b"1"))
        f.add(1)
        self.assertTrue(f.might_contain(1))
        self.assertTrue(f.might_contain("1"))

    def test_int_zero_ok(self):
        f = BloomFilter.create(1000, 0.01)
        self.assertTrue(f.add(0))
        self.assertTrue(f.might_contain(0))

    def test_bool_rejected(self):
        f = BloomFilter.create(1000, 0.01)
        with self.assertRaises(TypeError):
            f.add(True)
        with self.assertRaises(TypeError):
            f.might_contain(False)

    def test_negative_int_rejected(self):
        f = BloomFilter.create(1000, 0.01)
        with self.assertRaises(ValueError):
            f.add(-1)

    def test_unsupported_type_rejected(self):
        f = BloomFilter.create(1000, 0.01)
        for bad in (1.5, None, ["a"], {"a": 1}, object()):
            with self.assertRaises(TypeError):
                f.add(bad)
            with self.assertRaises(TypeError):
                f.might_contain(bad)

    def test_bytes_supported(self):
        f = BloomFilter.create(1000, 0.01)
        self.assertTrue(f.add(b"\x00\xff"))
        self.assertTrue(f.might_contain(b"\x00\xff"))

    def test_empty_string_supported(self):
        f = BloomFilter.create(1000, 0.01)
        self.assertTrue(f.add(""))
        self.assertTrue(f.might_contain(""))


class TestCapacity(unittest.TestCase):
    def test_capacity_exceeded_fail_closed(self):
        f = BloomFilter.create(3, 0.01)
        f.add("a")
        f.add("b")
        f.add("c")
        with self.assertRaises(CapacityExceeded) as ctx:
            f.add("d")
        self.assertEqual(ctx.exception.capacity, 3)
        self.assertEqual(ctx.exception.inserted, 3)

    def test_capacity_exceeded_is_bloom_error(self):
        self.assertTrue(issubclass(CapacityExceeded, BloomFilterError))


class TestFalsePositiveRate(unittest.TestCase):
    def test_empty_is_zero(self):
        f = BloomFilter.create(1000, 0.01)
        self.assertEqual(f.false_positive_rate(), 0.0)

    def test_grows_with_fill(self):
        f = BloomFilter.create(200, 0.05)
        r0 = None
        for i in range(0, 100, 10):
            f.add(f"x-{i}")
            r = f.false_positive_rate()
            if r0 is not None:
                self.assertGreaterEqual(r, r0)
            r0 = r
        self.assertGreater(f.false_positive_rate(), 0.0)

    def test_fill_fraction_bounds(self):
        f = BloomFilter.create(1000, 0.01)
        self.assertEqual(f.fill_fraction(), 0.0)
        f.add("a")
        self.assertGreater(f.fill_fraction(), 0.0)
        self.assertLessEqual(f.fill_fraction(), 1.0)


class TestDeterminism(unittest.TestCase):
    def test_identical_filters_identical_digest(self):
        a = BloomFilter.create(500, 0.01)
        b = BloomFilter.create(500, 0.01)
        for i in range(50):
            a.add(f"k{i}")
            b.add(f"k{i}")
        self.assertEqual(a.state_digest(), b.state_digest())
        self.assertEqual(a.to_bytes(), b.to_bytes())

    def test_digest_changes_on_add(self):
        f = BloomFilter.create(500, 0.01)
        d0 = f.state_digest()
        f.add("something")
        self.assertNotEqual(f.state_digest(), d0)
        self.assertTrue(f.state_digest().startswith("sha256:"))


class TestSerialization(unittest.TestCase):
    def test_round_trip(self):
        f = BloomFilter.create(500, 0.01)
        for i in range(100):
            f.add(f"item-{i}")
        data = f.to_bytes()
        r = BloomFilter.from_bytes(data)
        self.assertEqual(r.state_digest(), f.state_digest())
        self.assertEqual(r.inserted, f.inserted)
        for i in range(100):
            self.assertTrue(r.might_contain(f"item-{i}"))
        self.assertFalse(r.might_contain("never-added-here"))

    def test_tampered_bytes_rejected(self):
        f = BloomFilter.create(500, 0.01)
        f.add("a")
        data = bytearray(f.to_bytes())
        data[50] ^= 0xFF
        with self.assertRaises(BloomFilterError):
            BloomFilter.from_bytes(bytes(data))

    def test_truncated_rejected(self):
        with self.assertRaises(BloomFilterError):
            BloomFilter.from_bytes(b"short")

    def test_bad_magic_rejected(self):
        f = BloomFilter.create(100, 0.01)
        data = bytearray(f.to_bytes())
        data[0:4] = b"XXXX"
        body = bytes(data[:-32])
        import hashlib
        fixed = body + hashlib.sha256(body).digest()
        with self.assertRaises(BloomFilterError):
            BloomFilter.from_bytes(fixed)

    def test_non_bytes_rejected(self):
        with self.assertRaises(TypeError):
            BloomFilter.from_bytes("not bytes")


class TestAudit(unittest.TestCase):
    def test_audit_event_shape(self):
        f = BloomFilter.create(100, 0.01)
        f.add("a")
        ev = f.bloom_audit_event("added", seq=3)
        self.assertEqual(ev["schema"], "audit.ndjson/1")
        self.assertEqual(ev["kind"], "bloom-filter.added")
        self.assertEqual(ev["module"], BLOOM_FILTER_SCHEMA)
        self.assertEqual(ev["version"], BLOOM_FILTER_VERSION)
        self.assertEqual(ev["seq"], 3)
        self.assertEqual(ev["inserted"], 1)
        self.assertTrue(ev["state_digest"].startswith("sha256:"))

    def test_bad_kind_rejected(self):
        f = BloomFilter.create(100, 0.01)
        with self.assertRaises(ValueError):
            f.bloom_audit_event("bogus", seq=0)

    def test_bad_seq_rejected(self):
        f = BloomFilter.create(100, 0.01)
        for bad in (-1, True, "3"):
            with self.assertRaises(ValueError):
                f.bloom_audit_event("added", seq=bad)


class TestMain(unittest.TestCase):
    def test_main_runs(self):
        from bloom_filter import main
        main()


if __name__ == "__main__":
    unittest.main()
