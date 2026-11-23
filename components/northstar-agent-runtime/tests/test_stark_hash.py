"""Tests for stark_hash.py."""

import math
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from stark_hash import (  # noqa: E402
    STARK_HASH_VERSION,
    SCHEMA_PIN,
    FIELD_PRIME,
    StarkHash,
    StarkHashError,
    FieldDigest,
    stark_hash_audit_event,
    _permute,
    _sponge,
)


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(STARK_HASH_VERSION, "stark-hash.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.stark-hash.v1")

    def test_field_prime_is_prime_shape(self):
        self.assertEqual(FIELD_PRIME, (1 << 31) - 1)

    def test_sbox_exponent_is_permutation(self):
        self.assertEqual(math.gcd(5, FIELD_PRIME - 1), 1)


class TestConstructor(unittest.TestCase):
    def test_defaults_ok(self):
        StarkHash()

    def test_explicit_defaults_ok(self):
        StarkHash(rate=2, rounds_full=8, rounds_partial=13)

    def test_wrong_rate_rejected(self):
        with self.assertRaises(StarkHashError):
            StarkHash(rate=3)

    def test_wrong_rounds_rejected(self):
        with self.assertRaises(StarkHashError):
            StarkHash(rounds_full=10)

    def test_bool_param_rejected(self):
        with self.assertRaises(TypeError):
            StarkHash(rate=True)


class TestHash(unittest.TestCase):
    def setUp(self):
        self.h = StarkHash()

    def test_returns_field_digest(self):
        d = self.h.hash(b"abc")
        self.assertIsInstance(d, FieldDigest)
        self.assertTrue(0 <= d.value < FIELD_PRIME)

    def test_deterministic(self):
        self.assertEqual(self.h.hash(b"northstar"), self.h.hash(b"northstar"))

    def test_empty_input_defined(self):
        d = self.h.hash(b"")
        self.assertIsInstance(d, FieldDigest)

    def test_avalanche(self):
        self.assertNotEqual(self.h.hash(b"a").value, self.h.hash(b"b").value)

    def test_str_rejected(self):
        with self.assertRaises(TypeError):
            self.h.hash("abc")

    def test_none_rejected(self):
        with self.assertRaises(TypeError):
            self.h.hash(None)

    def test_bool_rejected(self):
        with self.assertRaises(TypeError):
            self.h.hash(True)

    def test_multi_block_input(self):
        # 100 bytes spans many rate blocks; must not raise and must differ
        # from the short input.
        d = self.h.hash(bytes(range(100)))
        self.assertIsInstance(d, FieldDigest)
        self.assertNotEqual(d.value, self.h.hash(b"a").value)


class TestHashMany(unittest.TestCase):
    def setUp(self):
        self.h = StarkHash()

    def test_deterministic(self):
        items = [b"north", b"star"]
        self.assertEqual(self.h.hash_many(items), self.h.hash_many(items))

    def test_domain_separated_from_concat(self):
        items = [b"north", b"star"]
        self.assertNotEqual(
            self.h.hash_many(items).value, self.h.hash(b"northstar").value
        )

    def test_item_boundaries_matter(self):
        self.assertNotEqual(
            self.h.hash_many([b"ab", b"c"]).value,
            self.h.hash_many([b"a", b"bc"]).value,
        )

    def test_empty_list_ok(self):
        d = self.h.hash_many([])
        self.assertIsInstance(d, FieldDigest)

    def test_non_bytes_item_rejected(self):
        with self.assertRaises(TypeError):
            self.h.hash_many([b"ok", "nope"])

    def test_non_sequence_rejected(self):
        with self.assertRaises(TypeError):
            self.h.hash_many(b"not-a-list")


class TestAlgebra(unittest.TestCase):
    def test_permutation_deterministic(self):
        s = [1, 2, 3]
        self.assertEqual(_permute(list(s)), _permute(list(s)))

    def test_permutation_diffuses(self):
        self.assertNotEqual(_permute([1, 2, 3]), _permute([1, 2, 4]))

    def test_permutation_stays_in_field(self):
        out = _permute([FIELD_PRIME - 1, 0, 12345])
        self.assertTrue(all(0 <= x < FIELD_PRIME for x in out))

    def test_sponge_known_shape(self):
        v = _sponge([1, 2], 0)
        self.assertTrue(0 <= v < FIELD_PRIME)


class TestFieldDigest(unittest.TestCase):
    def test_frozen(self):
        d = StarkHash().hash(b"x")
        with self.assertRaises(AttributeError):
            d.value = 5  # type: ignore[misc]

    def test_hex_round_trip(self):
        d = StarkHash().hash(b"x")
        self.assertEqual(len(d.as_hex()), 8)
        self.assertEqual(int(d.as_hex(), 16) % FIELD_PRIME, d.value)

    def test_as_dict_shape(self):
        d = StarkHash().hash(b"x")
        m = d.as_dict()
        self.assertEqual(m["schema"], SCHEMA_PIN)
        self.assertEqual(m["field_prime"], FIELD_PRIME)
        self.assertEqual(m["version"], STARK_HASH_VERSION)

    def test_out_of_field_rejected(self):
        with self.assertRaises(StarkHashError):
            FieldDigest(value=FIELD_PRIME)

    def test_wrong_prime_rejected(self):
        with self.assertRaises(StarkHashError):
            FieldDigest(value=1, field_prime=7)


class TestAuditEvent(unittest.TestCase):
    def test_shape(self):
        d = StarkHash().hash(b"x")
        ev = stark_hash_audit_event("hashed", d, 3)
        self.assertEqual(ev["schema"], "audit.ndjson/1")
        self.assertEqual(ev["kind"], "hashed")
        self.assertEqual(ev["audit_seq"], 3)
        self.assertEqual(ev["digest"]["value"], d.value)

    def test_batch_kind(self):
        d = StarkHash().hash_many([b"x"])
        ev = stark_hash_audit_event("batch-hashed", d, 0)
        self.assertEqual(ev["kind"], "batch-hashed")

    def test_bad_kind_rejected(self):
        d = StarkHash().hash(b"x")
        with self.assertRaises(ValueError):
            stark_hash_audit_event("nope", d, 0)

    def test_bad_digest_rejected(self):
        with self.assertRaises(TypeError):
            stark_hash_audit_event("hashed", "digest", 0)

    def test_bad_seq_rejected(self):
        d = StarkHash().hash(b"x")
        with self.assertRaises(ValueError):
            stark_hash_audit_event("hashed", d, -1)
        with self.assertRaises(ValueError):
            stark_hash_audit_event("hashed", d, True)


class TestMain(unittest.TestCase):
    def test_main_runs(self):
        import stark_hash

        stark_hash.main()


if __name__ == "__main__":
    unittest.main()
