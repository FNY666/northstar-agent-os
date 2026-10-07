"""Targeted tests for rsa_accumulator.py."""

import ast
import dataclasses
import unittest
from pathlib import Path

from rsa_accumulator import (
    RSA_ACCUMULATOR_VERSION,
    RSAAccumulator,
    RSAAccumulatorError,
    MembershipWitness,
    SCHEMA_PIN,
    UnknownElementError,
    _is_prime,
    element_prime,
    rsa_accumulator_audit_event,
)


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(RSA_ACCUMULATOR_VERSION, "rsa-accumulator.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.rsa-accumulator.v1")


class TestElementPrime(unittest.TestCase):
    def test_deterministic(self):
        self.assertEqual(element_prime("alice"), element_prime("alice"))
        self.assertEqual(element_prime(b"bob"), element_prime(b"bob"))

    def test_distinct_elements_distinct_primes(self):
        primes = {element_prime(f"member-{i}") for i in range(50)}
        self.assertEqual(len(primes), 50)

    def test_results_are_prime(self):
        for el in ("a", "b", "c", b"d", "hello world"):
            p = element_prime(el)
            self.assertTrue(_is_prime(p), f"{p} should be prime")

    def test_prime_range(self):
        for el in ("x", "y", b"z"):
            p = element_prime(el)
            self.assertGreaterEqual(p, 1 << 31)
            self.assertLess(p, 1 << 32)

    def test_type_tagged(self):
        # "1" and b"1" are distinct members: no type-confusion collision.
        self.assertNotEqual(element_prime("1"), element_prime(b"1"))

    def test_bad_element_types(self):
        for bad in (123, None, True, ["a"], {"a": 1}):
            with self.assertRaises(TypeError):
                element_prime(bad)

    def test_empty_element(self):
        with self.assertRaises(ValueError):
            element_prime("")
        with self.assertRaises(ValueError):
            element_prime(b"")

    def test_oversize_element(self):
        with self.assertRaises(ValueError):
            element_prime("x" * 4097)


class TestAddRemove(unittest.TestCase):
    def test_add_new_returns_true(self):
        acc = RSAAccumulator()
        self.assertTrue(acc.add("alice"))

    def test_add_duplicate_returns_false(self):
        acc = RSAAccumulator()
        acc.add("alice")
        self.assertFalse(acc.add("alice"))
        self.assertEqual(acc.member_count(), 1)

    def test_remove_existing(self):
        acc = RSAAccumulator()
        acc.add("alice")
        self.assertTrue(acc.remove("alice"))
        self.assertEqual(acc.member_count(), 0)
        self.assertFalse(acc.contains("alice"))

    def test_remove_missing_raises(self):
        acc = RSAAccumulator()
        with self.assertRaises(UnknownElementError):
            acc.remove("ghost")

    def test_unknown_is_accumulator_error(self):
        self.assertTrue(issubclass(UnknownElementError, RSAAccumulatorError))

    def test_readd_recovers_prime(self):
        acc = RSAAccumulator()
        p1 = element_prime("alice")
        acc.add("alice")
        acc.remove("alice")
        acc.add("alice")
        self.assertEqual(acc.witness("alice").element_prime, p1)

    def test_add_validation(self):
        acc = RSAAccumulator()
        with self.assertRaises(TypeError):
            acc.add(42)
        with self.assertRaises(ValueError):
            acc.add("")


class TestDigest(unittest.TestCase):
    def test_empty_digest_stable(self):
        self.assertEqual(
            RSAAccumulator().accumulator_digest(),
            RSAAccumulator().accumulator_digest(),
        )

    def test_digest_pin_shape(self):
        d = RSAAccumulator().accumulator_digest()
        self.assertTrue(d.startswith("sha256:"))
        self.assertEqual(len(d), len("sha256:") + 64)

    def test_order_independent(self):
        a, b = RSAAccumulator(), RSAAccumulator()
        a.add("x")
        a.add("y")
        a.add(b"z")
        b.add(b"z")
        b.add("y")
        b.add("x")
        self.assertEqual(a.accumulator_digest(), b.accumulator_digest())

    def test_digest_changes_on_mutation(self):
        acc = RSAAccumulator()
        d0 = acc.accumulator_digest()
        acc.add("a")
        d1 = acc.accumulator_digest()
        self.assertNotEqual(d0, d1)
        acc.remove("a")
        self.assertEqual(acc.accumulator_digest(), d0)


class TestWitness(unittest.TestCase):
    def test_witness_member(self):
        acc = RSAAccumulator()
        acc.add("alice")
        acc.add("bob")
        w = acc.witness("alice")
        self.assertIsInstance(w, MembershipWitness)
        self.assertEqual(w.element, "alice")
        self.assertEqual(w.element_prime, element_prime("alice"))
        self.assertEqual(w.member_count, 2)
        self.assertEqual(len(w.other_primes), 1)

    def test_witness_nonmember_raises(self):
        acc = RSAAccumulator()
        acc.add("alice")
        with self.assertRaises(UnknownElementError):
            acc.witness("mallory")

    def test_witness_frozen(self):
        acc = RSAAccumulator()
        acc.add("alice")
        w = acc.witness("alice")
        with self.assertRaises(dataclasses.FrozenInstanceError):
            w.member_count = 99  # type: ignore[misc]

    def test_witness_as_dict_schema(self):
        acc = RSAAccumulator()
        acc.add(b"blob")
        d = acc.witness(b"blob").as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertEqual(d["element"], {"type": "bytes", "hex": b"blob".hex()})
        self.assertTrue(d["accumulator_digest"].startswith("sha256:"))
        self.assertIn("witness_digest", d)

    def test_witness_record_validation(self):
        with self.assertRaises(TypeError):
            MembershipWitness(
                element="a",
                element_prime="not-an-int",  # type: ignore[arg-type]
                accumulator_digest="sha256:" + "0" * 64,
                other_primes=(),
                member_count=1,
            )
        with self.assertRaises(ValueError):
            MembershipWitness(
                element="a",
                element_prime=7,
                accumulator_digest="no-pin",
                other_primes=(),
                member_count=1,
            )
        with self.assertRaises(ValueError):
            MembershipWitness(
                element="a",
                element_prime=7,
                accumulator_digest="sha256:" + "0" * 64,
                other_primes=(),
                member_count=0,
            )


class TestVerify(unittest.TestCase):
    def _acc(self):
        acc = RSAAccumulator()
        acc.add("alice")
        acc.add("bob")
        return acc

    def test_verify_happy_path(self):
        acc = self._acc()
        self.assertTrue(acc.verify("alice", acc.witness("alice")))

    def test_verify_wrong_element(self):
        acc = self._acc()
        self.assertFalse(acc.verify("mallory", acc.witness("alice")))

    def test_verify_type_confusion(self):
        acc = RSAAccumulator()
        acc.add("1")
        acc.add(b"1")
        # Witness for "1" must not verify for b"1".
        self.assertFalse(acc.verify(b"1", acc.witness("1")))

    def test_verify_stale_witness_current(self):
        acc = self._acc()
        w = acc.witness("alice")
        acc.remove("alice")
        self.assertFalse(acc.verify("alice", w))

    def test_verify_stale_witness_historical(self):
        acc = self._acc()
        w = acc.witness("alice")
        old = acc.accumulator_digest()
        acc.add("carol")
        self.assertFalse(acc.verify("alice", w))  # current moved on
        self.assertTrue(acc.verify("alice", w, digest=old))

    def test_verify_tampered_other_primes(self):
        acc = self._acc()
        w = acc.witness("alice")
        bad = MembershipWitness(
            element=w.element,
            element_prime=w.element_prime,
            accumulator_digest=w.accumulator_digest,
            other_primes=w.other_primes + (999983,),
            member_count=w.member_count,
        )
        self.assertFalse(acc.verify("alice", bad))

    def test_verify_tampered_digest(self):
        acc = self._acc()
        w = acc.witness("alice")
        bad = MembershipWitness(
            element=w.element,
            element_prime=w.element_prime,
            accumulator_digest="sha256:" + "f" * 64,
            other_primes=w.other_primes,
            member_count=w.member_count,
        )
        self.assertFalse(acc.verify("alice", bad))

    def test_verify_cross_accumulator_same_state(self):
        a, b = self._acc(), self._acc()
        w = a.witness("bob")
        self.assertTrue(b.verify("bob", w))  # witness is state-bound

    def test_verify_non_witness_raises(self):
        acc = self._acc()
        with self.assertRaises(TypeError):
            acc.verify("alice", "not-a-witness")  # type: ignore[arg-type]

    def test_verify_bad_digest_type(self):
        acc = self._acc()
        with self.assertRaises(TypeError):
            acc.verify("alice", acc.witness("alice"), digest=123)  # type: ignore[arg-type]

    def test_bulk_witnesses(self):
        acc = RSAAccumulator()
        names = [f"user-{i}" for i in range(200)]
        for n in names:
            acc.add(n)
        for n in names:
            self.assertTrue(acc.verify(n, acc.witness(n)), n)


class TestMembers(unittest.TestCase):
    def test_members_sorted_deterministic(self):
        acc = RSAAccumulator()
        acc.add("charlie")
        acc.add("alice")
        acc.add(b"bob")
        self.assertEqual(acc.members(), acc.members())
        self.assertEqual(len(acc.members()), 3)
        self.assertIn("alice", acc.members())

    def test_contains(self):
        acc = RSAAccumulator()
        acc.add("alice")
        self.assertTrue(acc.contains("alice"))
        self.assertFalse(acc.contains(b"alice"))
        self.assertFalse(acc.contains("bob"))


class TestEvents(unittest.TestCase):
    def test_events_logged(self):
        acc = RSAAccumulator()
        acc.add("a")
        acc.add("b")
        acc.remove("a")
        kinds = [e["kind"] for e in acc.events()]
        self.assertEqual(kinds, ["add", "add", "remove"])
        seqs = [e["seq"] for e in acc.events()]
        self.assertEqual(seqs, [1, 2, 3])
        for e in acc.events():
            self.assertEqual(e["format"], "audit.ndjson/1")
            self.assertEqual(e["schema"], SCHEMA_PIN)

    def test_witness_issue_logged(self):
        acc = RSAAccumulator()
        acc.add("a")
        acc.witness("a")
        self.assertEqual(acc.events()[-1]["kind"], "witness-issued")


class TestAuditEvent(unittest.TestCase):
    def test_shape(self):
        acc = RSAAccumulator()
        acc.add("alice")
        e = rsa_accumulator_audit_event(
            "add", "alice", 7, acc.accumulator_digest()
        )
        self.assertEqual(e["format"], "audit.ndjson/1")
        self.assertEqual(e["schema"], SCHEMA_PIN)
        self.assertEqual(e["kind"], "add")
        self.assertEqual(e["seq"], 7)
        self.assertEqual(e["element"], {"type": "str", "value": "alice"})

    def test_bytes_element(self):
        e = rsa_accumulator_audit_event("remove", b"\x00\x01", 1)
        self.assertEqual(e["element"], {"type": "bytes", "hex": "0001"})
        self.assertNotIn("digest", e)

    def test_bad_kind(self):
        with self.assertRaises(ValueError):
            rsa_accumulator_audit_event("explode", "a", 1)

    def test_bad_seq(self):
        with self.assertRaises(TypeError):
            rsa_accumulator_audit_event("add", "a", True)
        with self.assertRaises(ValueError):
            rsa_accumulator_audit_event("add", "a", -1)

    def test_bad_element(self):
        with self.assertRaises(TypeError):
            rsa_accumulator_audit_event("add", 5, 1)


class TestStdlibOnly(unittest.TestCase):
    def test_stdlib_imports_only(self):
        src = Path(__file__).resolve().parent.parent / "rsa_accumulator.py"
        tree = ast.parse(src.read_text())
        allowed = {
            "hashlib",
            "threading",
            "dataclasses",
            "typing",
            "__future__",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed)


class TestMain(unittest.TestCase):
    def test_main_runs(self):
        import rsa_accumulator

        rsa_accumulator.main()  # asserts internally


if __name__ == "__main__":
    unittest.main()
