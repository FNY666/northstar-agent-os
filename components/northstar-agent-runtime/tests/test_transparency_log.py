"""Tests for transparency_log (Certificate Transparency style append-only log)."""

import hashlib
import unittest

from transparency_log import (
    EMPTY_ROOT,
    SCHEMA_PIN,
    TRANSPARENCY_LOG_VERSION,
    ConsistencyProof,
    InclusionProof,
    LogEntry,
    ProofStep,
    TransparencyLog,
    TransparencyLogError,
    transparency_log_audit_event,
    verify_consistency,
    verify_inclusion,
)


def _entries(n):
    return [f"entry-{i}".encode() for i in range(n)]


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(TRANSPARENCY_LOG_VERSION, "transparency-log.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.transparency-log.v1")

    def test_empty_root_is_sha256_of_empty(self):
        self.assertEqual(EMPTY_ROOT, hashlib.sha256(b"").digest())
        log = TransparencyLog()
        self.assertEqual(log.root(), EMPTY_ROOT)
        self.assertEqual(log.size(), 0)


class TestAppend(unittest.TestCase):
    def test_append_returns_log_entry_index_zero(self):
        log = TransparencyLog()
        e = log.append(b"hello")
        self.assertIsInstance(e, LogEntry)
        self.assertEqual(e.index, 0)
        self.assertEqual(log.size(), 1)

    def test_append_indices_increment(self):
        log = TransparencyLog()
        for i in range(5):
            self.assertEqual(log.append(b"x").index, i)

    def test_append_entry_digest_pin(self):
        log = TransparencyLog()
        e = log.append(b"hello")
        self.assertEqual(e.entry_digest, "sha256:" + hashlib.sha256(b"hello").hexdigest())

    def test_append_str_entry_utf8(self):
        log = TransparencyLog()
        e = log.append("héllo")
        expected = hashlib.sha256(b"\x00" + "héllo".encode("utf-8")).digest()
        self.assertEqual(e.leaf_hash, expected)

    def test_str_and_bytes_equivalence(self):
        a, b = TransparencyLog(), TransparencyLog()
        self.assertEqual(a.append("abc").leaf_hash, b.append(b"abc").leaf_hash)

    def test_append_rejects_bad_types(self):
        log = TransparencyLog()
        for bad in (123, None, True, ["x"], {"x": 1}, 4.5):
            with self.assertRaises(TypeError):
                log.append(bad)

    def test_root_changes_on_append(self):
        log = TransparencyLog()
        r0 = log.root()
        log.append(b"a")
        r1 = log.root()
        log.append(b"b")
        r2 = log.root()
        self.assertNotEqual(r0, r1)
        self.assertNotEqual(r1, r2)

    def test_root_deterministic_across_logs(self):
        a, b = TransparencyLog(), TransparencyLog()
        for e in _entries(12):
            a.append(e)
            b.append(e)
        self.assertEqual(a.root(), b.root())

    def test_leaf_hash_domain_separation(self):
        log = TransparencyLog()
        e = log.append(b"data")
        self.assertEqual(e.leaf_hash, hashlib.sha256(b"\x00data").digest())
        self.assertNotEqual(e.leaf_hash, hashlib.sha256(b"data").digest())


class TestInclusion(unittest.TestCase):
    def test_inclusion_all_indices(self):
        log = TransparencyLog()
        entries = _entries(10)
        for e in entries:
            log.append(e)
        head = log.root()
        for i, e in enumerate(entries):
            proof = log.inclusion_proof(i)
            self.assertIsInstance(proof, InclusionProof)
            self.assertEqual(proof.index, i)
            self.assertEqual(proof.tree_size, 10)
            self.assertEqual(proof.root, head)
            self.assertTrue(verify_inclusion(e, proof, head))

    def test_inclusion_single_leaf_empty_path(self):
        log = TransparencyLog()
        log.append(b"only")
        proof = log.inclusion_proof(0)
        self.assertEqual(proof.steps, ())
        self.assertTrue(verify_inclusion(b"only", proof, log.root()))

    def test_inclusion_wrong_entry_fails(self):
        log = TransparencyLog()
        log.append(b"a")
        log.append(b"b")
        proof = log.inclusion_proof(0)
        self.assertFalse(verify_inclusion(b"WRONG", proof, log.root()))

    def test_inclusion_wrong_root_fails(self):
        log = TransparencyLog()
        log.append(b"a")
        proof = log.inclusion_proof(0)
        self.assertFalse(verify_inclusion(b"a", proof, EMPTY_ROOT))

    def test_inclusion_tampered_step_fails(self):
        log = TransparencyLog()
        for e in _entries(5):
            log.append(e)
        proof = log.inclusion_proof(2)
        self.assertGreater(len(proof.steps), 0)
        bad = ProofStep(b"\xff" * 32, proof.steps[0].sibling_is_left)
        tampered = InclusionProof(
            index=proof.index, tree_size=proof.tree_size,
            steps=(bad,) + proof.steps[1:], root=proof.root,
        )
        self.assertFalse(verify_inclusion(_entries(5)[2], tampered, log.root()))

    def test_inclusion_str_entry_verifies(self):
        log = TransparencyLog()
        log.append("text-entry")
        proof = log.inclusion_proof(0)
        self.assertTrue(verify_inclusion("text-entry", proof, log.root()))

    def test_inclusion_bad_index_raises(self):
        log = TransparencyLog()
        log.append(b"a")
        with self.assertRaises(ValueError):
            log.inclusion_proof(-1)
        for bad in (1, 99):
            with self.assertRaises(TransparencyLogError):
                log.inclusion_proof(bad)
        for bad in (True, "0", 1.0):
            with self.assertRaises(TypeError):
                log.inclusion_proof(bad)

    def test_inclusion_empty_log_raises(self):
        with self.assertRaises(TransparencyLogError):
            TransparencyLog().inclusion_proof(0)

    def test_inclusion_path_length_logarithmic(self):
        log = TransparencyLog()
        for e in _entries(100):
            log.append(e)
        for i in (0, 37, 99):
            self.assertLessEqual(len(log.inclusion_proof(i).steps), 7)

    def test_inclusion_verify_rejects_bad_proof_type(self):
        log = TransparencyLog()
        log.append(b"a")
        with self.assertRaises(TypeError):
            verify_inclusion(b"a", "not-a-proof", log.root())

    def test_inclusion_verify_rejects_bad_root(self):
        log = TransparencyLog()
        log.append(b"a")
        proof = log.inclusion_proof(0)
        with self.assertRaises((TypeError, ValueError)):
            verify_inclusion(b"a", proof, b"short")


class TestConsistency(unittest.TestCase):
    def _log_of(self, n):
        log = TransparencyLog()
        for e in _entries(n):
            log.append(e)
        return log

    def test_consistency_all_pairs_small(self):
        full = self._log_of(16)
        for n in range(2, 17):
            new_root = self._log_of(n).root()
            for m in range(1, n):
                old_root = self._log_of(m).root()
                cp = full.consistency_proof(m, n)
                self.assertIsInstance(cp, ConsistencyProof)
                self.assertTrue(
                    verify_consistency(old_root, m, new_root, n, cp.hashes),
                    f"consistency {m}->{n} failed",
                )

    def test_consistency_equal_sizes_empty_proof(self):
        log = self._log_of(6)
        cp = log.consistency_proof(6, 6)
        self.assertEqual(cp.hashes, ())
        self.assertTrue(verify_consistency(log.root(), 6, log.root(), 6, ()))
        other = self._log_of(5)
        self.assertFalse(verify_consistency(log.root(), 6, other.root(), 6, ()))

    def test_consistency_proof_length_logarithmic(self):
        full = self._log_of(200)
        for m, n in ((1, 200), (199, 200), (100, 200), (1, 2)):
            cp = full.consistency_proof(m, n)
            self.assertLessEqual(len(cp.hashes), 9, f"{m}->{n}")

    def test_consistency_old_larger_raises(self):
        log = self._log_of(4)
        with self.assertRaises(TransparencyLogError):
            log.consistency_proof(4, 3)

    def test_consistency_old_zero_raises(self):
        log = self._log_of(4)
        with self.assertRaises(TransparencyLogError):
            log.consistency_proof(0, 4)

    def test_consistency_new_beyond_size_raises(self):
        log = self._log_of(4)
        with self.assertRaises(TransparencyLogError):
            log.consistency_proof(2, 5)

    def test_consistency_bool_sizes_rejected(self):
        log = self._log_of(4)
        with self.assertRaises(TypeError):
            log.consistency_proof(True, 4)

    def test_consistency_tampered_hash_fails(self):
        full = self._log_of(8)
        old_root = self._log_of(3).root()
        cp = full.consistency_proof(3, 8)
        bad = (b"\x00" * 32,) + cp.hashes[1:]
        self.assertFalse(verify_consistency(old_root, 3, full.root(), 8, bad))

    def test_consistency_wrong_old_root_fails(self):
        full = self._log_of(8)
        cp = full.consistency_proof(3, 8)
        self.assertFalse(verify_consistency(EMPTY_ROOT, 3, full.root(), 8, cp.hashes))

    def test_consistency_wrong_new_root_fails(self):
        full = self._log_of(8)
        old_root = self._log_of(3).root()
        cp = full.consistency_proof(3, 8)
        self.assertFalse(verify_consistency(old_root, 3, EMPTY_ROOT, 8, cp.hashes))

    def test_consistency_verify_rejects_type_misuse(self):
        full = self._log_of(4)
        cp = full.consistency_proof(1, 4)
        with self.assertRaises(TypeError):
            verify_consistency("x" * 32, 1, full.root(), 4, cp.hashes)
        with self.assertRaises(TypeError):
            verify_consistency(full.root(), 1, full.root(), 4, ["not-bytes"])

    def test_consistency_verify_rejects_bad_sizes(self):
        full = self._log_of(4)
        cp = full.consistency_proof(1, 4)
        with self.assertRaises(TransparencyLogError):
            verify_consistency(full.root(), 4, full.root(), 1, cp.hashes)
        with self.assertRaises(TransparencyLogError):
            verify_consistency(full.root(), 0, full.root(), 4, cp.hashes)


class TestRecordsAndAudit(unittest.TestCase):
    def test_records_frozen(self):
        log = TransparencyLog()
        entry = log.append(b"a")
        proof = log.inclusion_proof(0)
        cp = log.consistency_proof(1, 1)
        for rec, attr in ((entry, "index"), (proof, "index"), (cp, "old_size")):
            with self.assertRaises(Exception):
                setattr(rec, attr, 999)

    def test_as_dict_shapes(self):
        log = TransparencyLog()
        entry = log.append(b"a")
        d = entry.as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertTrue(d["entry_digest"].startswith("sha256:"))
        proof = log.inclusion_proof(0)
        pd = proof.as_dict()
        self.assertEqual(pd["tree_size"], 1)
        self.assertEqual(pd["root"], log.root().hex())
        cp = log.consistency_proof(1, 1)
        self.assertEqual(cp.as_dict()["schema"], SCHEMA_PIN)

    def test_audit_event_shapes(self):
        ev = transparency_log_audit_event("appended", 3)
        self.assertEqual(ev["event"], "transparency-log")
        self.assertEqual(ev["outcome"], "appended")
        self.assertEqual(ev["audit_seq"], 3)
        self.assertEqual(ev["schema"], "audit.ndjson/1")
        for kind in ("inclusion-proved", "consistency-proved"):
            self.assertEqual(transparency_log_audit_event(kind, 0)["outcome"], kind)
        with self.assertRaises(ValueError):
            transparency_log_audit_event("bogus", 0)
        for bad_seq in (-1, True, "0"):
            with self.assertRaises((TypeError, ValueError)):
                transparency_log_audit_event("appended", bad_seq)

    def test_main_self_check(self):
        import transparency_log as mod
        mod.main()


if __name__ == "__main__":
    unittest.main()
