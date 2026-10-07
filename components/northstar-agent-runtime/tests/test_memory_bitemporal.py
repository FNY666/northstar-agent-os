"""Tests for memory_bitemporal: bitemporal records, supersession, decay."""
from __future__ import annotations

import unittest

from memory_bitemporal import (
    BitemporalMemoryStore,
    MEMORY_BITEMPORAL_VERSION,
    MemoryNotFoundError,
    MemoryRecord,
    MemorySupersedeError,
)


class RecordSemanticsTest(unittest.TestCase):
    def test_record_is_frozen(self):
        r = MemoryRecord(
            id="mem-1", content="x", valid_from_seq=0, valid_to_seq=None,
            txn_seq=0, supersedes_id=None, last_accessed_seq=0,
        )
        with self.assertRaises(Exception):
            r.content = "y"  # type: ignore[misc]

    def test_is_current_open_interval(self):
        r = MemoryRecord(
            id="a", content="x", valid_from_seq=5, valid_to_seq=None,
            txn_seq=5, supersedes_id=None, last_accessed_seq=5,
        )
        self.assertTrue(r.is_current())

    def test_is_current_false_when_closed(self):
        r = MemoryRecord(
            id="a", content="x", valid_from_seq=5, valid_to_seq=9,
            txn_seq=5, supersedes_id=None, last_accessed_seq=5,
        )
        self.assertFalse(r.is_current())

    def test_is_current_false_when_expired(self):
        r = MemoryRecord(
            id="a", content="x", valid_from_seq=5, valid_to_seq=None,
            txn_seq=5, supersedes_id=None, last_accessed_seq=5, expired=True,
        )
        self.assertFalse(r.is_current())

    def test_valid_at_interval_edges(self):
        r = MemoryRecord(
            id="a", content="x", valid_from_seq=5, valid_to_seq=10,
            txn_seq=5, supersedes_id=None, last_accessed_seq=5,
        )
        self.assertTrue(r.valid_at(5))   # inclusive start
        self.assertTrue(r.valid_at(9))
        self.assertFalse(r.valid_at(10))  # exclusive end
        self.assertFalse(r.valid_at(4))

    def test_valid_at_open_interval(self):
        r = MemoryRecord(
            id="a", content="x", valid_from_seq=5, valid_to_seq=None,
            txn_seq=5, supersedes_id=None, last_accessed_seq=5,
        )
        self.assertTrue(r.valid_at(1_000_000))

    def test_valid_at_expired_always_false(self):
        r = MemoryRecord(
            id="a", content="x", valid_from_seq=0, valid_to_seq=None,
            txn_seq=0, supersedes_id=None, last_accessed_seq=0, expired=True,
        )
        self.assertFalse(r.valid_at(0))

    def test_as_dict_carries_version_pin(self):
        store = BitemporalMemoryStore()
        r = store.write("hello", txn_seq=3)
        self.assertEqual(r.as_dict()["version"], MEMORY_BITEMPORAL_VERSION)

    def test_seq_validation_rejects_bool_and_negative(self):
        store = BitemporalMemoryStore()
        with self.assertRaises(TypeError):
            store.write("x", txn_seq=True)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            store.write("x", txn_seq=-1)


class WriteTest(unittest.TestCase):
    def test_write_defaults_valid_from_to_txn(self):
        store = BitemporalMemoryStore()
        r = store.write("fact", txn_seq=7)
        self.assertEqual(r.valid_from_seq, 7)
        self.assertIsNone(r.valid_to_seq)
        self.assertIsNone(r.supersedes_id)
        self.assertEqual(r.last_accessed_seq, 7)
        self.assertFalse(r.expired)

    def test_write_backdated_valid_from(self):
        store = BitemporalMemoryStore()
        r = store.write("old fact", txn_seq=10, valid_from_seq=4)
        self.assertEqual(r.valid_from_seq, 4)
        self.assertTrue(r.valid_at(6))

    def test_write_rejects_future_valid_from(self):
        store = BitemporalMemoryStore()
        with self.assertRaises(ValueError):
            store.write("x", txn_seq=10, valid_from_seq=11)

    def test_write_rejects_empty_content(self):
        store = BitemporalMemoryStore()
        with self.assertRaises(ValueError):
            store.write("", txn_seq=1)

    def test_ids_are_unique_and_ordered(self):
        store = BitemporalMemoryStore()
        a = store.write("a", txn_seq=1)
        b = store.write("b", txn_seq=2)
        self.assertNotEqual(a.id, b.id)
        self.assertEqual(len(store), 2)

    def test_get_unknown_raises(self):
        store = BitemporalMemoryStore()
        with self.assertRaises(MemoryNotFoundError):
            store.get("mem-999")


class SupersedeTest(unittest.TestCase):
    def test_supersede_closes_old_and_links_new(self):
        store = BitemporalMemoryStore()
        old = store.write("v1", txn_seq=10)
        new = store.supersede(old.id, "v2", txn_seq=20)
        self.assertEqual(new.supersedes_id, old.id)
        self.assertEqual(new.valid_from_seq, 20)
        closed = store.get(old.id)
        self.assertEqual(closed.valid_to_seq, 20)
        self.assertFalse(closed.is_current())
        self.assertTrue(new.is_current())

    def test_superseded_record_still_queryable_in_history_window(self):
        store = BitemporalMemoryStore()
        old = store.write("v1", txn_seq=10)
        store.supersede(old.id, "v2", txn_seq=20)
        # At seq 15, the old record was the valid one.
        valid_at_15 = store.get_valid(15)
        self.assertEqual([r.id for r in valid_at_15], [old.id])
        # At seq 25, only the new one.
        valid_at_25 = store.get_valid(25)
        self.assertEqual(len(valid_at_25), 1)
        self.assertEqual(valid_at_25[0].content, "v2")

    def test_supersede_twice_fails_closed(self):
        store = BitemporalMemoryStore()
        old = store.write("v1", txn_seq=10)
        store.supersede(old.id, "v2", txn_seq=20)
        with self.assertRaises(MemorySupersedeError):
            store.supersede(old.id, "v3", txn_seq=30)

    def test_supersede_unknown_id_fails(self):
        store = BitemporalMemoryStore()
        with self.assertRaises(MemoryNotFoundError):
            store.supersede("mem-999", "x", txn_seq=1)

    def test_supersede_expired_record_fails(self):
        store = BitemporalMemoryStore()
        old = store.write("v1", txn_seq=10)
        store.apply_decay(current_seq=100, decay_threshold=5)
        with self.assertRaises(MemorySupersedeError):
            store.supersede(old.id, "v2", txn_seq=101)

    def test_supersede_with_earlier_txn_seq_fails(self):
        store = BitemporalMemoryStore()
        old = store.write("v1", txn_seq=10)
        with self.assertRaises(MemorySupersedeError):
            store.supersede(old.id, "v2", txn_seq=5)

    def test_history_walks_full_chain(self):
        store = BitemporalMemoryStore()
        v1 = store.write("v1", txn_seq=1)
        v2 = store.supersede(v1.id, "v2", txn_seq=2)
        v3 = store.supersede(v2.id, "v3", txn_seq=3)
        chain = store.history(v2.id)
        self.assertEqual([r.id for r in chain], [v1.id, v2.id, v3.id])
        # Same chain from the newest end.
        self.assertEqual([r.id for r in store.history(v3.id)], [v1.id, v2.id, v3.id])

    def test_history_single_record(self):
        store = BitemporalMemoryStore()
        r = store.write("solo", txn_seq=1)
        self.assertEqual(store.history(r.id), [r])


class GetValidTest(unittest.TestCase):
    def test_get_valid_excludes_future_records(self):
        store = BitemporalMemoryStore()
        store.write("early", txn_seq=5)
        store.write("late", txn_seq=50)
        valid = store.get_valid(10)
        self.assertEqual([r.content for r in valid], ["early"])

    def test_get_valid_deterministic_order(self):
        store = BitemporalMemoryStore()
        store.write("b", txn_seq=1)
        store.write("a", txn_seq=1)
        valid = store.get_valid(1)
        self.assertEqual([r.txn_seq for r in valid], [1, 1])
        # Same txn_seq: ordered by id for determinism.
        ids = [r.id for r in valid]
        self.assertEqual(ids, sorted(ids))

    def test_get_current_excludes_superseded(self):
        store = BitemporalMemoryStore()
        old = store.write("v1", txn_seq=1)
        new = store.supersede(old.id, "v2", txn_seq=2)
        current = store.get_current()
        self.assertEqual([r.id for r in current], [new.id])


class DecayTest(unittest.TestCase):
    def test_idle_record_decays_past_threshold(self):
        store = BitemporalMemoryStore()
        r = store.write("stale", txn_seq=10)
        expired = store.apply_decay(current_seq=100, decay_threshold=50)
        self.assertEqual(expired, [r.id])
        self.assertTrue(store.get(r.id).expired)

    def test_decay_boundary_is_strict_greater_than(self):
        store = BitemporalMemoryStore()
        r = store.write("edge", txn_seq=10)
        # Exactly at threshold: not decayed.
        self.assertEqual(store.apply_decay(current_seq=60, decay_threshold=50), [])
        self.assertFalse(store.get(r.id).expired)
        # One past: decayed.
        self.assertEqual(store.apply_decay(current_seq=61, decay_threshold=50), [r.id])

    def test_access_prevents_decay(self):
        store = BitemporalMemoryStore()
        r = store.write("kept", txn_seq=10)
        store.access(r.id, at_seq=90)
        expired = store.apply_decay(current_seq=100, decay_threshold=50)
        self.assertEqual(expired, [])
        self.assertFalse(store.get(r.id).expired)

    def test_access_does_not_unexpire(self):
        store = BitemporalMemoryStore()
        r = store.write("gone", txn_seq=10)
        store.apply_decay(current_seq=100, decay_threshold=5)
        self.assertTrue(store.get(r.id).expired)
        store.access(r.id, at_seq=101)
        # Still expired: expiry is sticky.
        self.assertTrue(store.get(r.id).expired)

    def test_access_backwards_seq_rejected(self):
        store = BitemporalMemoryStore()
        r = store.write("x", txn_seq=10)
        with self.assertRaises(ValueError):
            store.access(r.id, at_seq=5)

    def test_decay_skips_superseded_history(self):
        store = BitemporalMemoryStore()
        old = store.write("v1", txn_seq=10)
        new = store.supersede(old.id, "v2", txn_seq=11)
        # Superseded record is audit history: never decayed, even when ancient.
        expired = store.apply_decay(current_seq=10_000, decay_threshold=5)
        self.assertNotIn(old.id, expired)
        # The live successor did decay (never accessed).
        self.assertIn(new.id, expired)

    def test_decayed_record_excluded_from_get_valid(self):
        store = BitemporalMemoryStore()
        r = store.write("faded", txn_seq=10)
        store.apply_decay(current_seq=100, decay_threshold=5)
        self.assertEqual(store.get_valid(50), [])
        self.assertEqual(store.get_current(), [])

    def test_decay_returns_deterministic_order(self):
        store = BitemporalMemoryStore()
        a = store.write("a", txn_seq=1)
        b = store.write("b", txn_seq=2)
        expired = store.apply_decay(current_seq=100, decay_threshold=5)
        self.assertEqual(expired, sorted(expired))
        self.assertEqual(set(expired), {a.id, b.id})

    def test_decay_zero_threshold(self):
        store = BitemporalMemoryStore()
        r = store.write("x", txn_seq=10)
        # Any idle at all decays.
        self.assertEqual(store.apply_decay(current_seq=11, decay_threshold=0), [r.id])

    def test_decay_unknown_seq_validation(self):
        store = BitemporalMemoryStore()
        with self.assertRaises(TypeError):
            store.apply_decay(current_seq="100", decay_threshold=5)  # type: ignore[arg-type]


class MainSmokeTest(unittest.TestCase):
    def test_main_runs(self):
        import io
        from contextlib import redirect_stdout
        import memory_bitemporal as mb
        buf = io.StringIO()
        with redirect_stdout(buf):
            mb.main()
        self.assertIn("memory-bitemporal OK", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
