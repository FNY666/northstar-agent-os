"""Tests for cache_tier.py — LRU/LFU eviction, multi-level promotion/spillover."""

import unittest

from cache_tier import (
    CACHE_TIER_VERSION,
    SCHEMA_PIN,
    CacheTier,
    CacheTierError,
    EvictionPolicy,
    GetOutcome,
    MultiLevelCache,
    cache_tier_audit_event,
    main,
)


class TestPins(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(CACHE_TIER_VERSION, "cache-tier.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.cache-tier.v1")

    def test_record_pins(self):
        t = CacheTier("l1", 2)
        rec = t.put("k", "v", seq=1)
        self.assertEqual(rec.version, CACHE_TIER_VERSION)
        d = rec.as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertTrue(d["key_digest"].startswith("sha256:"))
        stats = t.stats()
        self.assertEqual(stats.as_dict()["schema"], SCHEMA_PIN)

    def test_get_outcome_no_value_leak_on_miss(self):
        t = CacheTier("l1", 2)
        out = t.get("nope", seq=1)
        self.assertFalse(out.hit)
        self.assertIsNone(out.tier)
        self.assertIsNone(out.as_dict()["value"])


class TestConstructorValidation(unittest.TestCase):
    def test_bad_capacity(self):
        for bad in (0, -3, True, "4", 2.5, 1_000_001):
            with self.assertRaises(CacheTierError, msg=f"capacity={bad!r}"):
                CacheTier("l1", bad)

    def test_bad_policy(self):
        with self.assertRaises(CacheTierError):
            CacheTier("l1", 2, policy="mru")
        with self.assertRaises(CacheTierError):
            CacheTier("l1", 2, policy="")

    def test_bad_name(self):
        with self.assertRaises(CacheTierError):
            CacheTier("", 2)
        with self.assertRaises(CacheTierError):
            CacheTier(123, 2)


class TestKeyValidation(unittest.TestCase):
    def setUp(self):
        self.t = CacheTier("l1", 2)

    def test_bad_keys(self):
        for bad in ("", 123, None, True, b"k"):
            with self.assertRaises(CacheTierError, msg=f"key={bad!r}"):
                self.t.put(bad, "v", seq=1)
            with self.assertRaises(CacheTierError):
                self.t.get(bad, seq=1)
            with self.assertRaises(CacheTierError):
                self.t.evict(bad, seq=1)

    def test_none_value_rejected(self):
        with self.assertRaises(CacheTierError):
            self.t.put("k", None, seq=1)

    def test_bad_seq(self):
        with self.assertRaises(CacheTierError):
            self.t.put("k", "v", seq=-1)
        with self.assertRaises(CacheTierError):
            self.t.get("k", seq=True)


class TestLRU(unittest.TestCase):
    def test_put_get_roundtrip(self):
        t = CacheTier("l1", 2, EvictionPolicy.LRU)
        t.put("a", 1, seq=1)
        out = t.get("a", seq=2)
        self.assertTrue(out.hit)
        self.assertEqual(out.value, 1)
        self.assertEqual(out.tier, "l1")

    def test_lru_evicts_least_recently_used(self):
        t = CacheTier("l1", 2, EvictionPolicy.LRU)
        t.put("a", 1, seq=1)
        t.put("b", 2, seq=2)
        rec = t.put("c", 3, seq=3)
        self.assertIsNotNone(rec.evicted_key_digest)
        self.assertFalse(t.contains("a"))
        self.assertTrue(t.contains("b"))
        self.assertTrue(t.contains("c"))

    def test_get_refreshes_recency(self):
        t = CacheTier("l1", 2, EvictionPolicy.LRU)
        t.put("a", 1, seq=1)
        t.put("b", 2, seq=2)
        t.get("a", seq=3)  # a is now most recent
        t.put("c", 3, seq=4)  # evicts b, not a
        self.assertTrue(t.contains("a"))
        self.assertFalse(t.contains("b"))

    def test_overwrite_updates_value_no_eviction(self):
        t = CacheTier("l1", 2, EvictionPolicy.LRU)
        t.put("a", 1, seq=1)
        t.put("b", 2, seq=2)
        rec = t.put("a", 99, seq=3)
        self.assertIsNone(rec.evicted_key_digest)
        self.assertEqual(t.get("a", seq=4).value, 99)


class TestLFU(unittest.TestCase):
    def test_lfu_evicts_least_frequent(self):
        t = CacheTier("l1", 2, EvictionPolicy.LFU)
        t.put("a", 1, seq=1)
        t.put("b", 2, seq=2)
        t.get("a", seq=3)
        t.get("a", seq=4)  # a: freq 3, b: freq 1
        rec = t.put("c", 3, seq=5)
        self.assertTrue(rec.evicted_key_digest is not None)
        self.assertFalse(t.contains("b"))
        self.assertTrue(t.contains("a"))

    def test_lfu_tie_broken_by_recency(self):
        t = CacheTier("l1", 2, EvictionPolicy.LFU)
        t.put("a", 1, seq=1)
        t.put("b", 2, seq=2)
        t.get("b", seq=3)  # both freq 2; b more recent
        t.put("c", 3, seq=4)  # evicts a (same freq, older)
        self.assertFalse(t.contains("a"))
        self.assertTrue(t.contains("b"))


class TestEvictAndStats(unittest.TestCase):
    def test_explicit_evict(self):
        t = CacheTier("l1", 2)
        t.put("a", 1, seq=1)
        self.assertTrue(t.evict("a", seq=2))
        self.assertFalse(t.evict("a", seq=3))
        self.assertFalse(t.contains("a"))

    def test_explicit_evict_counts_and_logs(self):
        t = CacheTier("l1", 2)
        t.put("a", 1, seq=1)
        t.evict("a", seq=2)
        self.assertEqual(t.stats().evictions, 1)
        log = t.eviction_log()
        self.assertEqual(len(log), 1)
        self.assertEqual(log[0].reason, "explicit")
        self.assertEqual(log[0].tier, "l1")

    def test_stats_counters_and_hit_rate(self):
        t = CacheTier("l1", 4)
        self.assertIsNone(t.stats().hit_rate)  # no lookups yet
        t.put("a", 1, seq=1)
        t.get("a", seq=2)
        t.get("missing", seq=3)
        s = t.stats()
        self.assertEqual((s.hits, s.misses, s.puts), (1, 1, 1))
        self.assertEqual(s.size, 1)
        self.assertEqual(s.hit_rate, 0.5)

    def test_contains_does_not_touch_recency(self):
        t = CacheTier("l1", 2, EvictionPolicy.LRU)
        t.put("a", 1, seq=1)
        t.put("b", 2, seq=2)
        self.assertTrue(t.contains("a"))
        t.put("c", 3, seq=3)  # contains() must not save "a"
        self.assertFalse(t.contains("a"))

    def test_eviction_log_capacity_reason(self):
        t = CacheTier("l1", 1, EvictionPolicy.LRU)
        t.put("a", 1, seq=1)
        t.put("b", 2, seq=2)
        log = t.eviction_log()
        self.assertEqual(log[0].reason, "capacity")
        self.assertEqual(log[0].policy, EvictionPolicy.LRU)


class TestDeterminism(unittest.TestCase):
    def test_same_ops_same_evictions(self):
        def run():
            t = CacheTier("l1", 3, EvictionPolicy.LFU)
            ops = [("a", 1), ("b", 2), ("c", 3)]
            for i, (k, v) in enumerate(ops, start=1):
                t.put(k, v, seq=i)
            t.get("a", seq=4)
            t.get("b", seq=5)
            t.put("d", 4, seq=6)
            return [e.key_digest for e in t.eviction_log()]

        self.assertEqual(run(), run())


class TestMultiLevel(unittest.TestCase):
    def make(self):
        return MultiLevelCache(
            [
                CacheTier("l1", 1, EvictionPolicy.LRU),
                CacheTier("l2", 2, EvictionPolicy.LRU),
            ]
        )

    def test_get_miss(self):
        m = self.make()
        out = m.get("nope", seq=1)
        self.assertFalse(out.hit)
        self.assertIsNone(out.tier)

    def test_l1_hit_no_promotion_needed(self):
        m = self.make()
        m.put("k", "v", seq=1)
        out = m.get("k", seq=2)
        self.assertTrue(out.hit)
        self.assertEqual(out.tier, "l1")

    def test_below_l1_hit_promotes(self):
        m = self.make()
        m.put("k", "v", seq=1)
        m.put("k2", "v2", seq=2)  # evicts k from l1 -> spills to l2
        self.assertFalse(m.tiers[0].contains("k"))
        self.assertTrue(m.tiers[1].contains("k"))
        out = m.get("k", seq=3)
        self.assertTrue(out.hit)
        self.assertEqual(out.tier, "l2")
        self.assertTrue(m.tiers[0].contains("k"))  # promoted back to l1

    def test_put_spills_victim_down(self):
        m = self.make()
        m.put("a", 1, seq=1)
        m.put("b", 2, seq=2)  # a spills from l1 to l2
        self.assertFalse(m.tiers[0].contains("a"))
        self.assertTrue(m.tiers[1].contains("a"))
        # l1 victim's value is preserved in l2
        self.assertEqual(m.get("a", seq=3).value, 1)

    def test_last_tier_victim_is_lost(self):
        m = MultiLevelCache([CacheTier("only", 1, EvictionPolicy.LRU)])
        m.put("a", 1, seq=1)
        m.put("b", 2, seq=2)  # a has nowhere to spill
        self.assertFalse(m.get("a", seq=3).hit)

    def test_evict_across_tiers(self):
        m = self.make()
        m.put("a", 1, seq=1)
        m.put("b", 2, seq=2)  # a now in l2
        self.assertTrue(m.evict("a", seq=3))
        self.assertFalse(m.tiers[1].contains("a"))
        self.assertFalse(m.evict("a", seq=4))

    def test_stats_per_tier(self):
        m = self.make()
        m.put("a", 1, seq=1)
        stats = m.stats()
        self.assertEqual(len(stats), 2)
        self.assertEqual(stats[0].tier, "l1")
        self.assertEqual(stats[1].tier, "l2")
        self.assertEqual(stats[0].puts, 1)

    def test_bad_construction(self):
        with self.assertRaises(CacheTierError):
            MultiLevelCache([])
        with self.assertRaises(CacheTierError):
            MultiLevelCache([CacheTier("l1", 1), "nope"])
        with self.assertRaises(CacheTierError):
            MultiLevelCache([CacheTier("l1", 1), CacheTier("l1", 2)])


class TestAuditEvents(unittest.TestCase):
    def test_kinds(self):
        for kind in ("put", "got", "evicted", "promoted", "rejected"):
            rec = cache_tier_audit_event(kind, seq=1, key_digest="sha256:x")
            self.assertEqual(rec["schema"], "audit.ndjson/1")
            self.assertEqual(rec["kind"], f"cache-tier.{kind}")
            self.assertEqual(rec["module"], CACHE_TIER_VERSION)

    def test_unknown_kind_rejected(self):
        with self.assertRaises(CacheTierError):
            cache_tier_audit_event("dropped", seq=1)

    def test_raw_value_never_logged(self):
        with self.assertRaises(CacheTierError):
            cache_tier_audit_event("put", seq=1, value="secret")

    def test_bad_seq(self):
        with self.assertRaises(CacheTierError):
            cache_tier_audit_event("put", seq=-1)


class TestMain(unittest.TestCase):
    def test_main(self):
        main()  # must not raise


class TestStdlibOnly(unittest.TestCase):
    def test_stdlib_only(self):
        import ast
        from pathlib import Path

        module_path = Path(__file__).resolve().parent.parent / "cache_tier.py"
        tree = ast.parse(module_path.read_text())
        allowed = {
            "__future__", "hashlib", "dataclasses", "typing",
            "builtins",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], allowed, a.name)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed, node.module)


if __name__ == "__main__":
    unittest.main()
