"""Tests for cache_aside (unittest style; pytest runs these too)."""

import subprocess
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cache_aside import (
    AUDIT_SCHEMA,
    CACHE_ASIDE_SCHEMA,
    CACHE_ASIDE_VERSION,
    AuditKindError,
    BadBackendError,
    BadCapacityError,
    BadKeyError,
    BadStrategyError,
    BadTTLError,
    BadValueError,
    CacheAside,
    CacheAsideError,
    SeqOrderError,
    cache_aside_audit_event,
    main,
)


class TestPins(unittest.TestCase):
    def test_version_pins(self):
        self.assertEqual(CACHE_ASIDE_VERSION, "cache-aside.v1")
        self.assertEqual(CACHE_ASIDE_SCHEMA, "northstar.cache-aside.v1")
        self.assertEqual(AUDIT_SCHEMA, "audit.ndjson/1")


class TestGetPath(unittest.TestCase):
    def test_miss_without_loader_is_data(self):
        ca = CacheAside()
        r = ca.get("k", seq=1)
        self.assertFalse(r.hit)
        self.assertFalse(r.loaded)
        self.assertIsNone(r.value)
        self.assertTrue(r.verify())

    def test_loader_populates_cache(self):
        ca = CacheAside()
        calls = []

        def loader(k):
            calls.append(k)
            return "v-" + k

        r = ca.get("k", seq=1, loader=loader)
        self.assertTrue(r.loaded)
        self.assertEqual(r.value, "v-k")
        self.assertTrue(r.verify())
        r2 = ca.get("k", seq=2, loader=loader)
        self.assertTrue(r2.hit)
        self.assertFalse(r2.loaded)
        self.assertEqual(r2.value, "v-k")
        self.assertEqual(calls, ["k"])  # loader called once

    def test_raising_loader_is_data(self):
        ca = CacheAside()

        def boom(k):
            raise RuntimeError("origin down")

        r = ca.get("k", seq=1, loader=boom)
        self.assertFalse(r.hit)
        self.assertFalse(r.loaded)
        self.assertIsNone(r.value)
        self.assertTrue(r.verify())

    def test_none_loader_return_is_data(self):
        ca = CacheAside()
        r = ca.get("k", seq=1, loader=lambda k: None)
        self.assertFalse(r.loaded)
        self.assertIsNone(r.value)

    def test_default_loader_reads_simulated_origin(self):
        ca = CacheAside()
        ca.set("k", "v", seq=1)  # writes simulated origin
        r = ca.get("k", seq=2)  # miss -> default loader -> origin
        self.assertTrue(r.loaded)
        self.assertEqual(r.value, "v")


class TestSetPath(unittest.TestCase):
    def test_invalidate_strategy_deletes_cache_entry(self):
        ca = CacheAside()
        ca.set("k", "v1", seq=1, strategy="update")
        self.assertTrue(ca.get("k", seq=2).hit)
        rec = ca.set("k", "v2", seq=3, strategy="invalidate")
        self.assertTrue(rec.written)
        self.assertEqual(rec.cache_action, "invalidated")
        self.assertTrue(rec.verify())
        self.assertFalse(ca.get("k", seq=4, loader=lambda k: None).hit)

    def test_update_strategy_refreshes_cache_entry(self):
        ca = CacheAside()
        rec = ca.set("k", "v1", seq=1, strategy="update")
        self.assertEqual(rec.cache_action, "updated")
        r = ca.get("k", seq=2)
        self.assertTrue(r.hit)
        self.assertEqual(r.value, "v1")

    def test_writer_failure_is_data_cache_untouched(self):
        ca = CacheAside()
        ca.set("k", "v1", seq=1, strategy="update")

        def boom(k, v):
            raise RuntimeError("db down")

        rec = ca.set("k", "v2", seq=2, writer=boom, strategy="invalidate")
        self.assertFalse(rec.written)
        self.assertEqual(rec.cache_action, "none")
        self.assertTrue(rec.verify())
        # cache still holds the old value
        self.assertEqual(ca.get("k", seq=3).value, "v1")

    def test_custom_writer_is_called(self):
        seen = []
        ca = CacheAside()
        rec = ca.set("k", "v", seq=1, writer=lambda k, v: seen.append((k, v)))
        self.assertTrue(rec.written)
        self.assertEqual(seen, [("k", "v")])

    def test_bad_strategy_refused(self):
        ca = CacheAside()
        with self.assertRaises(BadStrategyError):
            ca.set("k", "v", seq=1, strategy="write-around")


class TestInvalidate(unittest.TestCase):
    def test_invalidate_existing(self):
        ca = CacheAside()
        ca.set("k", "v", seq=1, strategy="update")
        rec = ca.invalidate("k", seq=2)
        self.assertTrue(rec.existed)
        self.assertTrue(rec.verify())
        self.assertFalse(ca.get("k", seq=3, loader=lambda k: None).hit)

    def test_invalidate_absent_is_idempotent(self):
        ca = CacheAside()
        rec = ca.invalidate("nope", seq=1)
        self.assertFalse(rec.existed)
        self.assertTrue(rec.verify())
        # double invalidate still fine
        rec2 = ca.invalidate("nope", seq=2)
        self.assertFalse(rec2.existed)


class TestTTL(unittest.TestCase):
    def test_expire_sweeps(self):
        ca = CacheAside()
        ca.set("a", 1, seq=1, strategy="update", ttl=2)
        ca.set("b", 2, seq=2, strategy="update")  # no ttl
        rep = ca.expire(seq=3)
        self.assertEqual(rep.count, 1)
        self.assertEqual(len(rep.expired_key_digests), 1)
        self.assertTrue(rep.verify())
        self.assertEqual(ca.stats(seq=4).size, 1)

    def test_lazy_expiry_on_get(self):
        ca = CacheAside()
        ca.set("a", 1, seq=1, strategy="update", ttl=2)
        r = ca.get("a", seq=5, loader=lambda k: None)  # expired by seq 3
        self.assertFalse(r.hit)
        self.assertFalse(r.loaded)


class TestEviction(unittest.TestCase):
    def test_fifo_eviction_deterministic(self):
        ca = CacheAside(capacity=2)
        ca.set("a", 1, seq=1, strategy="update")
        ca.set("b", 2, seq=2, strategy="update")
        rec = ca.set("c", 3, seq=3, strategy="update")
        self.assertIsNotNone(rec.evicted_key_digest)
        self.assertFalse(ca.get("a", seq=4, loader=lambda k: None).hit)
        self.assertTrue(ca.get("b", seq=5).hit)
        self.assertTrue(ca.get("c", seq=6).hit)
        # same call sequence, second instance: same victim
        ca2 = CacheAside(capacity=2)
        ca2.set("a", 1, seq=1, strategy="update")
        ca2.set("b", 2, seq=2, strategy="update")
        rec2 = ca2.set("c", 3, seq=3, strategy="update")
        self.assertEqual(rec.evicted_key_digest, rec2.evicted_key_digest)

    def test_bad_capacity(self):
        with self.assertRaises(BadCapacityError):
            CacheAside(capacity=0)
        with self.assertRaises(BadCapacityError):
            CacheAside(capacity=True)
        with self.assertRaises(BadCapacityError):
            CacheAside(capacity=1_000_001)


class TestSeqDiscipline(unittest.TestCase):
    def test_rewind_refused(self):
        ca = CacheAside()
        ca.get("k", seq=5)
        with self.assertRaises(SeqOrderError):
            ca.get("k", seq=5)
        with self.assertRaises(SeqOrderError):
            ca.get("k", seq=3)

    def test_bool_and_negative_seq_refused(self):
        ca = CacheAside()
        with self.assertRaises(SeqOrderError):
            ca.get("k", seq=True)
        with self.assertRaises(SeqOrderError):
            ca.set("k", "v", seq=-1)

    def test_stats_is_read_view(self):
        ca = CacheAside()
        ca.set("k", "v", seq=1, strategy="update")
        st1 = ca.stats(seq=2)
        st2 = ca.stats(seq=2)  # same seq: not consumed
        self.assertTrue(st1.verify())
        self.assertTrue(st2.verify())
        self.assertEqual(st1.hits, st2.hits)


class TestBadInputs(unittest.TestCase):
    def test_bad_keys(self):
        ca = CacheAside()
        for bad in ("", 123, None, True, "x" * 5000):
            with self.assertRaises(BadKeyError, msg=repr(bad)):
                ca.get(bad, seq=1)

    def test_none_value_refused(self):
        ca = CacheAside()
        with self.assertRaises(BadValueError):
            ca.set("k", None, seq=1)

    def test_unsafe_int_value_refused(self):
        ca = CacheAside()
        with self.assertRaises(BadValueError):
            ca.set("k", 2**60, seq=1)

    def test_nonfinite_float_refused(self):
        ca = CacheAside()
        with self.assertRaises(BadValueError):
            ca.set("k", float("nan"), seq=1)

    def test_bad_ttl(self):
        ca = CacheAside()
        with self.assertRaises(BadTTLError):
            ca.set("k", "v", seq=1, ttl=-1)
        with self.assertRaises(BadTTLError):
            ca.set("k", "v", seq=1, ttl=True)
        with self.assertRaises(BadTTLError):
            CacheAside(default_ttl=-5)

    def test_noncallable_backends_refused(self):
        ca = CacheAside()
        with self.assertRaises(BadBackendError):
            ca.get("k", seq=1, loader="nope")
        with self.assertRaises(BadBackendError):
            ca.set("k", "v", seq=1, writer=42)

    def test_value_types_roundtrip(self):
        ca = CacheAside()
        values = ["s", 42, 3.5, True, b"bytes", [1, "a"], {"x": 1}]
        for i, v in enumerate(values):
            ca.set(f"k{i}", v, seq=i + 1, strategy="update")
        for i, v in enumerate(values):
            self.assertEqual(ca.get(f"k{i}", seq=100 + i).value, v)


class TestAudit(unittest.TestCase):
    def test_audit_shapes(self):
        ca = CacheAside()
        ca.set("k", "v", seq=1, strategy="update")
        ca.get("k", seq=2)
        ca.invalidate("k", seq=3)
        ca.expire(seq=4)
        log = ca.audit_log()
        kinds = [e["kind"] for e in log]
        self.assertIn("cache-aside.set", kinds)
        self.assertIn("cache-aside.got", kinds)
        self.assertIn("cache-aside.invalidated", kinds)
        self.assertIn("cache-aside.expired", kinds)
        for e in log:
            self.assertEqual(e["schema"], AUDIT_SCHEMA)
            self.assertEqual(e["module"], CACHE_ASIDE_VERSION)

    def test_raw_keys_values_banned(self):
        with self.assertRaises(CacheAsideError):
            cache_aside_audit_event("got", 1, key="raw")
        with self.assertRaises(CacheAsideError):
            cache_aside_audit_event("set", 1, value="raw")
        with self.assertRaises(AuditKindError):
            cache_aside_audit_event("bogus", 1)

    def test_stats_and_counters(self):
        ca = CacheAside()
        ca.set("a", 1, seq=1, strategy="update")
        ca.get("a", seq=2)
        ca.get("missing", seq=3, loader=lambda k: None)
        ca.invalidate("a", seq=4)
        st = ca.stats(seq=5)
        self.assertEqual(st.hits, 1)
        self.assertEqual(st.misses, 1)
        self.assertEqual(st.sets, 1)
        self.assertEqual(st.invalidations, 1)
        self.assertEqual(st.size, 0)
        self.assertEqual(st.capacity, 1000)


class TestCrossInstanceDeterminism(unittest.TestCase):
    def test_digests_match_across_instances(self):
        def build():
            c = CacheAside()
            c.set("k", "v", seq=1, strategy="update")
            return c.get("k", seq=2)

        self.assertEqual(build().digest, build().digest)


class TestConcurrency(unittest.TestCase):
    def test_threads_smoke(self):
        import threading

        ca = CacheAside(capacity=1000)
        errs = []
        counter = [0]
        clock = threading.Lock()

        def worker(n):
            try:
                for i in range(20):
                    with clock:
                        counter[0] += 1
                        s = counter[0]
                    ca.set(f"w{n}-{i}", i, seq=s, strategy="update")
                    with clock:
                        counter[0] += 1
                        s2 = counter[0]
                    ca.get(f"w{n}-{i}", seq=s2)
            except Exception as e:  # noqa: BLE001
                errs.append(e)

        threads = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errs, [])


class TestMain(unittest.TestCase):
    def test_main(self):
        main()

    def test_main_subprocess(self):
        mod = Path(__file__).resolve().parent.parent / "cache_aside.py"
        out = subprocess.run(
            [sys.executable, str(mod)], capture_output=True, text=True, check=True
        )
        self.assertIn("cache-aside OK", out.stdout)


class TestStdlibOnly(unittest.TestCase):
    def test_stdlib_only(self):
        import ast

        module_path = (
            Path(__file__).resolve().parent.parent / "cache_aside.py"
        )
        tree = ast.parse(module_path.read_text())
        allowed = {
            "__future__", "hashlib", "base64", "threading", "dataclasses",
            "typing", "builtins", "canonical_json", "json",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], allowed, a.name)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn(
                    (node.module or "").split(".")[0], allowed, node.module
                )


if __name__ == "__main__":
    unittest.main()
