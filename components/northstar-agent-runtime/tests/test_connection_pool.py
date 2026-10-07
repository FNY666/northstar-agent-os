"""Targeted tests for connection_pool."""

import threading
import unittest

from connection_pool import (
    CONNECTION_POOL_VERSION,
    SCHEMA_PIN,
    ConnectionHandle,
    ConnectionPool,
    ConnectionPoolError,
    EvictionReport,
    NotBorrowedError,
    PoolConfigError,
    PoolExhaustedError,
    PoolStats,
    UnknownConnectionError,
    connection_pool_audit_event,
)


class TestVersionPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(CONNECTION_POOL_VERSION, "connection-pool.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.connection-pool.v1")


class TestConfig(unittest.TestCase):
    def test_rejects_zero_size(self):
        with self.assertRaises(PoolConfigError):
            ConnectionPool(0)

    def test_rejects_negative_size(self):
        with self.assertRaises(PoolConfigError):
            ConnectionPool(-3)

    def test_rejects_bool_size(self):
        with self.assertRaises(PoolConfigError):
            ConnectionPool(True)


class TestAcquire(unittest.TestCase):
    def test_acquire_returns_handle(self):
        pool = ConnectionPool(2)
        h = pool.acquire(0)
        self.assertIsInstance(h, ConnectionHandle)
        self.assertTrue(pool.is_borrowed(h.conn_id))
        self.assertEqual(h.version, CONNECTION_POOL_VERSION)

    def test_acquire_mints_distinct_ids(self):
        pool = ConnectionPool(3)
        ids = [pool.acquire(i).conn_id for i in range(3)]
        self.assertEqual(len(set(ids)), 3)

    def test_acquire_zero_seq_ok(self):
        pool = ConnectionPool(1)
        h = pool.acquire(0)
        self.assertTrue(pool.is_borrowed(h.conn_id))

    def test_exhausted_raises(self):
        pool = ConnectionPool(1)
        pool.acquire(1)
        with self.assertRaises(PoolExhaustedError):
            pool.acquire(2)
        self.assertEqual(pool.stats().exhausted_total, 1)

    def test_bad_seq_rejected(self):
        pool = ConnectionPool(1)
        for bad in (-1, True, "x", None):
            with self.assertRaises(ConnectionPoolError):
                pool.acquire(bad)


class TestRelease(unittest.TestCase):
    def test_release_returns_to_idle(self):
        pool = ConnectionPool(1)
        h = pool.acquire(1)
        pool.release(h.conn_id, 2)
        self.assertFalse(pool.is_borrowed(h.conn_id))
        self.assertTrue(pool.is_idle(h.conn_id))
        self.assertEqual(pool.stats().released_total, 1)

    def test_reused_on_reacquire(self):
        pool = ConnectionPool(1)
        h = pool.acquire(1)
        pool.release(h.conn_id, 2)
        h2 = pool.acquire(3)
        self.assertEqual(h2.conn_id, h.conn_id, "idle handle must be reused")
        self.assertEqual(pool.stats().created, 1, "no new handle should be minted")

    def test_release_unknown_raises(self):
        pool = ConnectionPool(1)
        with self.assertRaises(UnknownConnectionError):
            pool.release("conn-999", 1)

    def test_double_release_raises(self):
        pool = ConnectionPool(1)
        h = pool.acquire(1)
        pool.release(h.conn_id, 2)
        with self.assertRaises(NotBorrowedError):
            pool.release(h.conn_id, 3)

    def test_bad_conn_id_rejected(self):
        pool = ConnectionPool(1)
        for bad in ("", None, 42):
            with self.assertRaises(ConnectionPoolError):
                pool.release(bad, 1)


class TestInvalidate(unittest.TestCase):
    def test_invalidate_drops_handle(self):
        pool = ConnectionPool(2)
        h = pool.acquire(1)
        pool.invalidate(h.conn_id, 2)
        self.assertFalse(pool.is_borrowed(h.conn_id))
        self.assertFalse(pool.is_idle(h.conn_id))
        # Invalidated handles never return to idle: next acquire mints a new id.
        h2 = pool.acquire(3)
        self.assertNotEqual(h2.conn_id, h.conn_id)
        self.assertEqual(pool.stats().invalidated_total, 1)

    def test_invalidate_idle_raises(self):
        pool = ConnectionPool(1)
        h = pool.acquire(1)
        pool.release(h.conn_id, 2)
        with self.assertRaises(NotBorrowedError):
            pool.invalidate(h.conn_id, 3)

    def test_invalidate_unknown_raises(self):
        pool = ConnectionPool(1)
        with self.assertRaises(UnknownConnectionError):
            pool.invalidate("nope", 1)


class TestEvictIdle(unittest.TestCase):
    def test_evicts_only_stale(self):
        pool = ConnectionPool(3)
        a = pool.acquire(1)
        b = pool.acquire(2)
        pool.release(a.conn_id, 10)
        pool.release(b.conn_id, 20)
        report = pool.evict_idle(idle_before_seq=15, seq=30)
        self.assertIsInstance(report, EvictionReport)
        self.assertEqual(report.evicted, (a.conn_id,))
        self.assertEqual(report.remaining_idle, 1)
        self.assertTrue(pool.is_idle(b.conn_id))
        self.assertFalse(pool.is_idle(a.conn_id))
        self.assertEqual(pool.stats().evicted_total, 1)

    def test_evict_never_touches_borrowed(self):
        pool = ConnectionPool(2)
        h = pool.acquire(1)
        report = pool.evict_idle(idle_before_seq=10**9, seq=2)
        self.assertEqual(report.evicted, ())
        self.assertTrue(pool.is_borrowed(h.conn_id))

    def test_evict_empty_is_valid_noop(self):
        pool = ConnectionPool(1)
        report = pool.evict_idle(idle_before_seq=100, seq=1)
        self.assertEqual(report.evicted, ())
        self.assertEqual(report.remaining_idle, 0)

    def test_bad_cutoff_rejected(self):
        pool = ConnectionPool(1)
        with self.assertRaises(ConnectionPoolError):
            pool.evict_idle(-1, 1)


class TestAuditAndRecords(unittest.TestCase):
    def test_audit_shapes(self):
        for kind in ("acquired", "released", "evicted", "invalidated", "rejected"):
            rec = connection_pool_audit_event(kind, 5, conn_id="conn-1")
            self.assertEqual(rec["event"], "connection-pool")
            self.assertEqual(rec["kind"], kind)
            self.assertEqual(rec["audit_seq"], 5)

    def test_audit_unknown_kind_rejected(self):
        with self.assertRaises(ConnectionPoolError):
            connection_pool_audit_event("nope", 1)

    def test_audit_bad_seq_rejected(self):
        with self.assertRaises(ConnectionPoolError):
            connection_pool_audit_event("acquired", -1)

    def test_stats_shape(self):
        pool = ConnectionPool(4)
        h = pool.acquire(1)
        pool.release(h.conn_id, 2)
        s = pool.stats()
        self.assertIsInstance(s, PoolStats)
        d = s.as_dict()
        self.assertEqual(d["max_size"], 4)
        self.assertEqual(d["borrowed"], 0)
        self.assertEqual(d["idle"], 1)

    def test_handle_as_dict(self):
        pool = ConnectionPool(1)
        h = pool.acquire(1)
        d = h.as_dict()
        self.assertIn("digest", d)
        self.assertTrue(d["digest"].startswith("sha256:"))


class TestConcurrency(unittest.TestCase):
    def test_threads_acquire_release(self):
        pool = ConnectionPool(4)
        errors: list[Exception] = []

        def worker(n: int) -> None:
            try:
                for i in range(25):
                    h = pool.acquire(i)
                    pool.release(h.conn_id, i)
            except Exception as e:  # pragma: no cover - diagnostic
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        s = pool.stats()
        self.assertEqual(s.borrowed, 0)
        self.assertEqual(s.acquired_total, s.released_total)


class TestMain(unittest.TestCase):
    def test_main(self):
        from connection_pool import main

        main()  # must not raise


if __name__ == "__main__":
    unittest.main()
