"""Tests for config_management.py."""

import sys
import unittest

sys.path.insert(0, "..")

from config_management import (
    AUDIT_SCHEMA,
    CONFIG_MANAGEMENT_SCHEMA,
    CONFIG_MANAGEMENT_VERSION,
    MAX_VALUE_BYTES,
    ConfigManagement,
    AuditKindError,
    BadKeyError,
    BadLeaseError,
    BadOpError,
    BadSessionError,
    BadValueError,
    CasMismatchError,
    DuplicateLeaseError,
    ExpiredLeaseError,
    LockHeldError,
    LockNotHeldError,
    SeqOrderError,
    UnknownKeyError,
    UnknownLeaseError,
    UnknownSessionError,
    UnknownWatcherError,
    CancelledWatcherError,
    config_management_audit_event,
    main,
)


def fresh():
    return ConfigManagement()


class TestPins(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(CONFIG_MANAGEMENT_VERSION, "config-management.v1")
        self.assertEqual(CONFIG_MANAGEMENT_SCHEMA, "northstar.config-management.v1")

    def test_stdlib_only(self):
        import config_management

        self.assertTrue(config_management._stdlib_only(config_management.__file__))

    def test_main(self):
        main()


class TestSetGet(unittest.TestCase):
    def test_set_get_roundtrip(self):
        cm = fresh()
        rec = cm.set("app/db/host", "db1", 1)
        self.assertTrue(rec.verify())
        self.assertEqual(rec.version, 1)
        got = cm.get("app/db/host", 1)
        self.assertEqual(got.value, "db1")
        self.assertEqual(got.version, 1)

    def test_set_versions_increase(self):
        cm = fresh()
        a = cm.set("k", "v1", 1)
        b = cm.set("k", "v2", 2)
        self.assertEqual(b.version, a.version + 1)
        self.assertTrue(b.verify())

    def test_get_is_read_view(self):
        cm = fresh()
        cm.set("k", "v", 5)
        cm.get("k", 1)  # smaller seq OK on read view (shape validated, not consumed)
        with self.assertRaises(UnknownKeyError):
            cm.get("missing", 1)

    def test_bad_keys(self):
        cm = fresh()
        for bad in ("", "  k", "k ", "a//b", "a/../b", "a\x00b", "k" * 600):
            with self.assertRaises(BadKeyError, msg=repr(bad)):
                cm.set(bad, "v", 1 if bad == "" else 10)

    def test_bad_values(self):
        cm = fresh()
        with self.assertRaises(BadValueError):
            cm.set("k", 123, 1)
        with self.assertRaises(BadValueError):
            cm.set("k", "x" * (MAX_VALUE_BYTES + 1), 2)
        with self.assertRaises(BadValueError):
            cm.set("k", b"y" * (MAX_VALUE_BYTES + 1), 3)
        # bytes values are fine
        rec = cm.set("bin", b"\x00\x01", 4)
        self.assertTrue(rec.verify())


class TestDeletePrefix(unittest.TestCase):
    def test_delete_and_prefix(self):
        cm = fresh()
        cm.set("app/a", "1", 1)
        cm.set("app/b", "2", 2)
        cm.set("other", "3", 3)
        tombs = cm.delete_prefix("app", 4)
        self.assertEqual(len(tombs), 2)
        self.assertTrue(all(t.verify() for t in tombs))
        with self.assertRaises(UnknownKeyError):
            cm.get("app/a", 4)
        self.assertEqual(cm.get("other", 4).value, "3")
        kinds = [e["kind"] for e in cm.audit_log()]
        self.assertIn("transaction-applied", kinds)

    def test_prefix_view(self):
        cm = fresh()
        cm.set("app/a", "1", 1)
        cm.set("app/sub/b", "2", 2)
        cm.set("other", "3", 3)
        got = cm.prefix("app", 3)
        self.assertEqual([r.key for r in got], ["app/a", "app/sub/b"])

    def test_delete_unknown_refused(self):
        cm = fresh()
        with self.assertRaises(UnknownKeyError):
            cm.delete("nope", 1)


class TestCas(unittest.TestCase):
    def test_cas_happy(self):
        cm = fresh()
        r1 = cm.set("k", "v1", 1)
        r2 = cm.cas("k", r1.version, "v2", 2)
        self.assertEqual(r2.value, "v2")
        self.assertTrue(r2.verify())

    def test_cas_mismatch(self):
        cm = fresh()
        cm.set("k", "v1", 1)
        with self.assertRaises(CasMismatchError):
            cm.cas("k", 99, "v2", 2)
        # failed mutation consumed its seq
        with self.assertRaises(SeqOrderError):
            cm.set("k2", "x", 2)


class TestLease(unittest.TestCase):
    def test_grant_attach_revoke(self):
        cm = fresh()
        cm.set("k", "v", 1)
        lease = cm.grant("l-1", 10, 2)
        self.assertTrue(lease.verify())
        self.assertEqual(lease.expiry_seq, 12)
        attached = cm.attach("k", "l-1", 3)
        self.assertEqual(attached.lease_id, "l-1")
        tombs = cm.revoke("l-1", 4)
        self.assertEqual(len(tombs), 1)
        with self.assertRaises(UnknownKeyError):
            cm.get("k", 4)

    def test_lease_expiry_sweep(self):
        cm = fresh()
        cm.set("k", "v", 1)
        cm.grant("l-1", 3, 2)  # expiry at 5
        cm.attach("k", "l-1", 3)
        tombs = cm.expire(6)
        self.assertEqual(len(tombs), 1)
        with self.assertRaises(UnknownKeyError):
            cm.get("k", 6)

    def test_expired_lease_attach_refused(self):
        cm = fresh()
        cm.set("k", "v", 1)
        cm.grant("l-1", 2, 2)  # expiry at 4
        with self.assertRaises(ExpiredLeaseError):
            cm.attach("k", "l-1", 5)

    def test_bad_lease_inputs(self):
        cm = fresh()
        with self.assertRaises(BadLeaseError):
            cm.grant("", 5, 1)
        with self.assertRaises(BadLeaseError):
            cm.grant("l", 0, 2)
        cm.grant("l", 5, 3)
        with self.assertRaises(DuplicateLeaseError):
            cm.grant("l", 5, 4)


class TestWatch(unittest.TestCase):
    def test_watch_poll(self):
        cm = fresh()
        w = cm.watch("app", 1)
        cm.set("app/a", "1", 2)
        cm.set("other", "9", 3)
        page = cm.poll(w.watcher_id, 4)
        self.assertTrue(page.verify())
        self.assertEqual(len(page.events), 1)
        self.assertEqual(page.events[0].key, "app/a")
        # cursor advanced: second poll is empty
        page2 = cm.poll(w.watcher_id, 5)
        self.assertEqual(len(page2.events), 0)

    def test_cancel_watch(self):
        cm = fresh()
        w = cm.watch("app", 1)
        cm.cancel_watch(w.watcher_id, 2)
        with self.assertRaises(CancelledWatcherError):
            cm.poll(w.watcher_id, 3)
        with self.assertRaises(UnknownWatcherError):
            cm.poll("w-99", 3)


class TestSessionLock(unittest.TestCase):
    def test_lock_cycle(self):
        cm = fresh()
        cm.session("s-1", 1)
        lock = cm.lock("app/deploy", "s-1", 2)
        self.assertTrue(lock.verify() and lock.held)
        with self.assertRaises(LockHeldError):
            cm.lock("app/deploy", "s-1", 3)  # reentrant refused
        cm.session("s-2", 4)
        with self.assertRaises(LockHeldError):
            cm.lock("app/deploy", "s-2", 5)
        cm.unlock("app/deploy", "s-1", 6)
        cm.lock("app/deploy", "s-2", 7)  # now free

    def test_destroy_session_releases_locks(self):
        cm = fresh()
        cm.session("s-1", 1)
        cm.lock("k", "s-1", 2)
        cm.destroy_session("s-1", 3)
        with self.assertRaises(UnknownSessionError):
            cm.lock("k", "s-1", 4)
        cm.session("s-2", 5)
        cm.lock("k", "s-2", 6)  # released on destroy

    def test_unlock_not_held(self):
        cm = fresh()
        cm.session("s-1", 1)
        with self.assertRaises(LockNotHeldError):
            cm.unlock("k", "s-1", 2)


class TestTransaction(unittest.TestCase):
    def test_transaction_atomic(self):
        cm = fresh()
        cm.set("a", "1", 1)
        tx = cm.transaction([("set", "b", "2"), ("delete", "a")], 2)
        self.assertTrue(tx.verify())
        self.assertEqual(cm.get("b", 2).value, "2")
        with self.assertRaises(UnknownKeyError):
            cm.get("a", 2)

    def test_transaction_aborts_on_bad_op(self):
        cm = fresh()
        cm.set("a", "1", 1)
        with self.assertRaises(UnknownKeyError):
            cm.transaction([("set", "b", "2"), ("delete", "missing")], 2)
        # nothing applied
        with self.assertRaises(UnknownKeyError):
            cm.get("b", 2)
        self.assertEqual(cm.get("a", 2).value, "1")

    def test_transaction_bad_kind(self):
        cm = fresh()
        with self.assertRaises(BadOpError):
            cm.transaction([("frobnicate", "a")], 1)
        with self.assertRaises(BadOpError):
            cm.transaction([], 2)


class TestSeqDiscipline(unittest.TestCase):
    def test_rewind_refused(self):
        cm = fresh()
        cm.set("a", "1", 5)
        with self.assertRaises(SeqOrderError):
            cm.set("b", "2", 5)
        with self.assertRaises(SeqOrderError):
            cm.set("b", "2", 3)

    def test_bool_seq_refused(self):
        cm = fresh()
        with self.assertRaises(SeqOrderError):
            cm.set("a", "1", True)

    def test_failed_mutation_consumes_seq(self):
        cm = fresh()
        with self.assertRaises(BadKeyError):
            cm.set("", "v", 1)
        with self.assertRaises(SeqOrderError):
            cm.set("a", "v", 1)


class TestAudit(unittest.TestCase):
    def test_audit_shapes_and_kinds(self):
        cm = fresh()
        cm.set("k", "secret-value", 1)
        log = cm.audit_log()
        entry = [e for e in log if e["kind"] == "entry-set"][0]
        self.assertEqual(entry["schema"], AUDIT_SCHEMA)
        self.assertEqual(entry["key"], "k")
        # raw value never crosses the audit boundary
        self.assertNotIn("secret-value", str(log))
        self.assertIn("value=sha256:", entry["detail"])

    def test_bad_kind(self):
        with self.assertRaises(AuditKindError):
            config_management_audit_event("nope", 1)

    def test_rejected_audited(self):
        cm = fresh()
        with self.assertRaises(BadKeyError):
            cm.set("", "v", 1)
        self.assertEqual(cm.audit_log()[-1]["kind"], "rejected")


class TestViews(unittest.TestCase):
    def test_key_ids_stats(self):
        cm = fresh()
        cm.set("b", "1", 1)
        cm.set("a", "2", 2)
        self.assertEqual(cm.key_ids(), ("a", "b"))
        stats = cm.stats()
        self.assertEqual(stats["keys"], 2)
        self.assertIn("leases", stats)
        self.assertIn("watchers", stats)


class TestConcurrency(unittest.TestCase):
    def test_threads(self):
        import threading

        cm = fresh()
        errors = []

        def worker(i):
            try:
                cm.set(f"k-{i}", "v", i + 1)
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertFalse(errors, errors)


if __name__ == "__main__":
    unittest.main()
