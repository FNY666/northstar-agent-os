"""Tests for the notification_hub module."""

from __future__ import annotations

import threading
import unittest
from dataclasses import FrozenInstanceError

from notification_hub import (
    AUDIT_SCHEMA,
    CATEGORY_ALL,
    CHANNEL_EMAIL,
    CHANNEL_SMS,
    KIND_DIGESTED,
    KIND_NOTIFIED,
    MODE_DIGEST,
    MODE_IMMEDIATE,
    MODE_MUTED,
    NOTIFICATION_HUB_SCHEMA,
    NOTIFICATION_HUB_VERSION,
    PRIORITY_URGENT,
    STATUS_BUFFERED,
    STATUS_DROPPED_MUTED,
    STATUS_QUEUED,
    BadPreferenceError,
    DeliveryAttempt,
    DeliveryReport,
    DigestItem,
    DigestReport,
    DuplicateChannelError,
    DuplicateSubscriptionError,
    NoRouteError,
    NotificationHub,
    NotificationHubError,
    PreferenceRecord,
    UnknownChannelError,
    UnknownSubjectError,
    UnknownSubscriptionError,
    notification_hub_audit_event,
)


def _hub() -> NotificationHub:
    hub = NotificationHub()
    hub.register_channel("email", CHANNEL_EMAIL, 1)
    hub.register_channel("sms", CHANNEL_SMS, 2)
    hub.subscribe("alice", "email", 3)
    return hub


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(NOTIFICATION_HUB_VERSION, "notification-hub.v1")

    def test_schema_pin(self):
        self.assertEqual(NOTIFICATION_HUB_SCHEMA, "northstar.notification-hub.v1")

    def test_audit_schema(self):
        self.assertEqual(AUDIT_SCHEMA, "audit.ndjson/1")

    def test_stdlib_only(self):
        import ast
        from pathlib import Path

        tree = ast.parse(Path("notification_hub.py").read_text())
        allowed = {
            "__future__", "threading", "dataclasses", "typing",
            "hashlib", "json",
            "canonical_json",  # try/except import guard only
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertIn(alias.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed)


class TestChannels(unittest.TestCase):
    def test_register_happy_path(self):
        rec = NotificationHub().register_channel("c1", CHANNEL_EMAIL, 1)
        self.assertEqual(rec.channel_id, "c1")
        self.assertEqual(rec.kind, CHANNEL_EMAIL)
        self.assertTrue(rec.digest.startswith("sha256:"))

    def test_register_duplicate_refused(self):
        hub = NotificationHub()
        hub.register_channel("c1", CHANNEL_EMAIL, 1)
        with self.assertRaises(DuplicateChannelError):
            hub.register_channel("c1", CHANNEL_SMS, 2)

    def test_register_bad_kind_refused(self):
        with self.assertRaises(NotificationHubError):
            NotificationHub().register_channel("c1", "carrier-pigeon", 1)

    def test_register_bool_seq_refused(self):
        with self.assertRaises(NotificationHubError):
            NotificationHub().register_channel("c1", CHANNEL_EMAIL, True)


class TestSubscriptions(unittest.TestCase):
    def test_subscribe_happy_path(self):
        hub = _hub()
        rec = hub.subscribe("alice", "sms", 4, categories=("incidents",))
        self.assertEqual(rec.categories, ("incidents",))

    def test_subscribe_default_category_all(self):
        hub = _hub()
        self.assertEqual(hub.subscriptions("alice")[0].categories, (CATEGORY_ALL,))

    def test_subscribe_unknown_channel(self):
        hub = _hub()
        with self.assertRaises(UnknownChannelError):
            hub.subscribe("alice", "nope", 4)

    def test_subscribe_duplicate_refused(self):
        hub = _hub()
        with self.assertRaises(DuplicateSubscriptionError):
            hub.subscribe("alice", "email", 4)

    def test_unsubscribe_happy_path(self):
        hub = _hub()
        rec = hub.unsubscribe("alice", "email", 4)
        self.assertEqual(rec.channel_id, "email")
        self.assertEqual(hub.subscriptions("alice"), ())

    def test_unsubscribe_unknown_refused(self):
        hub = _hub()
        with self.assertRaises(UnknownSubscriptionError):
            hub.unsubscribe("alice", "sms", 4)


class TestPreferences(unittest.TestCase):
    def test_defaults_immediate(self):
        hub = _hub()
        prefs = hub.preferences("alice")
        self.assertEqual(prefs.mode, MODE_IMMEDIATE)
        self.assertIsNone(prefs.muted_until_seq)
        self.assertTrue(prefs.urgent_bypass)

    def test_set_preferences_happy_path(self):
        hub = _hub()
        prefs = hub.set_preferences("alice", 4, mode=MODE_DIGEST, digest_every_seqs=50)
        self.assertIsInstance(prefs, PreferenceRecord)
        self.assertEqual(prefs.mode, MODE_DIGEST)
        self.assertEqual(prefs.digest_every_seqs, 50)
        self.assertTrue(prefs.digest.startswith("sha256:"))

    def test_set_preferences_unknown_subject(self):
        hub = _hub()
        with self.assertRaises(UnknownSubjectError):
            hub.set_preferences("mallory", 4)

    def test_set_preferences_bad_mode(self):
        hub = _hub()
        with self.assertRaises(BadPreferenceError):
            hub.set_preferences("alice", 4, mode="carrier-pigeon")

    def test_set_preferences_past_mute_refused(self):
        hub = _hub()
        with self.assertRaises(BadPreferenceError):
            hub.set_preferences("alice", 10, muted_until_seq=5)

    def test_set_preferences_future_mute_ok(self):
        hub = _hub()
        prefs = hub.set_preferences("alice", 5, muted_until_seq=10)
        self.assertEqual(prefs.muted_until_seq, 10)

    def test_preferences_frozen(self):
        hub = _hub()
        with self.assertRaises(FrozenInstanceError):
            hub.preferences("alice").mode = MODE_MUTED  # type: ignore[misc]


class TestNotify(unittest.TestCase):
    def test_notify_immediate_queued(self):
        hub = _hub()
        report = hub.notify("alice", "anything", "Hello", "world", 4)
        self.assertIsInstance(report, DeliveryReport)
        self.assertEqual(report.notification_id, "ntf-1")
        self.assertEqual(len(report.attempts), 1)
        attempt = report.attempts[0]
        self.assertIsInstance(attempt, DeliveryAttempt)
        self.assertEqual(attempt.status, STATUS_QUEUED)
        self.assertEqual(attempt.channel_kind, CHANNEL_EMAIL)
        self.assertTrue(report.digest.startswith("sha256:"))

    def test_notify_notification_ids_monotonic(self):
        hub = _hub()
        r1 = hub.notify("alice", "a", "t", "b", 4)
        r2 = hub.notify("alice", "a", "t", "b", 5)
        self.assertEqual((r1.notification_id, r2.notification_id), ("ntf-1", "ntf-2"))

    def test_notify_unknown_subject(self):
        hub = _hub()
        with self.assertRaises(UnknownSubjectError):
            hub.notify("mallory", "a", "t", "b", 4)

    def test_notify_no_matching_category_refused_not_dropped(self):
        hub = NotificationHub()
        hub.register_channel("email", CHANNEL_EMAIL, 1)
        hub.subscribe("bob", "email", 2, categories=("incidents",))
        with self.assertRaises(NoRouteError):
            hub.notify("bob", "approvals", "t", "b", 3)

    def test_notify_bad_priority(self):
        hub = _hub()
        with self.assertRaises(NotificationHubError):
            hub.notify("alice", "a", "t", "b", 4, priority="mega-urgent")

    def test_notify_bool_seq_refused(self):
        hub = _hub()
        with self.assertRaises(NotificationHubError):
            hub.notify("alice", "a", "t", "b", True)

    def test_notify_digest_mode_buffers(self):
        hub = _hub()
        hub.set_preferences("alice", 4, mode=MODE_DIGEST)
        report = hub.notify("alice", "a", "t", "b", 5)
        self.assertEqual(report.attempts[0].status, STATUS_BUFFERED)
        self.assertEqual(hub.pending_digest_count("alice"), 1)

    def test_notify_muted_drops_visibly(self):
        hub = _hub()
        hub.set_preferences("alice", 4, mode=MODE_MUTED)
        report = hub.notify("alice", "a", "t", "b", 5)
        attempt = report.attempts[0]
        self.assertEqual(attempt.status, STATUS_DROPPED_MUTED)
        self.assertEqual(attempt.reason, "subject muted")

    def test_notify_muted_until_window(self):
        hub = _hub()
        hub.set_preferences("alice", 4, muted_until_seq=10)
        self.assertEqual(
            hub.notify("alice", "a", "t", "b", 9).attempts[0].status,
            STATUS_DROPPED_MUTED,
        )
        self.assertEqual(
            hub.notify("alice", "a", "t", "b", 11).attempts[0].status,
            STATUS_QUEUED,
        )

    def test_notify_urgent_bypasses_mute(self):
        hub = _hub()
        hub.set_preferences("alice", 4, mode=MODE_MUTED)
        report = hub.notify("alice", "a", "SEV-1", "page", 5, priority=PRIORITY_URGENT)
        self.assertEqual(report.attempts[0].status, STATUS_QUEUED)

    def test_notify_urgent_bypass_disabled(self):
        hub = _hub()
        hub.set_preferences("alice", 4, mode=MODE_MUTED, urgent_bypass=False)
        report = hub.notify("alice", "a", "SEV-1", "page", 5, priority=PRIORITY_URGENT)
        self.assertEqual(report.attempts[0].status, STATUS_DROPPED_MUTED)

    def test_notify_urgent_bypasses_digest(self):
        hub = _hub()
        hub.set_preferences("alice", 4, mode=MODE_DIGEST)
        report = hub.notify("alice", "a", "SEV-1", "page", 5, priority=PRIORITY_URGENT)
        self.assertEqual(report.attempts[0].status, STATUS_QUEUED)
        self.assertEqual(hub.pending_digest_count("alice"), 0)

    def test_notify_category_filtering(self):
        hub = _hub()
        hub.subscribe("alice", "sms", 4, categories=("incidents",))
        report = hub.notify("alice", "incidents", "t", "b", 5)
        self.assertEqual(len(report.attempts), 2)
        kinds = sorted(a.channel_kind for a in report.attempts)
        self.assertEqual(kinds, [CHANNEL_EMAIL, CHANNEL_SMS])


class TestDigest(unittest.TestCase):
    def test_digest_collects_and_clears(self):
        hub = _hub()
        hub.set_preferences("alice", 4, mode=MODE_DIGEST)
        hub.notify("alice", "a", "t1", "b1", 5)
        hub.notify("alice", "b", "t2", "b2", 6)
        digest = hub.digest("alice", 7)
        self.assertIsInstance(digest, DigestReport)
        self.assertEqual(len(digest.items), 2)
        self.assertTrue(all(isinstance(i, DigestItem) for i in digest.items))
        self.assertEqual(digest.items[0].notification_id, "ntf-1")
        self.assertTrue(digest.digest.startswith("sha256:"))
        self.assertEqual(hub.pending_digest_count("alice"), 0)

    def test_digest_empty_is_noop(self):
        hub = _hub()
        digest = hub.digest("alice", 4)
        self.assertEqual(digest.items, ())

    def test_digest_unknown_subject(self):
        hub = _hub()
        with self.assertRaises(UnknownSubjectError):
            hub.digest("mallory", 4)


class TestAudit(unittest.TestCase):
    def test_audit_shapes(self):
        for kind in (KIND_NOTIFIED, KIND_DIGESTED):
            ev = notification_hub_audit_event(kind, 1, subject_id="alice")
            self.assertEqual(ev["schema"], AUDIT_SCHEMA)
            self.assertEqual(ev["kind"], kind)
            self.assertEqual(ev["module"], "notification_hub")
            self.assertEqual(ev["module_version"], NOTIFICATION_HUB_VERSION)

    def test_audit_unknown_kind_rejected(self):
        with self.assertRaises(NotificationHubError):
            notification_hub_audit_event("bogus", 1)

    def test_audit_bad_seq_rejected(self):
        with self.assertRaises(NotificationHubError):
            notification_hub_audit_event(KIND_NOTIFIED, -1)


class TestConcurrency(unittest.TestCase):
    def test_concurrent_notify(self):
        hub = _hub()
        errors = []

        def worker(n: int) -> None:
            try:
                for i in range(10):
                    hub.notify("alice", "a", f"t{n}-{i}", "b", 4 + i)
            except Exception as exc:  # pragma: no cover - fail loudly
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        ids = set()
        # ids are not returned per-thread here; sanity: hub still consistent
        self.assertEqual(hub._next_notification, 80)
        for i in range(1, 81):
            ids.add(f"ntf-{i}")
        self.assertEqual(len(ids), 80)


class TestMain(unittest.TestCase):
    def test_main(self):
        import notification_hub

        notification_hub.main()


if __name__ == "__main__":
    unittest.main()
