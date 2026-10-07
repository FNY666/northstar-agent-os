"""Targeted tests for pubsub_broker."""

import unittest

from pubsub_broker import (
    PUBSUB_BROKER_VERSION,
    SCHEMA_PIN,
    Delivery,
    DuplicateSubscriberError,
    PayloadError,
    PubSubBroker,
    PubSubError,
    PublishReport,
    Subscription,
    TopicError,
    UnknownSubscriberError,
    pubsub_broker_audit_event,
)


class VersionPinTest(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(PUBSUB_BROKER_VERSION, "pubsub-broker.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.pubsub-broker.v1")


class SubscribeTest(unittest.TestCase):
    def test_subscribe_happy_path(self):
        b = PubSubBroker()
        sub = b.subscribe("s1", "events/cpu", 1)
        self.assertIsInstance(sub, Subscription)
        self.assertEqual(sub.subscriber_id, "s1")
        self.assertEqual(sub.pattern, "events/cpu")

    def test_subscribe_wildcards(self):
        b = PubSubBroker()
        b.subscribe("s1", "events/#", 1)
        b.subscribe("s2", "events/+/cpu", 2)
        self.assertEqual(len(b.subscribers()), 2)

    def test_subscribe_duplicate_pattern_rejected(self):
        b = PubSubBroker()
        b.subscribe("s1", "events/cpu", 1)
        with self.assertRaises(DuplicateSubscriberError):
            b.subscribe("s1", "events/cpu", 2)

    def test_subscribe_bad_pattern_rejected(self):
        b = PubSubBroker()
        for bad in ("", "a/#/b", "a/++", "a//b", "a/b#"):
            with self.assertRaises(PubSubError, msg=bad):
                b.subscribe("s1", bad, 1)

    def test_subscribe_bad_id_rejected(self):
        b = PubSubBroker()
        with self.assertRaises(PubSubError):
            b.subscribe("", "a/b", 1)
        with self.assertRaises(PubSubError):
            b.subscribe(123, "a/b", 1)

    def test_subscribe_bad_seq_rejected(self):
        b = PubSubBroker()
        with self.assertRaises(PubSubError):
            b.subscribe("s1", "a/b", -1)
        with self.assertRaises(PubSubError):
            b.subscribe("s1", "a/b", True)


class PublishTest(unittest.TestCase):
    def test_publish_exact_match(self):
        b = PubSubBroker()
        b.subscribe("s1", "events/cpu", 1)
        report = b.publish("events/cpu", {"load": 0.5}, 2)
        self.assertIsInstance(report, PublishReport)
        self.assertEqual(report.delivered_count, 1)

    def test_publish_no_match_is_noop(self):
        b = PubSubBroker()
        b.subscribe("s1", "events/cpu", 1)
        report = b.publish("events/mem", 1, 2)
        self.assertEqual(report.delivered_count, 0)

    def test_hash_wildcard(self):
        b = PubSubBroker()
        b.subscribe("s1", "events/#", 1)
        for topic in ("events", "events/cpu", "events/a/b/c"):
            report = b.publish(topic, "x", 2)
            self.assertEqual(report.delivered_count, 1, topic)

    def test_plus_wildcard_single_level(self):
        b = PubSubBroker()
        b.subscribe("s1", "events/+/cpu", 1)
        self.assertEqual(b.publish("events/h1/cpu", "x", 2).delivered_count, 1)
        self.assertEqual(b.publish("events/h1/mem", "x", 3).delivered_count, 0)
        self.assertEqual(b.publish("events/h1/x/cpu", "x", 4).delivered_count, 0)

    def test_fanout_to_multiple(self):
        b = PubSubBroker()
        b.subscribe("s1", "events/#", 1)
        b.subscribe("s2", "events/cpu", 2)
        report = b.publish("events/cpu", "x", 3)
        self.assertEqual(report.delivered_count, 2)
        ids = [d.subscriber_id for d in report.deliveries]
        self.assertEqual(ids, ["s1", "s2"])  # deterministic order

    def test_delivery_pins_payload(self):
        b = PubSubBroker()
        b.subscribe("s1", "a/b", 1)
        report = b.publish("a/b", {"k": "v"}, 2)
        d = report.deliveries[0]
        self.assertIsInstance(d, Delivery)
        self.assertTrue(d.payload_digest.startswith("sha256:"))
        self.assertTrue(d.digest.startswith("sha256:"))
        # Same payload -> same pin
        report2 = b.publish("a/b", {"k": "v"}, 3)
        self.assertEqual(report2.deliveries[0].payload_digest, d.payload_digest)

    def test_publish_bad_topic_rejected(self):
        b = PubSubBroker()
        with self.assertRaises(TopicError):
            b.publish("a//b", "x", 1)
        with self.assertRaises(TopicError):
            b.publish("a/+/b", "x", 1)
        with self.assertRaises(PubSubError):
            b.publish("", "x", 1)

    def test_publish_bad_payload_rejected(self):
        b = PubSubBroker()
        b.subscribe("s1", "a/b", 1)
        with self.assertRaises(PayloadError):
            b.publish("a/b", object(), 2)
        with self.assertRaises(PayloadError):
            b.publish("a/b", float("nan"), 2)
        with self.assertRaises(PayloadError):
            b.publish("a/b", {1: "x"}, 2)

    def test_publish_bool_distinct_from_int(self):
        b = PubSubBroker()
        b.subscribe("s1", "a/b", 1)
        r1 = b.publish("a/b", True, 2)
        r2 = b.publish("a/b", 1, 3)
        self.assertNotEqual(r1.deliveries[0].payload_digest, r2.deliveries[0].payload_digest)


class UnsubscribeTest(unittest.TestCase):
    def test_unsubscribe_one_pattern(self):
        b = PubSubBroker()
        b.subscribe("s1", "a/b", 1)
        b.subscribe("s1", "c/d", 2)
        removed = b.unsubscribe("s1", "a/b", 3)
        self.assertEqual(removed, 1)
        self.assertEqual(b.publish("a/b", "x", 4).delivered_count, 0)
        self.assertEqual(b.publish("c/d", "x", 5).delivered_count, 1)

    def test_unsubscribe_all(self):
        b = PubSubBroker()
        b.subscribe("s1", "a/b", 1)
        b.subscribe("s1", "c/d", 2)
        removed = b.unsubscribe("s1", None, 3)
        self.assertEqual(removed, 2)
        self.assertEqual(b.subscribers(), ())

    def test_unsubscribe_unknown_subscriber(self):
        b = PubSubBroker()
        with self.assertRaises(UnknownSubscriberError):
            b.unsubscribe("ghost", "a/b", 1)

    def test_unsubscribe_unknown_pattern(self):
        b = PubSubBroker()
        b.subscribe("s1", "a/b", 1)
        with self.assertRaises(PubSubError):
            b.unsubscribe("s1", "x/y", 2)


class ViewsTest(unittest.TestCase):
    def test_subscribers_sorted(self):
        b = PubSubBroker()
        b.subscribe("zeta", "a/b", 1)
        b.subscribe("alpha", "a/b", 2)
        self.assertEqual(b.subscribers(), ("alpha", "zeta"))

    def test_subscriptions_view(self):
        b = PubSubBroker()
        b.subscribe("s1", "a/b", 1)
        b.subscribe("s1", "c/#", 2)
        subs = b.subscriptions("s1")
        self.assertEqual([s.pattern for s in subs], ["a/b", "c/#"])

    def test_subscriptions_unknown(self):
        b = PubSubBroker()
        with self.assertRaises(UnknownSubscriberError):
            b.subscriptions("ghost")

    def test_published_count(self):
        b = PubSubBroker()
        b.publish("a/b", "x", 1)
        b.publish("a/b", "y", 2)
        self.assertEqual(b.published_count(), 2)

    def test_subscription_as_dict(self):
        b = PubSubBroker()
        sub = b.subscribe("s1", "a/b", 1)
        d = sub.as_dict()
        self.assertEqual(d["pattern"], "a/b")
        self.assertEqual(d["version"], "pubsub-broker.v1")

    def test_report_as_dict(self):
        b = PubSubBroker()
        b.subscribe("s1", "a/b", 1)
        report = b.publish("a/b", "x", 2)
        d = report.as_dict()
        self.assertEqual(d["delivered_count"], 1)
        self.assertEqual(d["topic"], "a/b")


class AuditTest(unittest.TestCase):
    def test_audit_shapes(self):
        for kind in ("subscribed", "unsubscribed", "published", "rejected"):
            event = pubsub_broker_audit_event(kind, 7, topic="a/b")
            self.assertEqual(event["kind"], f"pubsub-broker.{kind}")
            self.assertEqual(event["seq"], 7)
            self.assertEqual(event["schema"], "northstar.pubsub-broker.v1")

    def test_audit_rejects_unknown_kind(self):
        with self.assertRaises(PubSubError):
            pubsub_broker_audit_event("bogus", 1)

    def test_audit_never_carries_raw_payload(self):
        event = pubsub_broker_audit_event("published", 1, payload_digest="sha256:abc")
        self.assertNotIn("payload", event)


class MainTest(unittest.TestCase):
    def test_main(self):
        import pubsub_broker as m

        m.main()  # asserts internally


if __name__ == "__main__":
    unittest.main()
