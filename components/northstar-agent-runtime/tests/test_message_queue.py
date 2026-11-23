"""Tests for message_queue.py (at-least-once pub/sub queue)."""

import ast
import unittest

from message_queue import (
    MESSAGE_QUEUE_VERSION,
    SCHEMA_PIN,
    AckRecord,
    Delivery,
    DuplicateSubscriberError,
    Message,
    MessageNotPendingError,
    MessageQueue,
    NackRecord,
    PayloadNotCanonicalError,
    Subscription,
    UnknownMessageError,
    UnknownSubscriberError,
    message_queue_audit_event,
)


def _queue_with(topic="t", subscriber="s1"):
    q = MessageQueue()
    q.subscribe(topic, subscriber, seq=0)
    return q


class PinsTest(unittest.TestCase):
    def test_version_pins(self):
        self.assertEqual(MESSAGE_QUEUE_VERSION, "message-queue.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.message-queue.v1")

    def test_schema_pins_on_records(self):
        m = Message(
            message_id="msg-1", topic="t", payload=1,
            payload_digest="sha256:" + "0" * 64, publish_seq=0,
        )
        self.assertEqual(m.schema, SCHEMA_PIN)
        self.assertEqual(m.as_dict()["schema"], SCHEMA_PIN)
        sub = Subscription(topic="t", subscriber_id="s", subscribe_seq=0)
        self.assertEqual(sub.schema, SCHEMA_PIN)


class PublishTest(unittest.TestCase):
    def test_publish_mints_monotonic_ids(self):
        q = MessageQueue()
        m1 = q.publish("t", {"a": 1}, seq=0)
        m2 = q.publish("t", {"a": 2}, seq=1)
        self.assertEqual(m1.message_id, "msg-1")
        self.assertEqual(m2.message_id, "msg-2")
        self.assertEqual(q.published_count("t"), 2)
        self.assertEqual(q.published_count(), 2)

    def test_payload_digest_pinned_and_deterministic(self):
        q = MessageQueue()
        m1 = q.publish("t", {"b": 2, "a": 1}, seq=0)
        m2 = q.publish("t", {"a": 1, "b": 2}, seq=1)
        self.assertTrue(m1.payload_digest.startswith("sha256:"))
        self.assertEqual(m1.payload_digest, m2.payload_digest)

    def test_payload_deep_copied_on_publish(self):
        q = MessageQueue()
        payload = {"items": [1, 2]}
        m = q.publish("t", payload, seq=0)
        payload["items"].append(3)
        self.assertEqual(m.payload, {"items": [1, 2]})
        # digest pins the original content
        q2 = MessageQueue()
        m2 = q2.publish("t", {"items": [1, 2]}, seq=0)
        self.assertEqual(m.payload_digest, m2.payload_digest)

    def test_publish_rejects_empty_topic(self):
        q = MessageQueue()
        with self.assertRaises(TypeError):
            q.publish("", {"a": 1}, seq=0)

    def test_publish_rejects_bad_topic_type(self):
        q = MessageQueue()
        with self.assertRaises(TypeError):
            q.publish(123, {"a": 1}, seq=0)

    def test_publish_rejects_nan_payload(self):
        q = MessageQueue()
        with self.assertRaises(PayloadNotCanonicalError):
            q.publish("t", {"v": float("nan")}, seq=0)

    def test_publish_rejects_non_str_keys(self):
        q = MessageQueue()
        with self.assertRaises(PayloadNotCanonicalError):
            q.publish("t", {1: "x"}, seq=0)

    def test_publish_rejects_bad_seq(self):
        q = MessageQueue()
        with self.assertRaises(TypeError):
            q.publish("t", {"a": 1}, seq=True)
        with self.assertRaises(TypeError):
            q.publish("t", {"a": 1}, seq=-1)


class SubscribeTest(unittest.TestCase):
    def test_subscribe_returns_subscription(self):
        q = MessageQueue()
        sub = q.subscribe("orders", "worker-1", seq=3)
        self.assertIsInstance(sub, Subscription)
        self.assertEqual(sub.as_dict()["topic"], "orders")

    def test_duplicate_subscribe_raises(self):
        q = _queue_with()
        with self.assertRaises(DuplicateSubscriberError):
            q.subscribe("t", "s1", seq=1)

    def test_same_subscriber_different_topic_still_duplicate(self):
        q = _queue_with()
        with self.assertRaises(DuplicateSubscriberError):
            q.subscribe("other-topic", "s1", seq=1)

    def test_subscribers_view(self):
        q = _queue_with()
        q.subscribe("t", "s2", seq=1)
        self.assertEqual(q.subscribers("t"), ("s1", "s2"))
        self.assertEqual(q.subscribers("empty"), ())

    def test_subscribe_rejects_bad_id(self):
        q = MessageQueue()
        with self.assertRaises(TypeError):
            q.subscribe("t", "", seq=0)


class ReceiveTest(unittest.TestCase):
    def test_receive_delivers_in_topic_order(self):
        q = _queue_with()
        q.publish("t", "first", seq=0)
        q.publish("t", "second", seq=1)
        got = q.receive("s1", seq=2)
        self.assertEqual([d.payload for d in got], ["first", "second"])
        self.assertEqual([d.message_id for d in got], ["msg-1", "msg-2"])
        self.assertTrue(all(d.attempts == 1 for d in got))

    def test_receive_limit(self):
        q = _queue_with()
        q.publish("t", 1, seq=0)
        q.publish("t", 2, seq=1)
        got = q.receive("s1", seq=2, limit=1)
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0].payload, 1)

    def test_receive_rejects_bad_limit(self):
        q = _queue_with()
        with self.assertRaises(TypeError):
            q.receive("s1", seq=0, limit=0)
        with self.assertRaises(TypeError):
            q.receive("s1", seq=0, limit=True)

    def test_receive_unknown_subscriber(self):
        q = MessageQueue()
        with self.assertRaises(UnknownSubscriberError):
            q.receive("ghost", seq=0)

    def test_delivery_records_shape(self):
        q = _queue_with()
        q.publish("t", {"a": 1}, seq=0)
        (d,) = q.receive("s1", seq=1)
        self.assertIsInstance(d, Delivery)
        d.as_dict()  # no raise
        self.assertEqual(d.delivery_seq, 1)
        self.assertTrue(d.payload_digest.startswith("sha256:"))

    def test_delivery_payload_isolated(self):
        q = _queue_with()
        q.publish("t", {"items": [1]}, seq=0)
        (d1,) = q.receive("s1", seq=1)
        d1.payload["items"].append(99)
        q.ack("s1", "msg-1", seq=2)
        self.assertEqual(q.receive("s1", seq=3), ())
        q.publish("t", {"items": [1]}, seq=4)
        (d3,) = q.receive("s1", seq=5)
        self.assertEqual(d3.payload, {"items": [1]})


class AtLeastOnceTest(unittest.TestCase):
    def test_unacked_message_redelivered(self):
        q = _queue_with()
        q.publish("t", "x", seq=0)
        (d1,) = q.receive("s1", seq=1)
        (d2,) = q.receive("s1", seq=2)
        self.assertEqual(d2.message_id, d1.message_id)
        self.assertEqual(d2.attempts, 2)

    def test_pending_before_new(self):
        q = _queue_with()
        q.publish("t", "old", seq=0)
        (d1,) = q.receive("s1", seq=1)
        q.publish("t", "new", seq=2)
        got = q.receive("s1", seq=3)
        self.assertEqual([d.message_id for d in got], ["msg-1", "msg-2"])
        self.assertEqual(got[0].attempts, 2)
        self.assertEqual(got[1].attempts, 1)

    def test_nack_keeps_message_pending(self):
        q = _queue_with()
        q.publish("t", "x", seq=0)
        (d1,) = q.receive("s1", seq=1)
        rec = q.nack("s1", d1.message_id, seq=2)
        self.assertIsInstance(rec, NackRecord)
        self.assertEqual(rec.attempts, 1)
        self.assertEqual(q.pending_count("s1"), 1)
        (d2,) = q.receive("s1", seq=3)
        self.assertEqual(d2.attempts, 2)

    def test_ack_removes_pending_and_stops_redelivery(self):
        q = _queue_with()
        q.publish("t", "x", seq=0)
        (d1,) = q.receive("s1", seq=1)
        rec = q.ack("s1", d1.message_id, seq=2)
        self.assertIsInstance(rec, AckRecord)
        self.assertEqual(rec.attempts, 1)
        self.assertEqual(q.pending_count("s1"), 0)
        self.assertEqual(q.receive("s1", seq=3), ())

    def test_double_ack_raises(self):
        q = _queue_with()
        q.publish("t", "x", seq=0)
        q.receive("s1", seq=1)
        q.ack("s1", "msg-1", seq=2)
        with self.assertRaises(MessageNotPendingError):
            q.ack("s1", "msg-1", seq=3)

    def test_ack_never_delivered_raises(self):
        q = _queue_with()
        q.publish("t", "x", seq=0)
        with self.assertRaises(MessageNotPendingError):
            q.ack("s1", "msg-1", seq=1)

    def test_ack_unknown_message_raises(self):
        q = _queue_with()
        with self.assertRaises(UnknownMessageError):
            q.ack("s1", "msg-999", seq=0)

    def test_ack_unknown_subscriber_raises(self):
        q = _queue_with()
        with self.assertRaises(UnknownSubscriberError):
            q.ack("ghost", "msg-1", seq=0)

    def test_nack_not_pending_raises(self):
        q = _queue_with()
        q.publish("t", "x", seq=0)
        with self.assertRaises(MessageNotPendingError):
            q.nack("s1", "msg-1", seq=1)

    def test_nack_unknown_message_raises(self):
        q = _queue_with()
        with self.assertRaises(UnknownMessageError):
            q.nack("s1", "msg-999", seq=0)

    def test_pending_is_per_subscriber(self):
        q = _queue_with()
        q.subscribe("t", "s2", seq=0)
        q.publish("t", "x", seq=0)
        (d1,) = q.receive("s1", seq=1)
        (d2,) = q.receive("s2", seq=2)
        self.assertEqual(d1.message_id, d2.message_id)
        q.ack("s1", d1.message_id, seq=3)
        # s1's own copy is settled; s2 still holds its copy.
        with self.assertRaises(MessageNotPendingError):
            q.ack("s1", d2.message_id, seq=4)
        self.assertEqual(q.pending_count("s2"), 1)


class RecordsFrozenTest(unittest.TestCase):
    def test_records_are_frozen(self):
        q = _queue_with()
        m = q.publish("t", 1, seq=0)
        (d,) = q.receive("s1", seq=1)
        for rec in (m, d, q.subscribe("t", "s9", seq=2)):
            with self.assertRaises(Exception):
                rec.topic = "mutated"  # type: ignore


class AuditTest(unittest.TestCase):
    def test_audit_shapes(self):
        q = _queue_with()
        m = q.publish("t", {"secret_token_xyz": 1}, seq=0)
        (d,) = q.receive("s1", seq=1)
        pub = message_queue_audit_event("published", seq=2, message=m)
        self.assertEqual(pub["event"], "message-queue-published")
        self.assertEqual(pub["message_id"], "msg-1")
        sub = message_queue_audit_event("subscribed", seq=3, subscriber_id="s1")
        self.assertEqual(sub["event"], "message-queue-subscribed")
        self.assertEqual(sub["subscriber_id"], "s1")
        dlv = message_queue_audit_event("delivered", seq=4, subscriber_id="s1", delivery=d)
        self.assertEqual(dlv["attempts"], 1)
        self.assertNotIn("secret_token_xyz", str(dlv))  # payload content stays out
        ack = message_queue_audit_event("acked", seq=5, subscriber_id="s1")
        self.assertEqual(ack["schema"], SCHEMA_PIN)

    def test_audit_rejects_bad_kind(self):
        with self.assertRaises(ValueError):
            message_queue_audit_event("explode", seq=0)

    def test_audit_rejects_bad_seq(self):
        with self.assertRaises(TypeError):
            message_queue_audit_event("published", seq=-1)

    def test_audit_rejects_wrong_record_type(self):
        with self.assertRaises(TypeError):
            message_queue_audit_event("published", seq=0, message="nope")  # type: ignore


class StdlibOnlyTest(unittest.TestCase):
    def test_stdlib_only(self):
        import message_queue

        with open(message_queue.__file__) as f:
            tree = ast.parse(f.read())
        allowed = {
            "copy", "hashlib", "json", "math", "threading",
            "dataclasses", "typing", "__future__",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn(node.module.split(".")[0], allowed)  # type: ignore


class MainTest(unittest.TestCase):
    def test_main_self_check(self):
        import message_queue

        message_queue.main()


if __name__ == "__main__":
    unittest.main()
