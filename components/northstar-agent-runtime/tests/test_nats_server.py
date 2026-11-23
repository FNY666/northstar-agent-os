"""Targeted tests for nats_server."""

import ast
import subprocess
import sys
import unittest

from nats_server import (
    AUDIT_SCHEMA,
    NATS_SERVER_SCHEMA,
    NATS_SERVER_VERSION,
    AckStateError,
    BadPayloadError,
    BadSubjectError,
    DuplicateConsumerError,
    DuplicateStreamError,
    DuplicateSubscriberError,
    NATSServer,
    NATSServerError,
    RequestStateError,
    SeqOrderError,
    UnknownConsumerError,
    UnknownRequestError,
    UnknownStreamError,
    UnknownSubscriberError,
    nats_server_audit_event,
)


class VersionPinTest(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(NATS_SERVER_VERSION, "nats-server.v1")

    def test_schema_pin(self):
        self.assertEqual(NATS_SERVER_SCHEMA, "northstar.nats-server.v1")


class StdlibOnlyTest(unittest.TestCase):
    def test_stdlib_only(self):
        with open("nats_server.py") as fh:
            tree = ast.parse(fh.read())
        allowed = {"canonical_json"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertTrue(
                        a.name.split(".")[0] in allowed
                        or a.name in (
                            "re", "threading", "dataclasses", "typing",
                            "hashlib", "json", "__future__"),
                        f"non-stdlib import: {a.name}")
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    self.assertTrue(
                        node.module.split(".")[0] in allowed
                        or node.module.split(".")[0] in (
                            "re", "threading", "dataclasses", "typing",
                            "hashlib", "json", "__future__"),
                        f"non-stdlib import: {node.module}")


class SubjectWildcardTest(unittest.TestCase):
    def test_star_matches_one_token(self):
        s = NATSServer()
        s.subscribe("a", "orders.*.created", 1)
        self.assertEqual(s.match("orders.us.created", 2), ("a",))
        self.assertEqual(s.match("orders.us.eu.created", 3), ())

    def test_gt_matches_trailing(self):
        s = NATSServer()
        s.subscribe("a", "orders.>", 1)
        self.assertEqual(s.match("orders.us", 2), ("a",))
        self.assertEqual(s.match("orders.us.created", 3), ("a",))
        self.assertEqual(s.match("orders", 4), ())

    def test_gt_must_be_final(self):
        s = NATSServer()
        with self.assertRaises(BadSubjectError):
            s.subscribe("a", "orders.>.x", 1)

    def test_publish_subject_rejects_wildcards(self):
        s = NATSServer()
        s.subscribe("a", "orders.>", 1)
        with self.assertRaises(BadSubjectError):
            s.publish("orders.*", {"x": 1}, 2)


class PublishSubscribeTest(unittest.TestCase):
    def test_publish_fanout(self):
        s = NATSServer()
        s.subscribe("a", "evt.>", 1)
        s.subscribe("b", "evt.cpu", 2)
        msg, dlvs = s.publish("evt.cpu", {"v": 1}, 3)
        self.assertTrue(msg.verify())
        self.assertEqual(len(dlvs), 2)
        self.assertTrue(all(d.verify() for d in dlvs))

    def test_queue_group_single_delivery(self):
        s = NATSServer()
        s.subscribe("w1", "jobs.run", 1, queue_group="workers")
        s.subscribe("w2", "jobs.run", 2, queue_group="workers")
        _, dlvs = s.publish("jobs.run", {"n": 1}, 3)
        self.assertEqual(len(dlvs), 1)

    def test_duplicate_subscriber_refused(self):
        s = NATSServer()
        s.subscribe("a", "x.y", 1)
        with self.assertRaises(DuplicateSubscriberError):
            s.subscribe("a", "x.y", 2)

    def test_unsubscribe_unknown_refused(self):
        s = NATSServer()
        with self.assertRaises(UnknownSubscriberError):
            s.unsubscribe("nope", 1)

    def test_bad_payload_refused(self):
        s = NATSServer()
        s.subscribe("a", "x.y", 1)
        with self.assertRaises(BadPayloadError):
            s.publish("x.y", {"v": float("nan")}, 2)
        with self.assertRaises(BadPayloadError):
            s.publish("x.y", {"v": 2 ** 53}, 3)


class SeqDisciplineTest(unittest.TestCase):
    def test_seq_must_increase(self):
        s = NATSServer()
        s.subscribe("a", "x.y", 1)
        with self.assertRaises(SeqOrderError):
            s.subscribe("b", "x.y", 1)

    def test_failed_mutation_consumes_seq(self):
        s = NATSServer()
        with self.assertRaises(DuplicateSubscriberError):
            s.subscribe("a", "x.y", 1)
            s.subscribe("a", "x.y", 2)
        # seq 2 was consumed by the failed mutation
        with self.assertRaises(SeqOrderError):
            s.subscribe("b", "x.y", 2)


class RequestReplyTest(unittest.TestCase):
    def test_request_reply_roundtrip(self):
        s = NATSServer()
        req = s.request("svc.add", {"a": 1}, 1, timeout_seqs=10)
        self.assertTrue(req.verify())
        self.assertTrue(s.inbox(req.request_id, 2).startswith("_INBOX."))
        rep = s.reply(req.request_id, {"sum": 2}, 3)
        self.assertTrue(rep.verify())

    def test_double_reply_refused(self):
        s = NATSServer()
        req = s.request("svc.add", {"a": 1}, 1)
        s.reply(req.request_id, {"sum": 2}, 2)
        with self.assertRaises(RequestStateError):
            s.reply(req.request_id, {"sum": 3}, 3)

    def test_late_reply_refused_after_expiry(self):
        s = NATSServer()
        req = s.request("svc.add", {"a": 1}, 1, timeout_seqs=5)
        expired = s.expire_requests(10)
        self.assertEqual(expired, (req.request_id,))
        with self.assertRaises(RequestStateError):
            s.reply(req.request_id, {"sum": 2}, 11)

    def test_unknown_request_refused(self):
        s = NATSServer()
        with self.assertRaises(UnknownRequestError):
            s.reply("req-999", {"x": 1}, 1)


class JetStreamTest(unittest.TestCase):
    def test_stream_publish_consume_ack(self):
        s = NATSServer()
        st = s.create_stream("ORDERS", ("orders.>",), 1)
        self.assertTrue(st.verify())
        m1 = s.jetstream_publish("ORDERS", "orders.us", {"id": 1}, 2)
        m2 = s.jetstream_publish("ORDERS", "orders.eu", {"id": 2}, 3)
        self.assertEqual((m1.stream_seq, m2.stream_seq), (1, 2))
        con = s.create_consumer("ORDERS", "audit", 4)
        self.assertTrue(con.verify())
        d1 = s.consumer_deliver("ORDERS", "audit", 5)
        self.assertEqual(d1.stream_seq, 1)
        self.assertFalse(d1.acked)
        acked = s.ack(d1.delivery_id, 6)
        self.assertTrue(acked.acked and acked.verify())

    def test_subject_outside_stream_refused(self):
        s = NATSServer()
        s.create_stream("ORDERS", ("orders.>",), 1)
        with self.assertRaises(BadSubjectError):
            s.jetstream_publish("ORDERS", "billing.us", {"id": 1}, 2)

    def test_duplicate_stream_refused(self):
        s = NATSServer()
        s.create_stream("S", ("a.b",), 1)
        with self.assertRaises(DuplicateStreamError):
            s.create_stream("S", ("a.b",), 2)

    def test_duplicate_consumer_refused(self):
        s = NATSServer()
        s.create_stream("S", ("a.b",), 1)
        s.create_consumer("S", "c1", 2)
        with self.assertRaises(DuplicateConsumerError):
            s.create_consumer("S", "c1", 3)

    def test_double_ack_refused(self):
        s = NATSServer()
        s.create_stream("S", ("a.b",), 1)
        s.jetstream_publish("S", "a.b", {"x": 1}, 2)
        s.create_consumer("S", "c1", 3)
        d = s.consumer_deliver("S", "c1", 4)
        s.ack(d.delivery_id, 5)
        with self.assertRaises(AckStateError):
            s.ack(d.delivery_id, 6)

    def test_unknown_stream_consumer_refused(self):
        s = NATSServer()
        with self.assertRaises(UnknownStreamError):
            s.create_consumer("NOPE", "c1", 1)
        s.create_stream("S", ("a.b",), 2)
        with self.assertRaises(UnknownConsumerError):
            s.consumer_deliver("S", "nope", 3)


class AuditBoundaryTest(unittest.TestCase):
    def test_audit_shapes(self):
        ev = nats_server_audit_event(
            "published", 1, {"subject": "a.b", "digest": "sha256:00"})
        self.assertEqual(ev["schema"], AUDIT_SCHEMA)
        self.assertEqual(ev["kind"], "nats-server.published")

    def test_payload_banned_from_audit(self):
        with self.assertRaises(NATSServerError):
            nats_server_audit_event("published", 1, {"payload": {"x": 1}})

    def test_bad_kind_refused(self):
        with self.assertRaises(NATSServerError):
            nats_server_audit_event("bogus", 1)

    def test_stats(self):
        s = NATSServer()
        s.subscribe("a", "x.>", 1)
        s.publish("x.y", {"v": 1}, 2)
        stats = s.stats()
        self.assertEqual(stats["subscribers"], 1)
        self.assertEqual(stats["messages"], 1)
        self.assertEqual(stats["deliveries"], 1)

    def test_main_self_check(self):
        r = subprocess.run([sys.executable, "nats_server.py"],
                           capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("nats-server OK", r.stdout)


if __name__ == "__main__":
    unittest.main()
