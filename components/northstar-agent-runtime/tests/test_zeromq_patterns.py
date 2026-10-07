"""Tests for zeromq_patterns."""

import os
import unittest

from zeromq_patterns import (
    ZeroMQPatterns,
    ZeroMQPatternsError,
    BadSocketError,
    DuplicateSocketError,
    UnknownSocketError,
    BadConnectError,
    BadSubscriptionError,
    BadExchangeError,
    BadPublishError,
    BadPipelineError,
    BadAckError,
    SeqOrderError,
    SocketRecord,
    ConnectionRecord,
    SubscriptionRecord,
    ExchangeRecord,
    PublishRecord,
    TaskRecord,
    AckRecord,
    PATTERNS,
    _MODULE_VERSION,
    _SCHEMA_PIN,
    _stdlib_only_ok,
    zeromq_patterns_audit_event,
    main,
    _digest,
)


def make_zp():
    events = []
    return ZeroMQPatterns(audit=events.append), events


def digest(tag, i):
    return _digest(tag, {"i": i})


class PinsTest(unittest.TestCase):
    def test_version_pins(self):
        self.assertEqual(_MODULE_VERSION, "zeromq-patterns.v1")
        self.assertEqual(_SCHEMA_PIN, "northstar.zeromq-patterns.v1")

    def test_pattern_vocabulary(self):
        self.assertEqual(PATTERNS, ("req", "rep", "pub", "sub", "push", "pull"))

    def test_stdlib_only(self):
        here = os.path.dirname(os.path.abspath(__file__))
        mod = os.path.join(os.path.dirname(here), "zeromq_patterns.py")
        ok, why = _stdlib_only_ok(mod)
        self.assertTrue(ok, why)


class SocketTest(unittest.TestCase):
    def test_socket_roundtrip(self):
        zp, events = make_zp()
        rec = zp.socket("s1", "req", 1)
        self.assertIsInstance(rec, SocketRecord)
        self.assertEqual(rec.pattern, "req")
        self.assertTrue(rec.verify_digest())
        self.assertEqual(zp.socket_ids(), ("s1",))
        self.assertEqual(zp.pattern_of("s1"), "req")
        kinds = [e["event"] for e in events]
        self.assertIn("socket-created", kinds)

    def test_bad_pattern_refused(self):
        zp, _ = make_zp()
        with self.assertRaises(BadSocketError):
            zp.socket("s1", "tcp", 1)

    def test_duplicate_refused(self):
        zp, _ = make_zp()
        zp.socket("s1", "req", 1)
        with self.assertRaises(DuplicateSocketError):
            zp.socket("s1", "rep", 2)

    def test_bad_id_refused(self):
        zp, _ = make_zp()
        with self.assertRaises(BadSocketError):
            zp.socket("   ", "req", 1)

    def test_pattern_of_unknown(self):
        zp, _ = make_zp()
        with self.assertRaises(UnknownSocketError):
            zp.pattern_of("nope")


class ConnectTest(unittest.TestCase):
    def test_connect_roundtrip(self):
        zp, events = make_zp()
        zp.socket("cli", "req", 1)
        zp.socket("srv", "rep", 2)
        rec = zp.connect("cli", "srv", 3)
        self.assertIsInstance(rec, ConnectionRecord)
        self.assertTrue(rec.verify_digest())
        self.assertEqual(zp.peers_of("cli"), ("srv",))
        self.assertEqual(zp.peers_of("srv"), ("cli",))
        self.assertIn("connected", [e["event"] for e in events])

    def test_bad_pairing_refused(self):
        zp, _ = make_zp()
        zp.socket("a", "req", 1)
        zp.socket("b", "req", 2)
        with self.assertRaises(BadConnectError):
            zp.connect("a", "b", 3)

    def test_pub_cannot_connect(self):
        zp, _ = make_zp()
        zp.socket("p", "pub", 1)
        zp.socket("s", "sub", 2)
        with self.assertRaises(BadConnectError):
            zp.connect("p", "s", 3)

    def test_unknown_peer_refused(self):
        zp, _ = make_zp()
        zp.socket("a", "req", 1)
        with self.assertRaises(UnknownSocketError):
            zp.connect("a", "ghost", 2)

    def test_self_connect_refused(self):
        zp, _ = make_zp()
        zp.socket("a", "push", 1)
        with self.assertRaises(BadConnectError):
            zp.connect("a", "a", 2)


class SubscribeTest(unittest.TestCase):
    def test_subscribe_roundtrip(self):
        zp, events = make_zp()
        zp.socket("s", "sub", 1)
        rec = zp.subscribe("s", "news.", 2)
        self.assertIsInstance(rec, SubscriptionRecord)
        self.assertEqual(rec.topic, "news.")
        self.assertTrue(rec.verify_digest())
        self.assertEqual(len(zp.subscriptions_of("s")), 1)
        self.assertIn("subscribed", [e["event"] for e in events])

    def test_non_sub_refused(self):
        zp, _ = make_zp()
        zp.socket("p", "pub", 1)
        with self.assertRaises(BadSubscriptionError):
            zp.subscribe("p", "news.", 2)

    def test_unknown_socket_refused(self):
        zp, _ = make_zp()
        with self.assertRaises(UnknownSocketError):
            zp.subscribe("ghost", "news.", 1)

    def test_topic_too_long(self):
        zp, _ = make_zp()
        zp.socket("s", "sub", 1)
        with self.assertRaises(BadSubscriptionError):
            zp.subscribe("s", "x" * 300, 2)


class ReqRepTest(unittest.TestCase):
    def test_reqrep_roundtrip(self):
        zp, events = make_zp()
        zp.socket("cli", "req", 1)
        zp.socket("srv", "rep", 2)
        req = digest("q", 1)
        rec = zp.reqrep("cli", "srv", req, 3)
        self.assertIsInstance(rec, ExchangeRecord)
        self.assertTrue(rec.verify_digest())
        self.assertEqual(rec.request_digest, req)
        self.assertTrue(rec.reply_digest.startswith("sha256:"))
        got = zp.exchange(rec.exchange_id)
        self.assertEqual(got.exchange_id, rec.exchange_id)
        self.assertIn("requested", [e["event"] for e in events])

    def test_reqrep_injected_handler(self):
        zp, _ = make_zp()
        zp.socket("cli", "req", 1)
        zp.socket("srv", "rep", 2)
        reply = digest("r", 9)
        rec = zp.reqrep("cli", "srv", digest("q", 2), 3,
                        handler=lambda sid, rd: reply)
        self.assertEqual(rec.reply_digest, reply)

    def test_reqrep_bad_pairing_refused(self):
        zp, _ = make_zp()
        zp.socket("a", "push", 1)
        zp.socket("b", "pull", 2)
        with self.assertRaises(BadExchangeError):
            zp.reqrep("a", "b", digest("q", 1), 3)

    def test_reqrep_unknown_socket_refused(self):
        zp, _ = make_zp()
        zp.socket("cli", "req", 1)
        with self.assertRaises(UnknownSocketError):
            zp.reqrep("cli", "ghost", digest("q", 1), 2)

    def test_reqrep_bad_digest_refused(self):
        zp, _ = make_zp()
        zp.socket("cli", "req", 1)
        zp.socket("srv", "rep", 2)
        with self.assertRaises(BadExchangeError):
            zp.reqrep("cli", "srv", "not-a-digest", 3)

    def test_reqrep_raising_handler_fail_closed(self):
        zp, _ = make_zp()
        zp.socket("cli", "req", 1)
        zp.socket("srv", "rep", 2)

        def boom(sid, rd):
            raise RuntimeError("wire down")

        with self.assertRaises(BadExchangeError):
            zp.reqrep("cli", "srv", digest("q", 1), 3, handler=boom)


class PubSubTest(unittest.TestCase):
    def test_pubsub_prefix_matching(self):
        zp, events = make_zp()
        zp.socket("pub1", "pub", 1)
        zp.socket("s1", "sub", 2)
        zp.socket("s2", "sub", 3)
        zp.subscribe("s1", "news.", 4)
        zp.subscribe("s2", "", 5)  # empty topic matches everything
        rec = zp.pubsub("pub1", "news.sports", digest("m", 1), 6)
        self.assertIsInstance(rec, PublishRecord)
        self.assertTrue(rec.verify_digest())
        self.assertEqual(rec.matched_subscribers, ("s1", "s2"))
        self.assertIn("published", [e["event"] for e in events])

    def test_pubsub_no_match_is_data(self):
        zp, _ = make_zp()
        zp.socket("pub1", "pub", 1)
        zp.socket("s1", "sub", 2)
        zp.subscribe("s1", "news.", 3)
        rec = zp.pubsub("pub1", "weather", digest("m", 2), 4)
        self.assertEqual(rec.matched_subscribers, ())

    def test_pubsub_non_pub_refused(self):
        zp, _ = make_zp()
        zp.socket("s", "sub", 1)
        with self.assertRaises(BadPublishError):
            zp.pubsub("s", "news.", digest("m", 1), 2)

    def test_pubsub_bad_payload_digest_refused(self):
        zp, _ = make_zp()
        zp.socket("p", "pub", 1)
        with self.assertRaises(BadPublishError):
            zp.pubsub("p", "news.", "raw-bytes", 2)


class PipelineTest(unittest.TestCase):
    def test_pipeline_round_robin(self):
        zp, events = make_zp()
        zp.socket("vent", "push", 1)
        zp.socket("w1", "pull", 2)
        zp.socket("w2", "pull", 3)
        zp.connect("vent", "w1", 4)
        zp.connect("vent", "w2", 5)
        t1 = zp.pipeline("vent", digest("t", 1), 6)
        t2 = zp.pipeline("vent", digest("t", 2), 7)
        self.assertIsInstance(t1, TaskRecord)
        self.assertTrue(t1.verify_digest())
        self.assertEqual(t1.worker_id, "w1")
        self.assertEqual(t2.worker_id, "w2")
        self.assertIn("task-pushed", [e["event"] for e in events])

    def test_pipeline_no_worker_refused(self):
        zp, _ = make_zp()
        zp.socket("vent", "push", 1)
        with self.assertRaises(BadPipelineError):
            zp.pipeline("vent", digest("t", 1), 2)

    def test_pipeline_non_push_refused(self):
        zp, _ = make_zp()
        zp.socket("p", "pub", 1)
        with self.assertRaises(BadPipelineError):
            zp.pipeline("p", digest("t", 1), 2)


class AckTest(unittest.TestCase):
    def _task(self, zp):
        zp.socket("vent", "push", 1)
        zp.socket("w1", "pull", 2)
        zp.connect("vent", "w1", 3)
        return zp.pipeline("vent", digest("t", 1), 4)

    def test_ack_roundtrip(self):
        zp, events = make_zp()
        t = self._task(zp)
        rec = zp.ack(t.task_id, True, 5)
        self.assertIsInstance(rec, AckRecord)
        self.assertTrue(rec.verify_digest())
        self.assertTrue(zp.is_acked(t.task_id))
        self.assertIn("task-acked", [e["event"] for e in events])

    def test_ack_fail_is_data(self):
        zp, _ = make_zp()
        t = self._task(zp)
        rec = zp.ack(t.task_id, False, 5)
        self.assertFalse(rec.ok)
        self.assertTrue(zp.is_acked(t.task_id))

    def test_double_ack_refused(self):
        zp, _ = make_zp()
        t = self._task(zp)
        zp.ack(t.task_id, True, 5)
        with self.assertRaises(BadAckError):
            zp.ack(t.task_id, True, 6)

    def test_ack_unknown_task_refused(self):
        zp, _ = make_zp()
        with self.assertRaises(UnknownSocketError):
            zp.ack("task-999", True, 1)

    def test_ack_non_bool_refused(self):
        zp, _ = make_zp()
        t = self._task(zp)
        with self.assertRaises(BadAckError):
            zp.ack(t.task_id, "yes", 5)


class SeqTest(unittest.TestCase):
    def test_seq_rewind_refused(self):
        zp, _ = make_zp()
        zp.socket("a", "req", 5)
        with self.assertRaises(SeqOrderError):
            zp.socket("b", "req", 5)

    def test_seq_bool_refused(self):
        zp, _ = make_zp()
        with self.assertRaises(SeqOrderError):
            zp.socket("a", "req", True)

    def test_failed_mutation_consumes_seq(self):
        zp, _ = make_zp()
        zp.socket("a", "req", 1)
        with self.assertRaises(DuplicateSocketError):
            zp.socket("a", "rep", 2)  # failed, but seq 2 is consumed
        with self.assertRaises(SeqOrderError):
            zp.socket("b", "req", 2)

    def test_rejected_audited(self):
        zp, events = make_zp()
        with self.assertRaises(BadSocketError):
            zp.socket("a", "tcp", 7)
        rejected = [e for e in events if e["event"] == "rejected"]
        self.assertEqual(len(rejected), 1)
        self.assertEqual(rejected[0]["seq"], 7)


class AuditTest(unittest.TestCase):
    def test_audit_shapes(self):
        ev = zeromq_patterns_audit_event(
            "socket-created", 3, {"socket_id": "s1"})
        self.assertEqual(ev["schema_version"], "audit.ndjson/1")
        self.assertEqual(ev["module"], _MODULE_VERSION)
        self.assertEqual(ev["event"], "socket-created")
        self.assertEqual(ev["seq"], 3)

    def test_audit_bad_kind_refused(self):
        with self.assertRaises(ZeroMQPatternsError):
            zeromq_patterns_audit_event("nonsense", 1, {})

    def test_audit_carries_digests_only(self):
        # No raw payload bytes in any module-emitted audit detail.
        zp, events = make_zp()
        zp.socket("cli", "req", 1)
        zp.socket("srv", "rep", 2)
        rec = zp.reqrep("cli", "srv", digest("q", 1), 3)
        requested = [e for e in events if e["event"] == "requested"]
        self.assertEqual(len(requested), 1)
        detail = requested[0]["detail"]
        self.assertNotIn("payload", detail)
        self.assertEqual(detail["reply_digest"], rec.reply_digest)


class MainTest(unittest.TestCase):
    def test_main(self):
        self.assertEqual(main(), 0)


if __name__ == "__main__":
    unittest.main()
