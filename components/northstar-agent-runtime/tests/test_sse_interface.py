"""Tests for sse_interface.py."""

import ast
import threading
import unittest

from sse_interface import (
    SSEError,
    ClosedStreamError,
    CloseRecord,
    DuplicateEventIdError,
    DuplicateSubscriberError,
    EventRecord,
    SSE_INTERFACE_VERSION,
    SCHEMA_PIN,
    SSEInterface,
    Subscription,
    UnknownEventIdError,
    UnknownStreamError,
    UnknownSubscriberError,
    sse_interface_audit_event,
)


class VersionPinTests(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(SSE_INTERFACE_VERSION, "sse-interface.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.sse-interface.v1")


class SubscribeTests(unittest.TestCase):
    def setUp(self):
        self.iface = SSEInterface()

    def test_subscribe_creates_stream(self):
        sub = self.iface.subscribe("chat", "browser-1", 0)
        self.assertIsInstance(sub, Subscription)
        self.assertEqual(sub.stream_id, "chat")
        self.assertEqual(sub.subscriber_id, "browser-1")
        self.assertEqual(sub.seq, 0)
        self.assertIn("chat", self.iface.streams())

    def test_duplicate_subscriber_refused(self):
        self.iface.subscribe("chat", "browser-1", 0)
        with self.assertRaises(DuplicateSubscriberError):
            self.iface.subscribe("chat", "browser-1", 1)

    def test_subscribe_bad_inputs(self):
        with self.assertRaises(SSEError):
            self.iface.subscribe("", "browser-1", 0)
        with self.assertRaises(SSEError):
            self.iface.subscribe("chat", "", 0)
        with self.assertRaises(SSEError):
            self.iface.subscribe("chat", "browser-1", -1)
        with self.assertRaises(SSEError):
            self.iface.subscribe("chat", "browser-1", True)

    def test_subscribers_sorted(self):
        self.iface.subscribe("chat", "b", 0)
        self.iface.subscribe("chat", "a", 1)
        self.assertEqual(self.iface.subscribers("chat"), ("a", "b"))

    def test_unsubscribe(self):
        self.iface.subscribe("chat", "browser-1", 0)
        self.iface.unsubscribe("chat", "browser-1", 1)
        self.assertEqual(self.iface.subscribers("chat"), ())
        with self.assertRaises(UnknownSubscriberError):
            self.iface.unsubscribe("chat", "browser-1", 2)
        with self.assertRaises(UnknownStreamError):
            self.iface.unsubscribe("nope", "browser-1", 3)


class EmitTests(unittest.TestCase):
    def setUp(self):
        self.iface = SSEInterface()
        self.iface.subscribe("chat", "browser-1", 0)

    def test_emit_auto_id(self):
        ev = self.iface.emit("chat", {"text": "hi"}, 1)
        self.assertIsInstance(ev, EventRecord)
        self.assertEqual(ev.event_id, "evt-1")
        self.assertEqual(ev.event_type, "message")
        self.assertTrue(ev.verify())

    def test_emit_explicit_id(self):
        ev = self.iface.emit("chat", {"text": "hi"}, 1, event_type="chat", event_id="abc")
        self.assertEqual(ev.event_id, "abc")
        self.assertEqual(ev.event_type, "chat")
        self.assertTrue(ev.verify())

    def test_emit_duplicate_id_refused(self):
        self.iface.emit("chat", "a", 1, event_id="x")
        with self.assertRaises(DuplicateEventIdError):
            self.iface.emit("chat", "b", 2, event_id="x")

    def test_emit_unknown_stream_refused(self):
        with self.assertRaises(UnknownStreamError):
            self.iface.emit("nope", "a", 0)

    def test_emit_retry(self):
        ev = self.iface.emit("chat", "a", 1, retry_ms=3000)
        self.assertEqual(ev.retry_ms, 3000)
        with self.assertRaises(SSEError):
            self.iface.emit("chat", "a", 2, retry_ms=-1)
        with self.assertRaises(SSEError):
            self.iface.emit("chat", "a", 3, retry_ms=True)

    def test_emit_nan_refused(self):
        with self.assertRaises(SSEError):
            self.iface.emit("chat", float("nan"), 1)

    def test_emit_big_float_refused(self):
        with self.assertRaises(SSEError):
            self.iface.emit("chat", {"n": float(2**54)}, 1)

    def test_emit_digest_binds_content(self):
        a = self.iface.emit("chat", {"n": 1}, 1, event_id="same")
        self.iface.emit("chat", {"n": 2}, 2, event_id="other")
        self.assertNotEqual(a.digest, self.iface._streams["chat"].events[-1].digest)
        self.assertNotEqual(a.data_digest, self.iface._streams["chat"].events[-1].data_digest)


class CloseTests(unittest.TestCase):
    def setUp(self):
        self.iface = SSEInterface()
        self.iface.subscribe("chat", "browser-1", 0)

    def test_close_happy_path(self):
        self.iface.emit("chat", "a", 1)
        rec = self.iface.close("chat", 2)
        self.assertIsInstance(rec, CloseRecord)
        self.assertEqual(rec.event_count, 1)
        self.assertEqual(rec.last_event_id, "evt-1")

    def test_close_empty_stream(self):
        rec = self.iface.close("chat", 1)
        self.assertIsNone(rec.last_event_id)
        self.assertEqual(rec.event_count, 0)

    def test_close_twice_refused(self):
        self.iface.close("chat", 1)
        with self.assertRaises(ClosedStreamError):
            self.iface.close("chat", 2)

    def test_close_unknown_refused(self):
        with self.assertRaises(UnknownStreamError):
            self.iface.close("nope", 0)

    def test_emit_after_close_refused(self):
        self.iface.close("chat", 1)
        with self.assertRaises(ClosedStreamError):
            self.iface.emit("chat", "a", 2)

    def test_subscribe_after_close_refused(self):
        self.iface.close("chat", 1)
        with self.assertRaises(ClosedStreamError):
            self.iface.subscribe("chat", "late", 2)


class ResumeTests(unittest.TestCase):
    def setUp(self):
        self.iface = SSEInterface()
        self.iface.subscribe("chat", "browser-1", 0)
        self.a = self.iface.emit("chat", "a", 1)
        self.b = self.iface.emit("chat", "b", 2)
        self.c = self.iface.emit("chat", "c", 3)

    def test_events_since(self):
        missed = self.iface.events_since("chat", self.a.event_id)
        self.assertEqual([e.event_id for e in missed], [self.b.event_id, self.c.event_id])

    def test_events_since_latest_empty(self):
        missed = self.iface.events_since("chat", self.c.event_id)
        self.assertEqual(missed, ())

    def test_events_since_unknown_id_refused(self):
        with self.assertRaises(UnknownEventIdError):
            self.iface.events_since("chat", "evt-999")

    def test_last_event_id(self):
        self.assertEqual(self.iface.last_event_id("chat"), "evt-3")
        self.iface.subscribe("empty", "x", 4)
        self.assertIsNone(self.iface.last_event_id("empty"))


class AuditTests(unittest.TestCase):
    def test_audit_shapes(self):
        ev = sse_interface_audit_event("emitted", 1, "chat", digest="sha256:abc")
        self.assertEqual(ev["schema"], "audit.ndjson/1")
        self.assertEqual(ev["module"], SSE_INTERFACE_VERSION)
        self.assertEqual(ev["kind"], "emitted")
        self.assertEqual(ev["digest"], "sha256:abc")
        for kind in ("stream-created", "subscribed", "unsubscribed", "closed", "replayed"):
            rec = sse_interface_audit_event(kind, 2, "s")
            self.assertEqual(rec["kind"], kind)

    def test_audit_unknown_kind_refused(self):
        with self.assertRaises(SSEError):
            sse_interface_audit_event("nope", 0, "s")

    def test_audit_bad_seq_refused(self):
        with self.assertRaises(SSEError):
            sse_interface_audit_event("emitted", -1, "s")


class RecordShapeTests(unittest.TestCase):
    def test_frozen_records(self):
        sub = Subscription(stream_id="s", subscriber_id="u", seq=0)
        with self.assertRaises(Exception):
            sub.seq = 5  # frozen dataclass

    def test_as_dict_no_raw_data(self):
        ev = EventRecord(stream_id="s", event_id="e", event_type="m", data={"secret": 1}, seq=0)
        d = ev.as_dict()
        self.assertNotIn("data", d)
        self.assertIn("data_digest", d)

    def test_concurrent_emit(self):
        iface = SSEInterface()
        iface.subscribe("chat", "u", 0)
        errors = []

        def worker(i):
            try:
                for j in range(10):
                    iface.emit("chat", {"i": i, "j": j}, i * 10 + j)
            except Exception as exc:  # pragma: no cover
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertEqual(len(iface._streams["chat"].events), 50)


class StdlibOnlyTests(unittest.TestCase):
    def test_stdlib_only(self):
        import sse_interface

        allowed = {
            "hashlib",
            "json",
            "math",
            "threading",
            "dataclasses",
            "typing",
            "__future__",
        }
        with open(sse_interface.__file__, encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imports.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module.split(".")[0])
        self.assertLessEqual(imports, allowed, f"unexpected imports: {imports - allowed}")


class MainTests(unittest.TestCase):
    def test_main(self):
        import sse_interface

        sse_interface.main()


if __name__ == "__main__":
    unittest.main()
