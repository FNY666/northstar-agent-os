"""Tests for websocket_gateway."""

from __future__ import annotations

import ast
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from websocket_gateway import (  # noqa: E402
    STATE_CLOSED,
    STATE_OPEN,
    SCHEMA_PIN,
    WEBSOCKET_GATEWAY_VERSION,
    BroadcastReport,
    CloseRecord,
    ClosedConnectionError,
    Connection,
    DuplicateConnectionError,
    Frame,
    ProtocolError,
    UnknownConnectionError,
    WebSocketGateway,
    WebSocketGatewayError,
    websocket_gateway_audit_event,
)


def _gw_with(n: int) -> WebSocketGateway:
    gw = WebSocketGateway()
    for i in range(n):
        gw.connect(f"c{i}", i)
    return gw


class TestVersionPin(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(WEBSOCKET_GATEWAY_VERSION, "websocket-gateway.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.websocket-gateway.v1")


class TestConnect(unittest.TestCase):
    def test_happy_path(self):
        gw = WebSocketGateway()
        conn = gw.connect("c1", 0)
        self.assertEqual(conn.state, STATE_OPEN)
        self.assertEqual(conn.conn_id, "c1")
        self.assertIsNone(conn.subprotocol)
        self.assertTrue(conn.digest.startswith("sha256:"))

    def test_subprotocol(self):
        gw = WebSocketGateway()
        conn = gw.connect("c1", 0, subprotocol="chat")
        self.assertEqual(conn.subprotocol, "chat")

    def test_duplicate_rejected(self):
        gw = _gw_with(1)
        with self.assertRaises(DuplicateConnectionError):
            gw.connect("c0", 9)

    def test_bad_conn_id(self):
        gw = WebSocketGateway()
        for bad in ("", 123, None, True, b"c1"):
            with self.assertRaises((TypeError, ValueError)):
                gw.connect(bad, 0)

    def test_bad_seq(self):
        gw = WebSocketGateway()
        for bad in (-1, True, "0", 1.5):
            with self.assertRaises((TypeError, ValueError)):
                gw.connect("c1", bad)

    def test_bad_subprotocol(self):
        gw = WebSocketGateway()
        with self.assertRaises(TypeError):
            gw.connect("c1", 0, subprotocol=123)
        with self.assertRaises(ValueError):
            gw.connect("c1", 0, subprotocol="")


class TestSend(unittest.TestCase):
    def test_happy_path(self):
        gw = _gw_with(1)
        f = gw.send("c0", "hello", 1)
        self.assertEqual(f.opcode, "text")
        self.assertEqual(f.frame_no, 0)
        self.assertFalse(f.masked)  # server side
        self.assertTrue(f.digest.startswith("sha256:"))

    def test_frame_ordering(self):
        gw = _gw_with(1)
        a = gw.send("c0", "a", 1)
        b = gw.send("c0", "b", 2)
        self.assertEqual((a.frame_no, b.frame_no), (0, 1))
        self.assertNotEqual(a.digest, b.digest)

    def test_digest_deterministic(self):
        gw1, gw2 = _gw_with(1), _gw_with(1)
        f1 = gw1.send("c0", {"k": "v"}, 1)
        f2 = gw2.send("c0", {"k": "v"}, 1)
        self.assertEqual(f1.digest, f2.digest)

    def test_unknown_conn(self):
        gw = _gw_with(1)
        with self.assertRaises(UnknownConnectionError):
            gw.send("nope", "x", 1)

    def test_bad_opcode(self):
        gw = _gw_with(1)
        with self.assertRaises(ProtocolError):
            gw.send("c0", "x", 1, opcode="weird")
        with self.assertRaises(TypeError):
            gw.send("c0", "x", 1, opcode=123)

    def test_bad_payload(self):
        gw = _gw_with(1)
        with self.assertRaises(ValueError):
            gw.send("c0", float("nan"), 1)
        with self.assertRaises(TypeError):
            gw.send("c0", object(), 1)

    def test_bool_payload_distinct(self):
        gw = _gw_with(1)
        a = gw.send("c0", True, 1)
        gw2 = _gw_with(1)
        b = gw2.send("c0", 1, 1)
        self.assertNotEqual(a.digest, b.digest)


class TestInjectReceive(unittest.TestCase):
    def test_roundtrip_masked(self):
        gw = _gw_with(1)
        gw.inject("c0", "client says hi", 1, opcode="text")
        f = gw.receive("c0", 2)
        self.assertIsNotNone(f)
        assert f is not None
        self.assertTrue(f.masked)  # client side
        self.assertEqual(f.payload, "client says hi")

    def test_receive_empty_is_none(self):
        gw = _gw_with(1)
        self.assertIsNone(gw.receive("c0", 0))

    def test_fifo_order(self):
        gw = _gw_with(1)
        gw.inject("c0", "first", 1)
        gw.inject("c0", "second", 2)
        self.assertEqual(gw.receive("c0", 3).payload, "first")
        self.assertEqual(gw.receive("c0", 4).payload, "second")
        self.assertIsNone(gw.receive("c0", 5))

    def test_receive_unknown_conn(self):
        gw = _gw_with(1)
        with self.assertRaises(UnknownConnectionError):
            gw.receive("nope", 0)

    def test_inject_closed_fails(self):
        gw = _gw_with(1)
        gw.close("c0", 1)
        with self.assertRaises(ClosedConnectionError):
            gw.inject("c0", "x", 2)


class TestPingPong(unittest.TestCase):
    def test_ping_pong_opcodes(self):
        gw = _gw_with(1)
        p = gw.ping("c0", 1)
        q = gw.pong("c0", 2)
        self.assertEqual(p.opcode, "ping")
        self.assertEqual(q.opcode, "pong")


class TestBroadcast(unittest.TestCase):
    def test_fanout(self):
        gw = _gw_with(3)
        rep = gw.broadcast("news", 3)
        self.assertEqual(rep.delivered, ("c0", "c1", "c2"))
        self.assertEqual(rep.skipped, ())
        self.assertTrue(rep.payload_digest.startswith("sha256:"))
        self.assertTrue(rep.digest.startswith("sha256:"))

    def test_skips_closed(self):
        gw = _gw_with(2)
        gw.close("c1", 2)
        rep = gw.broadcast("news", 3)
        self.assertEqual(rep.delivered, ("c0",))
        self.assertEqual(rep.skipped, ("c1",))

    def test_outbound_queued(self):
        gw = _gw_with(2)
        gw.broadcast("news", 2)
        self.assertEqual(len(gw.outbound("c0")), 1)
        self.assertEqual(gw.outbound("c0")[0].payload, "news")


class TestClose(unittest.TestCase):
    def test_happy_path(self):
        gw = _gw_with(1)
        rec = gw.close("c0", 1, code=1000, reason="done")
        self.assertEqual(rec.code, 1000)
        self.assertEqual(rec.reason, "done")
        self.assertTrue(rec.digest.startswith("sha256:"))
        self.assertEqual(gw.connection("c0").state, STATE_CLOSED)
        # close frame was booked before the state change
        self.assertEqual(gw.outbound("c0")[-1].opcode, "close")

    def test_send_after_close_fails(self):
        gw = _gw_with(1)
        gw.close("c0", 1)
        with self.assertRaises(ClosedConnectionError):
            gw.send("c0", "x", 2)

    def test_double_close_fails(self):
        gw = _gw_with(1)
        gw.close("c0", 1)
        with self.assertRaises(ClosedConnectionError):
            gw.close("c0", 2)

    def test_reserved_codes_refused(self):
        gw = _gw_with(1)
        for code in (1005, 1006, 1015):
            with self.assertRaises(ProtocolError):
                gw.close("c0", 1, code=code)

    def test_bad_codes_refused(self):
        gw = _gw_with(1)
        for code in (999, 5000, "1000", True):
            with self.assertRaises((ProtocolError, TypeError)):
                gw.close("c0", 1, code=code)

    def test_unknown_conn(self):
        gw = _gw_with(1)
        with self.assertRaises(UnknownConnectionError):
            gw.close("nope", 1)


class TestViews(unittest.TestCase):
    def test_connections_sorted(self):
        gw = WebSocketGateway()
        gw.connect("b", 0)
        gw.connect("a", 1)
        self.assertEqual(gw.connections(), ("a", "b"))

    def test_stats(self):
        gw = _gw_with(1)
        gw.send("c0", "x", 1)
        gw.inject("c0", "y", 2)
        gw.receive("c0", 3)
        st = gw.stats("c0")
        self.assertEqual(st["frames_sent"], 1)
        self.assertEqual(st["frames_received"], 1)
        self.assertEqual(st["inbound_queued"], 0)
        self.assertEqual(st["state"], STATE_OPEN)

    def test_stats_unknown(self):
        gw = _gw_with(1)
        with self.assertRaises(UnknownConnectionError):
            gw.stats("nope")

    def test_mask_key_deterministic(self):
        gw = _gw_with(1)
        self.assertEqual(gw.mask_key("c0", 0), gw.mask_key("c0", 0))
        self.assertNotEqual(gw.mask_key("c0", 0), gw.mask_key("c0", 1))
        self.assertEqual(len(gw.mask_key("c0", 0)), 4)


class TestFrozenRecords(unittest.TestCase):
    def test_frame_frozen(self):
        gw = _gw_with(1)
        f = gw.send("c0", "x", 1)
        with self.assertRaises(Exception):
            f.opcode = "binary"  # type: ignore[misc]

    def test_as_dict_shapes(self):
        gw = _gw_with(1)
        f = gw.send("c0", "x", 1)
        d = f.as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertEqual(d["version"], WEBSOCKET_GATEWAY_VERSION)
        rep = gw.broadcast("x", 2)
        self.assertEqual(rep.as_dict()["delivered"], ["c0"])


class TestAudit(unittest.TestCase):
    def test_shapes(self):
        for kind in (
            "connected",
            "frame-sent",
            "frame-injected",
            "frame-received",
            "broadcast",
            "closed",
            "rejected",
        ):
            ev = websocket_gateway_audit_event(kind, 0, conn_id="c0")
            self.assertEqual(ev["format"], "audit.ndjson/1")
            self.assertEqual(ev["kind"], kind)
            self.assertEqual(ev["module"], WEBSOCKET_GATEWAY_VERSION)

    def test_rejections(self):
        with self.assertRaises(ValueError):
            websocket_gateway_audit_event("nope", 0)
        with self.assertRaises((TypeError, ValueError)):
            websocket_gateway_audit_event("connected", -1)
        with self.assertRaises(TypeError):
            websocket_gateway_audit_event("connected", True)


class TestStdlibOnly(unittest.TestCase):
    def test_stdlib_only(self):
        src = Path(__file__).resolve().parent.parent / "websocket_gateway.py"
        tree = ast.parse(src.read_text())
        allowed = {
            "hashlib",
            "hmac",
            "json",
            "math",
            "threading",
            "dataclasses",
            "typing",
            "__future__",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], allowed, a.name)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn(node.module.split(".")[0], allowed, node.module)


class TestMain(unittest.TestCase):
    def test_main(self):
        from websocket_gateway import main  # noqa: E402

        main()  # must not raise


if __name__ == "__main__":
    unittest.main()
