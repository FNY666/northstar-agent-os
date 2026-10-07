"""Tests for cqrs_pattern: segregated command/query dispatch."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import cqrs_pattern as m


def _cmd(cid="c-1", ctype="set", payload=None, seq=0):
    return m.Command(
        command_id=cid,
        command_type=ctype,
        payload={} if payload is None else payload,
        seq=seq,
    )


def _qry(qid="q-1", qtype="get", criteria=None, seq=0):
    return m.Query(
        query_id=qid,
        query_type=qtype,
        criteria={} if criteria is None else criteria,
        seq=seq,
    )


def _bus_with_echo():
    """Bus with a 'set' command handler and a 'get' query handler."""
    store = {}

    def set_handler(cmd):
        store[cmd.payload["key"]] = cmd.payload["value"]

    def get_handler(q):
        return store.get(q.criteria["key"])

    bus = m.CQRSBus()
    bus.register_command_handler("set", set_handler)
    bus.register_query_handler("get", get_handler)
    return bus, store


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(m.CQRS_PATTERN_VERSION, "cqrs-pattern.v1")

    def test_schema_pin(self):
        self.assertEqual(m.SCHEMA_PIN, "northstar.cqrs-pattern.v1")


class TestCommandValidation(unittest.TestCase):
    def test_frozen(self):
        cmd = _cmd()
        with self.assertRaises(AttributeError):
            cmd.command_id = "x"  # type: ignore[misc]

    def test_empty_id_rejected(self):
        with self.assertRaises(ValueError):
            _cmd(cid="")

    def test_empty_type_rejected(self):
        with self.assertRaises(ValueError):
            _cmd(ctype="")

    def test_non_mapping_payload_rejected(self):
        with self.assertRaises(TypeError):
            _cmd(payload="nope")  # type: ignore[arg-type]

    def test_bool_seq_rejected(self):
        with self.assertRaises(ValueError):
            _cmd(seq=True)

    def test_negative_seq_rejected(self):
        with self.assertRaises(ValueError):
            _cmd(seq=-1)

    def test_digest_deterministic(self):
        self.assertEqual(_cmd().digest(), _cmd().digest())
        self.assertTrue(_cmd().digest().startswith("sha256:"))


class TestQueryValidation(unittest.TestCase):
    def test_frozen(self):
        q = _qry()
        with self.assertRaises(AttributeError):
            q.query_id = "x"  # type: ignore[misc]

    def test_empty_id_rejected(self):
        with self.assertRaises(ValueError):
            _qry(qid="")

    def test_non_mapping_criteria_rejected(self):
        with self.assertRaises(TypeError):
            _qry(criteria=42)  # type: ignore[arg-type]

    def test_digest_deterministic(self):
        self.assertEqual(_qry().digest(), _qry().digest())


class TestDispatch(unittest.TestCase):
    def test_command_returns_ack_only(self):
        bus, store = _bus_with_echo()
        ack = bus.dispatch_command(
            _cmd(payload={"key": "k", "value": "v"})
        )
        self.assertTrue(ack.accepted)
        self.assertEqual(ack.command_id, "c-1")
        self.assertEqual(store, {"k": "v"})
        # Acknowledgment carries no domain data.
        self.assertNotIn("value", ack.as_dict())

    def test_query_returns_data(self):
        bus, _ = _bus_with_echo()
        bus.dispatch_command(_cmd(payload={"key": "k", "value": "v"}))
        res = bus.dispatch_query(_qry(criteria={"key": "k"}))
        self.assertEqual(res.data, "v")
        self.assertEqual(res.query_id, "q-1")

    def test_unknown_command_type_raises(self):
        bus, _ = _bus_with_echo()
        with self.assertRaises(m.UnknownCommandType):
            bus.dispatch_command(_cmd(ctype="delete"))

    def test_unknown_query_type_raises(self):
        bus, _ = _bus_with_echo()
        with self.assertRaises(m.UnknownQueryType):
            bus.dispatch_query(_qry(qtype="count"))

    def test_cross_type_command_refuses_query(self):
        bus, _ = _bus_with_echo()
        with self.assertRaises(TypeError):
            bus.dispatch_command(_qry())  # type: ignore[arg-type]

    def test_cross_type_query_refuses_command(self):
        bus, _ = _bus_with_echo()
        with self.assertRaises(TypeError):
            bus.dispatch_query(_cmd())  # type: ignore[arg-type]

    def test_leaking_command_handler_rejected(self):
        bus = m.CQRSBus()
        bus.register_command_handler("leak", lambda c: "data")  # noqa: ARG005
        with self.assertRaises(m.HandlerViolation):
            bus.dispatch_command(_cmd(ctype="leak"))

    def test_handler_exception_propagates_unwrapped(self):
        bus = m.CQRSBus()

        def boom(cmd):  # noqa: ARG001
            raise RuntimeError("handler blew up")

        bus.register_command_handler("boom", boom)
        with self.assertRaises(RuntimeError):
            bus.dispatch_command(_cmd(ctype="boom"))

    def test_duplicate_command_registration_refused(self):
        bus = m.CQRSBus()
        bus.register_command_handler("set", lambda c: None)
        with self.assertRaises(ValueError):
            bus.register_command_handler("set", lambda c: None)

    def test_duplicate_query_registration_refused(self):
        bus = m.CQRSBus()
        bus.register_query_handler("get", lambda q: None)
        with self.assertRaises(ValueError):
            bus.register_query_handler("get", lambda q: None)

    def test_non_callable_handler_rejected(self):
        bus = m.CQRSBus()
        with self.assertRaises(TypeError):
            bus.register_command_handler("set", "not-callable")  # type: ignore[arg-type]

    def test_same_name_in_both_registries(self):
        bus = m.CQRSBus()
        seen = []
        bus.register_command_handler("thing", lambda c: seen.append(("cmd", c)))
        bus.register_query_handler("thing", lambda q: seen.append(("qry", q)))
        bus.dispatch_command(_cmd(ctype="thing"))
        bus.dispatch_query(_qry(qtype="thing"))
        self.assertEqual([s[0] for s in seen], ["cmd", "qry"])

    def test_type_views_sorted(self):
        bus = m.CQRSBus()
        bus.register_command_handler("zebra", lambda c: None)
        bus.register_command_handler("apple", lambda c: None)
        self.assertEqual(bus.command_types(), ("apple", "zebra"))
        self.assertEqual(bus.query_types(), ())


class TestAuditEvent(unittest.TestCase):
    def test_command_audit_event_shape(self):
        ack = m.CommandResult(command_id="c-1", command_type="set",
                              accepted=True, seq=3)
        event = m.cqrs_audit_event(ack, 7)
        self.assertEqual(event["schema"], m.SCHEMA_PIN)
        self.assertEqual(event["audit_seq"], 7)
        self.assertEqual(event["kind"], "command-result")

    def test_query_audit_event_shape(self):
        res = m.QueryResult(query_id="q-1", query_type="get", data=1, seq=1)
        event = m.cqrs_audit_event(res, 2)
        self.assertEqual(event["kind"], "query-result")

    def test_bad_record_rejected(self):
        with self.assertRaises(TypeError):
            m.cqrs_audit_event("nope", 0)

    def test_bad_seq_rejected(self):
        ack = m.CommandResult(command_id="c-1", command_type="set",
                              accepted=True, seq=0)
        with self.assertRaises(ValueError):
            m.cqrs_audit_event(ack, -1)


class TestMain(unittest.TestCase):
    def test_main_self_check(self):
        m.main()


if __name__ == "__main__":
    unittest.main()
