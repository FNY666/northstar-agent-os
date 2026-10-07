"""Tests for event_sourcing: append-only log, hash chain, replay."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from event_sourcing import (
    EVENT_SOURCING_VERSION,
    GENESIS_HEAD,
    SCHEMA_PIN,
    Event,
    EventSourcingError,
    EventStore,
    OutOfOrderAppend,
    ReplayError,
    event_audit_event,
    replay,
)


def _mk(seq, event_id=None, event_type="test.happened", payload=None,
        prev_head=GENESIS_HEAD):
    return Event(event_id or f"e{seq}", event_type,
                 payload if payload is not None else {"n": seq}, seq,
                 prev_head=prev_head)


class TestVersionPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(EVENT_SOURCING_VERSION, "event-sourcing.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.event-sourcing.v1")

    def test_genesis_head_shape(self):
        self.assertTrue(GENESIS_HEAD.startswith("sha256:"))
        self.assertEqual(len(GENESIS_HEAD), 71)


class TestEventConstruction(unittest.TestCase):
    def test_digest_deterministic(self):
        a = _mk(0)
        b = _mk(0)
        self.assertEqual(a.digest, b.digest)

    def test_digest_chains_prev_head(self):
        a = _mk(0)
        b = _mk(1, prev_head=a.digest)
        self.assertNotEqual(a.digest, b.digest)
        self.assertEqual(b.prev_head, a.digest)

    def test_frozen(self):
        e = _mk(0)
        with self.assertRaises(Exception):
            e.seq = 99  # type: ignore

    def test_verify_ok(self):
        self.assertTrue(_mk(3).verify())

    def test_as_dict_schema(self):
        d = _mk(0).as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertIn("digest", d)
        self.assertIn("prev_head", d)

    def test_empty_event_id_rejected(self):
        with self.assertRaises(ValueError):
            Event("", "t", {}, 0)

    def test_empty_event_type_rejected(self):
        with self.assertRaises(ValueError):
            Event("id", "", {}, 0)

    def test_non_mapping_payload_rejected(self):
        with self.assertRaises(TypeError):
            Event("id", "t", "nope", 0)

    def test_non_str_payload_key_rejected(self):
        with self.assertRaises(TypeError):
            Event("id", "t", {1: "x"}, 0)

    def test_non_canonicalizable_payload_rejected(self):
        with self.assertRaises(TypeError):
            Event("id", "t", {"f": object()}, 0)

    def test_negative_seq_rejected(self):
        with self.assertRaises(ValueError):
            Event("id", "t", {}, -1)

    def test_bool_seq_rejected(self):
        with self.assertRaises(TypeError):
            Event("id", "t", {}, True)

    def test_bad_prev_head_rejected(self):
        with self.assertRaises(ValueError):
            Event("id", "t", {}, 0, prev_head="nope")

    def test_payload_copied(self):
        p = {"n": 1}
        e = Event("id", "t", p, 0)
        p["n"] = 999
        self.assertEqual(e.payload["n"], 1)


class TestEventStore(unittest.TestCase):
    def test_append_and_len(self):
        s = EventStore()
        e0 = _mk(0)
        s.append(e0)
        self.assertEqual(len(s), 1)
        self.assertEqual(s.head(), e0.digest)

    def test_empty_head_is_genesis(self):
        self.assertEqual(EventStore().head(), GENESIS_HEAD)

    def test_append_returns_event(self):
        s = EventStore()
        e0 = _mk(0)
        self.assertIs(s.append(e0), e0)

    def test_chain_enforced(self):
        s = EventStore()
        e0 = _mk(0)
        s.append(e0)
        e1 = _mk(1, prev_head=e0.digest)
        s.append(e1)
        self.assertTrue(s.verify_chain())

    def test_duplicate_id_rejected(self):
        s = EventStore()
        s.append(_mk(0, event_id="dup"))
        with self.assertRaises(OutOfOrderAppend):
            s.append(_mk(1, event_id="dup", prev_head=s.head()))

    def test_non_monotonic_seq_rejected(self):
        s = EventStore()
        e0 = _mk(5)
        s.append(e0)
        with self.assertRaises(OutOfOrderAppend):
            s.append(_mk(5, event_id="eX", prev_head=e0.digest))
        with self.assertRaises(OutOfOrderAppend):
            s.append(_mk(3, event_id="eY", prev_head=e0.digest))
        self.assertEqual(len(s), 1)  # nothing appended

    def test_broken_chain_rejected(self):
        s = EventStore()
        e0 = _mk(0)
        s.append(e0)
        with self.assertRaises(OutOfOrderAppend):
            s.append(_mk(1, event_id="eX", prev_head=GENESIS_HEAD))
        self.assertEqual(len(s), 1)

    def test_first_event_must_chain_genesis(self):
        s = EventStore()
        with self.assertRaises(OutOfOrderAppend):
            s.append(_mk(0, prev_head="sha256:" + "f" * 64))

    def test_append_non_event_rejected(self):
        with self.assertRaises(TypeError):
            EventStore().append("not-an-event")

    def test_events_in_order(self):
        s = EventStore()
        evts = []
        prev = GENESIS_HEAD
        for i in range(4):
            e = _mk(i, prev_head=prev)
            prev = e.digest
            evts.append(e)
            s.append(e)
        self.assertEqual([e.seq for e in s.events()], [0, 1, 2, 3])

    def test_events_since(self):
        s = EventStore()
        prev = GENESIS_HEAD
        for i in range(3):
            e = _mk(i, prev_head=prev)
            prev = e.digest
            s.append(e)
        self.assertEqual([e.seq for e in s.events_since(0)], [1, 2])
        self.assertEqual(s.events_since(2), ())

    def test_events_of_type(self):
        s = EventStore()
        prev = GENESIS_HEAD
        e0 = _mk(0, event_type="a", prev_head=prev); prev = e0.digest
        e1 = _mk(1, event_type="b", prev_head=prev); prev = e1.digest
        e2 = _mk(2, event_type="a", prev_head=prev)
        for e in (e0, e1, e2):
            s.append(e)
        self.assertEqual([e.event_id for e in s.events_of_type("a")],
                         [e0.event_id, e2.event_id])

    def test_get(self):
        s = EventStore()
        e0 = _mk(0)
        s.append(e0)
        self.assertIs(s.get(e0.event_id), e0)
        with self.assertRaises(KeyError):
            s.get("missing")

    def test_verify_chain_detects_tamper(self):
        s = EventStore()
        e0 = _mk(0)
        s.append(e0)
        # Corrupt the stored event's payload in place (simulating tamper).
        object.__setattr__(e0, "payload", {"n": 999})
        self.assertFalse(s.verify_chain())


class TestReplay(unittest.TestCase):
    def _counter_handlers(self):
        def add(state, payload):
            return (state or 0) + payload["n"]
        return {"n.add": add}

    def test_replay_folds_in_order(self):
        evts = []
        prev = GENESIS_HEAD
        for i, n in enumerate([1, 2, 3]):
            e = _mk(i, event_type="n.add", payload={"n": n}, prev_head=prev)
            prev = e.digest
            evts.append(e)
        self.assertEqual(replay(evts, self._counter_handlers()), 6)

    def test_replay_normalizes_input_order(self):
        evts = []
        prev = GENESIS_HEAD
        for i, n in enumerate([1, 2, 3]):
            e = _mk(i, event_type="n.add", payload={"n": n}, prev_head=prev)
            prev = e.digest
            evts.append(e)
        self.assertEqual(replay(list(reversed(evts)),
                                self._counter_handlers()), 6)

    def test_replay_initial_state(self):
        e = _mk(0, event_type="n.add", payload={"n": 5})
        self.assertEqual(replay([e], self._counter_handlers(), initial=10), 15)

    def test_replay_empty(self):
        self.assertEqual(replay([], self._counter_handlers(), initial="s"), "s")

    def test_unknown_type_raises(self):
        e = _mk(0, event_type="mystery")
        with self.assertRaises(ReplayError):
            replay([e], self._counter_handlers())

    def test_duplicate_seq_raises(self):
        e0 = _mk(0, event_type="n.add", payload={"n": 1})
        e1 = _mk(0, event_id="other", event_type="n.add", payload={"n": 2})
        with self.assertRaises(ReplayError):
            replay([e0, e1], self._counter_handlers())

    def test_non_event_raises(self):
        with self.assertRaises(TypeError):
            replay(["x"], self._counter_handlers())

    def test_non_mapping_handlers_raises(self):
        with self.assertRaises(TypeError):
            replay([], ["not-a-mapping"])

    def test_non_callable_handler_raises(self):
        with self.assertRaises(TypeError):
            replay([_mk(0, event_type="n.add", payload={"n": 1})],
                   {"n.add": 42})

    def test_handler_exception_propagates(self):
        def boom(state, payload):
            raise RuntimeError("reducer blew up")
        with self.assertRaises(RuntimeError):
            replay([_mk(0, event_type="n.add", payload={"n": 1})],
                   {"n.add": boom})

    def test_handler_receives_payload_mapping(self):
        seen = []

        def rec(state, payload):
            seen.append(dict(payload))
            return state
        replay([_mk(0, event_type="n.add", payload={"n": 7})], {"n.add": rec})
        self.assertEqual(seen, [{"n": 7}])


class TestAuditEvent(unittest.TestCase):
    def test_appended_shape(self):
        e = _mk(0)
        a = event_audit_event(e, "appended", 4)
        self.assertEqual(a["schema"], "audit.ndjson/1")
        self.assertEqual(a["module"], SCHEMA_PIN)
        self.assertEqual(a["outcome"], "appended")
        self.assertEqual(a["event_digest"], e.digest)
        self.assertEqual(a["audit_seq"], 4)

    def test_all_outcomes(self):
        e = _mk(0)
        for outcome in ("appended", "replayed", "rejected"):
            self.assertEqual(event_audit_event(e, outcome, 0)["outcome"],
                             outcome)

    def test_bad_outcome_rejected(self):
        with self.assertRaises(ValueError):
            event_audit_event(_mk(0), "exploded", 0)

    def test_bad_seq_rejected(self):
        with self.assertRaises(TypeError):
            event_audit_event(_mk(0), "appended", True)

    def test_non_event_rejected(self):
        with self.assertRaises(TypeError):
            event_audit_event("x", "appended", 0)


if __name__ == "__main__":
    unittest.main()
