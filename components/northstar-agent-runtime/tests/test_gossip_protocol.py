"""Tests for gossip_protocol: deterministic probabilistic rumor dissemination."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from gossip_protocol import (
    EVENT_RECEIVED,
    EVENT_ROUND,
    EVENT_SPREAD,
    GOSSIP_PROTOCOL_SCHEMA,
    GOSSIP_PROTOCOL_VERSION,
    GossipError,
    GossipNetwork,
    GossipNode,
    GossipRound,
    Rumor,
    gossip_audit_event,
    main,
)


def _rumor(rid="r1", origin="n0", seq=1, payload=None):
    return Rumor(
        rumor_id=rid,
        payload=payload if payload is not None else {"k": "v"},
        origin=origin,
        seq=seq,
    )


def _node(nid, peers, **kw):
    return GossipNode(nid, peers, **kw)


class TestPins(unittest.TestCase):
    def test_version_and_schema_pins(self):
        self.assertEqual(GOSSIP_PROTOCOL_VERSION, "gossip-protocol.v1")
        self.assertEqual(GOSSIP_PROTOCOL_SCHEMA, "northstar.gossip-protocol.v1")


class TestRumor(unittest.TestCase):
    def test_digest_roundtrip(self):
        r = _rumor()
        self.assertTrue(r.verify_digest(r.digest()))
        self.assertTrue(r.digest().startswith("sha256:"))

    def test_digest_binds_payload(self):
        r1 = _rumor(payload={"a": 1})
        r2 = _rumor(payload={"a": 2})
        self.assertNotEqual(r1.digest(), r2.digest())

    def test_digest_key_order_invariant(self):
        r1 = _rumor(payload={"a": 1, "b": 2})
        r2 = _rumor(payload={"b": 2, "a": 1})
        self.assertEqual(r1.digest(), r2.digest())

    def test_frozen(self):
        r = _rumor()
        with self.assertRaises(AttributeError):
            r.rumor_id = "x"  # type: ignore

    def test_validation(self):
        with self.assertRaises(ValueError):
            _rumor(rid="")
        with self.assertRaises(ValueError):
            _rumor(origin="")
        with self.assertRaises((TypeError, ValueError)):
            _rumor(seq=-1)
        with self.assertRaises(TypeError):
            _rumor(seq=True)
        with self.assertRaises(TypeError):
            Rumor(rumor_id="r", payload=[1], origin="n0", seq=0)
        with self.assertRaises(ValueError):
            _rumor(payload={"k": float("nan")})

    def test_as_dict_shape(self):
        d = _rumor().as_dict()
        self.assertEqual(d["schema"], GOSSIP_PROTOCOL_SCHEMA)
        self.assertEqual(d["version"], GOSSIP_PROTOCOL_VERSION)
        self.assertIn("digest", d)


class TestGossipNode(unittest.TestCase):
    def test_receive_new_and_duplicate(self):
        n = _node("n0", ["n1"])
        self.assertTrue(n.receive(_rumor()))
        self.assertFalse(n.receive(_rumor()))
        self.assertEqual(n.infected_count(), 1)

    def test_receive_rejects_non_rumor(self):
        n = _node("n0", ["n1"])
        with self.assertRaises(TypeError):
            n.receive("not-a-rumor")

    def test_constructor_validation(self):
        with self.assertRaises(ValueError):
            _node("", ["n1"])
        with self.assertRaises(TypeError):
            _node("n0", ["n1"], fanout=True)
        with self.assertRaises(ValueError):
            _node("n0", ["n1"], fanout=0)
        with self.assertRaises(ValueError):
            _node("n0", ["n1"], probability=1.5)
        with self.assertRaises(ValueError):
            _node("n0", ["n1"], probability=-0.1)
        with self.assertRaises(ValueError):
            _node("n0", ["n1", "n1"])

    def test_self_excluded_from_peers(self):
        n = _node("n0", ["n0", "n1", "n2"])
        self.assertEqual(n.peers, ("n1", "n2"))

    def test_spread_deterministic(self):
        n1 = _node("n0", ["n1", "n2", "n3"])
        n2 = _node("n0", ["n1", "n2", "n3"])
        self.assertEqual(n1.spread(_rumor(), 7), n2.spread(_rumor(), 7))

    def test_spread_respects_fanout(self):
        n = _node("n0", [f"n{i}" for i in range(1, 11)], fanout=2, probability=1.0)
        self.assertEqual(len(n.spread(_rumor(), 0)), 2)

    def test_spread_probability_zero(self):
        n = _node("n0", ["n1", "n2"], probability=0.0)
        self.assertEqual(n.spread(_rumor(), 0), ())

    def test_spread_probability_one_selects_up_to_fanout(self):
        peers = [f"n{i}" for i in range(1, 6)]
        n = _node("n0", peers, fanout=10, probability=1.0)
        # all peers selected (probability=1.0), order is draw-ordered not sorted
        self.assertEqual(set(n.spread(_rumor(), 3)), set(peers))
        self.assertEqual(len(n.spread(_rumor(), 3)), len(peers))

    def test_spread_different_rounds_may_differ(self):
        n = _node("n0", [f"n{i}" for i in range(1, 6)], fanout=1, probability=0.5)
        selections = {n.spread(_rumor(), r) for r in range(20)}
        # not strictly guaranteed, but overwhelmingly likely with 20 rounds
        self.assertGreater(len(selections), 1)

    def test_has_seen(self):
        n = _node("n0", ["n1"])
        self.assertFalse(n.has_seen("r1"))
        n.receive(_rumor())
        self.assertTrue(n.has_seen("r1"))


class TestGossipNetwork(unittest.TestCase):
    def _clique(self, size=5, **kw):
        ids = [f"n{i}" for i in range(size)]
        nodes = [_node(i, [j for j in ids if j != i], **kw) for i in ids]
        return GossipNetwork(nodes)

    def test_broadcast_seeds_origin(self):
        net = self._clique()
        net.broadcast("n0", _rumor(), 0)
        self.assertEqual(net.infected_by("r1"), ("n0",))

    def test_broadcast_origin_mismatch(self):
        net = self._clique()
        with self.assertRaises(GossipError):
            net.broadcast("n1", _rumor(origin="n0"), 0)

    def test_converges_on_clique(self):
        net = self._clique()
        net.broadcast("n0", _rumor(), 0)
        rounds = 0
        while not net.converged("r1") and rounds < 20:
            report = net.step(rounds)
            rounds += 1
        self.assertTrue(net.converged("r1"))
        self.assertIsInstance(report, GossipRound)
        self.assertEqual(report.round_seq, rounds - 1)

    def test_partition_never_converges(self):
        # two disconnected cliques: gossip cannot cross the gap
        a = [_node(f"a{i}", [f"a{j}" for j in range(3) if j != i]) for i in range(3)]
        b = [_node(f"b{i}", [f"b{j}" for j in range(3) if j != i]) for i in range(3)]
        net = GossipNetwork(a + b)
        net.broadcast("a0", _rumor(origin="a0"), 0)
        for r in range(10):
            net.step(r)
        self.assertFalse(net.converged("r1"))
        self.assertEqual(net.infected_by("r1"), ("a0", "a1", "a2"))

    def test_duplicate_delivery_no_double_count(self):
        net = self._clique()
        net.broadcast("n0", _rumor(), 0)
        net.step(0)
        counts = {nid: net.node(nid).infected_count() for nid in net.node_ids()}
        self.assertTrue(all(c <= 1 for c in counts.values()))

    def test_network_validation(self):
        with self.assertRaises(ValueError):
            GossipNetwork([])
        with self.assertRaises(ValueError):
            GossipNetwork([_node("n0", []), _node("n0", [])])
        net = self._clique()
        with self.assertRaises(KeyError):
            net.node("nope")

    def test_round_report_order_deterministic(self):
        net1 = self._clique()
        net2 = self._clique()
        for net in (net1, net2):
            net.broadcast("n0", _rumor(), 0)
        self.assertEqual(net1.step(0).newly_informed, net2.step(0).newly_informed)


class TestAuditEvents(unittest.TestCase):
    def test_received_event_shape(self):
        ev = gossip_audit_event(EVENT_RECEIVED, node_id="n0", rumor_id="r1", seq=5)
        self.assertEqual(ev["audit"], "audit.ndjson/1")
        self.assertEqual(ev["kind"], EVENT_RECEIVED)
        self.assertEqual(ev["audit_seq"], 5)

    def test_spread_and_round_events(self):
        ev = gossip_audit_event(
            EVENT_SPREAD, node_id="n0", rumor_id="r1", seq=1, detail={"peers": ["n1"]}
        )
        self.assertEqual(ev["detail"], {"peers": ["n1"]})
        ev2 = gossip_audit_event(EVENT_ROUND, node_id="n0", rumor_id="r1", seq=2)
        self.assertEqual(ev2["detail"], {})

    def test_bad_kind_rejected(self):
        with self.assertRaises(ValueError):
            gossip_audit_event("nope", node_id="n0", rumor_id="r1", seq=0)

    def test_bad_seq_rejected(self):
        with self.assertRaises((TypeError, ValueError)):
            gossip_audit_event(EVENT_RECEIVED, node_id="n0", rumor_id="r1", seq=-1)


class TestMain(unittest.TestCase):
    def test_main_self_check(self):
        main()


if __name__ == "__main__":
    unittest.main()
