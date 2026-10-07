"""Tests for zab_interface.py."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from zab_interface import (
    EVENT_ACKED,
    EVENT_COMMITTED,
    EVENT_COMMIT_REFUSED,
    EVENT_PROPOSED,
    ROLE_FOLLOWER,
    ROLE_LEADER,
    ZAB_INTERFACE_SCHEMA,
    ZAB_INTERFACE_VERSION,
    EpochRegressionError,
    ZabAck,
    ZabCommitRecord,
    ZabError,
    ZabNode,
    ZabProposal,
    ZxidOrderError,
    compare_zxid,
    make_zxid,
    pin_value,
    quorum_size,
    zab_audit_event,
    zxid_counter,
    zxid_epoch,
)


class TestZxidEncoding(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(ZAB_INTERFACE_VERSION, "zab-interface.v1")
        self.assertEqual(ZAB_INTERFACE_SCHEMA, "northstar.zab-interface.v1")

    def test_make_zxid_layout(self):
        z = make_zxid(3, 7)
        self.assertEqual(zxid_epoch(z), 3)
        self.assertEqual(zxid_counter(z), 7)
        self.assertEqual(z, (3 << 32) | 7)

    def test_epoch_orders_before_counter(self):
        a = make_zxid(1, 0xFFFFFFFF)
        b = make_zxid(2, 0)
        self.assertEqual(compare_zxid(a, b), -1)
        self.assertEqual(compare_zxid(b, a), 1)
        self.assertEqual(compare_zxid(a, a), 0)

    def test_bad_epoch(self):
        with self.assertRaises(TypeError):
            make_zxid(True, 0)
        with self.assertRaises(ValueError):
            make_zxid(-1, 0)
        with self.assertRaises(ValueError):
            make_zxid(2**32, 0)

    def test_bad_counter(self):
        with self.assertRaises(TypeError):
            make_zxid(0, "1")
        with self.assertRaises(ValueError):
            make_zxid(0, 2**32)

    def test_quorum_size(self):
        self.assertEqual(quorum_size(1), 1)
        self.assertEqual(quorum_size(3), 2)
        self.assertEqual(quorum_size(4), 3)
        with self.assertRaises(ValueError):
            quorum_size(0)


class TestZabNode(unittest.TestCase):
    def test_leader_propose_sequence(self):
        leader = ZabNode("n0", ROLE_LEADER, epoch=1, followers=["n1"])
        p0 = leader.propose({"a": 1}, seq=0)
        p1 = leader.propose({"a": 2}, seq=1)
        self.assertEqual(zxid_counter(p0.zxid), 0)
        self.assertEqual(zxid_counter(p1.zxid), 1)
        self.assertEqual(compare_zxid(p0.zxid, p1.zxid), -1)

    def test_value_pinned_not_stored(self):
        leader = ZabNode("n0", ROLE_LEADER, followers=["n1"])
        p = leader.propose({"secret": "x"}, seq=0)
        self.assertTrue(p.value_digest.startswith("sha256:"))
        self.assertNotIn("secret", p.as_dict()["value_digest"])

    def test_pin_value_deterministic(self):
        self.assertEqual(pin_value({"b": 1, "a": 2}), pin_value({"a": 2, "b": 1}))

    def test_epoch_regression_refused(self):
        leader = ZabNode("n0", ROLE_LEADER, epoch=5, followers=["n1"])
        with self.assertRaises(EpochRegressionError):
            leader.set_epoch(4, seq=0)

    def test_epoch_advance_resets_counter(self):
        leader = ZabNode("n0", ROLE_LEADER, epoch=1, followers=["n1"])
        leader.propose("v", seq=0)
        leader.set_epoch(2, seq=1)
        p = leader.propose("v2", seq=2)
        self.assertEqual(zxid_epoch(p.zxid), 2)
        self.assertEqual(zxid_counter(p.zxid), 0)

    def test_follower_cannot_propose(self):
        f = ZabNode("n1", ROLE_FOLLOWER)
        with self.assertRaises(ZabError):
            f.propose("v", seq=0)

    def test_leader_cannot_ack(self):
        leader = ZabNode("n0", ROLE_LEADER, followers=["n1"])
        with self.assertRaises(ZabError):
            leader.ack(make_zxid(0, 0), seq=0)

    def test_follower_ordering_enforced(self):
        f = ZabNode("n1", ROLE_FOLLOWER)
        p = ZabProposal(
            zxid=make_zxid(0, 5), value_digest=pin_value("v"),
            leader_id="n0", proposed_seq=0,
        )
        f.receive_proposal(p)
        with self.assertRaises(ZxidOrderError):
            f.receive_proposal(p)  # duplicate
        older = ZabProposal(
            zxid=make_zxid(0, 3), value_digest=pin_value("w"),
            leader_id="n0", proposed_seq=1,
        )
        with self.assertRaises(ZxidOrderError):
            f.receive_proposal(older)  # rewind

    def test_ack_only_received(self):
        f = ZabNode("n1", ROLE_FOLLOWER)
        with self.assertRaises(ZxidOrderError):
            f.ack(make_zxid(0, 9), seq=0)

    def test_quorum_commit_flow(self):
        leader = ZabNode("n0", ROLE_LEADER, followers=["n1", "n2", "n3"])
        p = leader.propose("cfg", seq=0)
        self.assertIsNone(leader.commit(p.zxid, seq=1))  # no acks yet
        for i, fid in enumerate(["n1", "n2"]):
            f = ZabNode(fid, ROLE_FOLLOWER)
            f.receive_proposal(p)
            leader.receive_ack(f.ack(p.zxid, seq=i + 2))
        self.assertTrue(leader.commit_ready(p.zxid))
        rec = leader.commit(p.zxid, seq=5)
        self.assertIsInstance(rec, ZabCommitRecord)
        self.assertEqual(rec.zxid, p.zxid)
        self.assertEqual(rec.quorum, 2)
        # idempotent
        self.assertEqual(leader.commit(p.zxid, seq=6), rec)

    def test_duplicate_ack_refused(self):
        leader = ZabNode("n0", ROLE_LEADER, followers=["n1"])
        p = leader.propose("cfg", seq=0)
        f = ZabNode("n1", ROLE_FOLLOWER)
        f.receive_proposal(p)
        leader.receive_ack(f.ack(p.zxid, seq=1))
        with self.assertRaises(ZabError):
            leader.receive_ack(ZabAck(zxid=p.zxid, follower_id="n1", ack_seq=2))

    def test_unknown_follower_ack_refused(self):
        leader = ZabNode("n0", ROLE_LEADER, followers=["n1"])
        p = leader.propose("cfg", seq=0)
        with self.assertRaises(ZabError):
            leader.receive_ack(ZabAck(zxid=p.zxid, follower_id="nX", ack_seq=1))

    def test_follower_commit(self):
        f = ZabNode("n1", ROLE_FOLLOWER)
        p = ZabProposal(
            zxid=make_zxid(2, 0), value_digest=pin_value("v"),
            leader_id="n0", proposed_seq=0,
        )
        f.receive_proposal(p)
        rec = f.commit(p.zxid, seq=1)
        self.assertEqual(rec.zxid, p.zxid)
        with self.assertRaises(ZxidOrderError):
            f.commit(make_zxid(2, 1), seq=2)  # never received

    def test_frozen_records(self):
        leader = ZabNode("n0", ROLE_LEADER, followers=["n1"])
        p = leader.propose("v", seq=0)
        with self.assertRaises(Exception):
            p.zxid = 0  # frozen

    def test_audit_events(self):
        leader = ZabNode("n0", ROLE_LEADER, followers=["n1"])
        p = leader.propose("v", seq=0)
        ev = zab_audit_event(EVENT_PROPOSED, p, seq=1)
        self.assertEqual(ev["kind"], EVENT_PROPOSED)
        self.assertEqual(ev["schema"], ZAB_INTERFACE_SCHEMA)
        with self.assertRaises(ValueError):
            zab_audit_event("bogus-kind", p, seq=1)

    def test_all_event_kinds_valid(self):
        leader = ZabNode("n0", ROLE_LEADER, followers=["n1"])
        p = leader.propose("v", seq=0)
        for kind in (EVENT_PROPOSED, EVENT_ACKED, EVENT_COMMITTED,
                     EVENT_COMMIT_REFUSED):
            ev = zab_audit_event(kind, p, seq=0)
            self.assertEqual(ev["kind"], kind)

    def test_bad_role(self):
        with self.assertRaises(ValueError):
            ZabNode("n0", "candidate")

    def test_main_self_check(self):
        import zab_interface
        zab_interface.main()  # must not raise


if __name__ == "__main__":
    unittest.main()
