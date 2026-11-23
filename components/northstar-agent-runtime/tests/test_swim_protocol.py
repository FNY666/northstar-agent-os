"""Tests for swim_protocol.py (SWIM gossip-based membership)."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from swim_protocol import (
    GossipReceipt,
    MemberStatus,
    MembershipUpdate,
    ProbeOutcome,
    SWIM_PROTOCOL_SCHEMA,
    SWIM_PROTOCOL_VERSION,
    SwimError,
    SwimMember,
    SwimNode,
    swim_audit_event,
)


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(SWIM_PROTOCOL_VERSION, "swim-protocol.v1")

    def test_schema_pin(self):
        self.assertEqual(SWIM_PROTOCOL_SCHEMA, "northstar.swim-protocol.v1")


class TestRecords(unittest.TestCase):
    def test_member_frozen(self):
        m = SwimMember("n1", MemberStatus.ALIVE, 0, 1)
        with self.assertRaises(Exception):
            m.status = MemberStatus.FAILED  # type: ignore

    def test_member_validation(self):
        with self.assertRaises(ValueError):
            SwimMember("", MemberStatus.ALIVE, 0, 1)
        with self.assertRaises(TypeError):
            SwimMember("n1", MemberStatus.ALIVE, True, 1)
        with self.assertRaises(ValueError):
            SwimMember("n1", MemberStatus.ALIVE, -1, 1)
        with self.assertRaises(ValueError):
            SwimMember("n1", "bogus", 0, 1)

    def test_member_status_string_accepted(self):
        m = SwimMember("n1", "suspect", 2, 3)
        self.assertEqual(m.status, MemberStatus.SUSPECT)

    def test_update_defaults_gossip_count_zero(self):
        u = MembershipUpdate("n1", MemberStatus.ALIVE, 0, 1)
        self.assertEqual(u.gossip_count, 0)

    def test_probe_outcome_ack_must_be_bool(self):
        with self.assertRaises(TypeError):
            ProbeOutcome("n1", 1, MemberStatus.ALIVE, 1)  # type: ignore

    def test_receipt_validation(self):
        r = GossipReceipt(("n1",), (), False, 5)
        self.assertEqual(r.seq, 5)
        with self.assertRaises(TypeError):
            GossipReceipt(["n1"], (), False, 5)  # type: ignore


class TestMembership(unittest.TestCase):
    def setUp(self):
        self.node = SwimNode("n0")

    def test_add_member(self):
        m = self.node.add_member("n1", seq=1)
        self.assertEqual(m.status, MemberStatus.ALIVE)
        self.assertEqual(m.incarnation, 0)
        self.assertEqual(self.node.member_ids(), ("n1",))

    def test_add_self_rejected(self):
        with self.assertRaises(SwimError):
            self.node.add_member("n0", seq=1)

    def test_add_duplicate_rejected(self):
        self.node.add_member("n1", seq=1)
        with self.assertRaises(SwimError):
            self.node.add_member("n1", seq=2)

    def test_add_bad_seq(self):
        with self.assertRaises(TypeError):
            self.node.add_member("n1", seq=True)  # type: ignore
        with self.assertRaises(ValueError):
            self.node.add_member("n1", seq=-1)

    def test_constructor_validation(self):
        with self.assertRaises(ValueError):
            SwimNode("n0", indirect_probe_k=0)
        with self.assertRaises(ValueError):
            SwimNode("n0", suspect_timeout_seqs=0)
        with self.assertRaises(TypeError):
            SwimNode("n0", gossip_lambda=True)  # type: ignore

    def test_views(self):
        self.node.add_member("n1", seq=1)
        self.node.add_member("n2", seq=1)
        self.node.suspect("n1", seq=2)
        self.assertEqual(self.node.alive_members(), ("n2",))
        self.assertEqual(self.node.suspect_members(), ("n1",))
        self.assertEqual(self.node.failed_members(), ())


class TestProbing(unittest.TestCase):
    def setUp(self):
        self.node = SwimNode("n0", indirect_probe_k=2, suspect_timeout_seqs=3)
        self.node.add_member("n1", seq=1)
        self.node.add_member("n2", seq=1)

    def test_next_probe_target_round_robin(self):
        t1 = self.node.next_probe_target()
        t2 = self.node.next_probe_target()
        t3 = self.node.next_probe_target()
        self.assertEqual((t1, t2, t3), ("n1", "n2", "n1"))

    def test_next_probe_target_none_when_empty(self):
        empty = SwimNode("solo")
        self.assertIsNone(empty.next_probe_target())

    def test_probe_ack_keeps_alive(self):
        out = self.node.probe("n1", ack=True, seq=2)
        self.assertEqual(out.outcome, MemberStatus.ALIVE)
        self.assertEqual(self.node.alive_members(), ("n1", "n2"))

    def test_probe_noack_suspects(self):
        out = self.node.probe("n1", ack=False, seq=2)
        self.assertEqual(out.outcome, MemberStatus.SUSPECT)
        self.assertEqual(self.node.suspect_members(), ("n1",))

    def test_probe_unknown_member(self):
        with self.assertRaises(SwimError):
            self.node.probe("ghost", ack=True, seq=2)

    def test_probe_failed_member_rejected(self):
        self.node.probe("n1", ack=False, seq=2)
        self.node.confirm_failed("n1", seq=5)
        with self.assertRaises(SwimError):
            self.node.probe("n1", ack=True, seq=6)

    def test_indirect_probe_ack_clears(self):
        self.node.probe("n1", ack=False, seq=2)
        out = self.node.probe_indirect("n1", ["n2"], ack=True, seq=3)
        self.assertEqual(out.outcome, MemberStatus.ALIVE)
        self.assertEqual(self.node.suspect_members(), ())

    def test_indirect_probe_noack_suspects(self):
        out = self.node.probe_indirect("n1", ["n2"], ack=False, seq=2)
        self.assertEqual(out.outcome, MemberStatus.SUSPECT)

    def test_indirect_too_many_probers(self):
        with self.assertRaises(SwimError):
            self.node.probe_indirect("n1", ["n2", "n3", "n4"], ack=True, seq=2)

    def test_indirect_self_or_target_as_prober(self):
        with self.assertRaises(SwimError):
            self.node.probe_indirect("n1", ["n0"], ack=True, seq=2)
        with self.assertRaises(SwimError):
            self.node.probe_indirect("n1", ["n1"], ack=True, seq=2)

    def test_suspect_direct(self):
        m = self.node.suspect("n1", seq=4)
        self.assertEqual(m.status, MemberStatus.SUSPECT)

    def test_suspect_failed_rejected(self):
        self.node.probe("n1", ack=False, seq=2)
        self.node.confirm_failed("n1", seq=5)
        with self.assertRaises(SwimError):
            self.node.suspect("n1", seq=6)


class TestFailureConfirmation(unittest.TestCase):
    def setUp(self):
        self.node = SwimNode("n0", suspect_timeout_seqs=3)
        self.node.add_member("n1", seq=1)

    def test_confirm_before_timeout_refused(self):
        self.node.suspect("n1", seq=2)
        with self.assertRaises(SwimError):
            self.node.confirm_failed("n1", seq=4)  # need >= 2+3

    def test_confirm_at_timeout_boundary(self):
        self.node.suspect("n1", seq=2)
        m = self.node.confirm_failed("n1", seq=5)
        self.assertEqual(m.status, MemberStatus.FAILED)
        self.assertEqual(self.node.failed_members(), ("n1",))

    def test_confirm_alive_rejected(self):
        with self.assertRaises(SwimError):
            self.node.confirm_failed("n1", seq=10)

    def test_confirm_unknown_rejected(self):
        with self.assertRaises(SwimError):
            self.node.confirm_failed("ghost", seq=10)


class TestRefutation(unittest.TestCase):
    def test_refute_self_bumps_incarnation(self):
        node = SwimNode("n0")
        u1 = node.refute_self(seq=1)
        self.assertEqual(u1.incarnation, 1)
        self.assertEqual(u1.status, MemberStatus.ALIVE)
        u2 = node.refute_self(seq=2)
        self.assertEqual(u2.incarnation, 2)


class TestGossipMerge(unittest.TestCase):
    def setUp(self):
        self.node = SwimNode("n0")
        self.node.add_member("n1", seq=1)

    def test_higher_incarnation_wins(self):
        r = self.node.receive_gossip(
            [MembershipUpdate("n1", MemberStatus.SUSPECT, 5, 2)], seq=3
        )
        self.assertEqual(r.applied, ("n1",))
        self.assertEqual(self.node.get("n1").status, MemberStatus.SUSPECT)

    def test_lower_incarnation_ignored(self):
        self.node.receive_gossip(
            [MembershipUpdate("n1", MemberStatus.SUSPECT, 5, 2)], seq=3
        )
        r = self.node.receive_gossip(
            [MembershipUpdate("n1", MemberStatus.FAILED, 4, 4)], seq=5
        )
        self.assertEqual(r.ignored, ("n1",))
        self.assertEqual(self.node.get("n1").status, MemberStatus.SUSPECT)

    def test_equal_incarnation_severity_wins(self):
        # suspect beats alive at equal incarnation
        r = self.node.receive_gossip(
            [MembershipUpdate("n1", MemberStatus.SUSPECT, 0, 2)], seq=3
        )
        self.assertEqual(r.applied, ("n1",))
        # alive does NOT beat suspect at equal incarnation (needs refute)
        r = self.node.receive_gossip(
            [MembershipUpdate("n1", MemberStatus.ALIVE, 0, 4)], seq=5
        )
        self.assertEqual(r.ignored, ("n1",))
        self.assertEqual(self.node.get("n1").status, MemberStatus.SUSPECT)

    def test_refute_via_higher_incarnation(self):
        self.node.receive_gossip(
            [MembershipUpdate("n1", MemberStatus.SUSPECT, 0, 2)], seq=3
        )
        r = self.node.receive_gossip(
            [MembershipUpdate("n1", MemberStatus.ALIVE, 1, 4)], seq=5
        )
        self.assertEqual(r.applied, ("n1",))
        self.assertEqual(self.node.get("n1").status, MemberStatus.ALIVE)

    def test_unknown_member_joins(self):
        r = self.node.receive_gossip(
            [MembershipUpdate("n9", MemberStatus.ALIVE, 0, 2)], seq=3
        )
        self.assertEqual(r.applied, ("n9",))
        self.assertIn("n9", self.node.member_ids())

    def test_self_suspected_flag(self):
        r = self.node.receive_gossip(
            [MembershipUpdate("n0", MemberStatus.SUSPECT, 0, 2)], seq=3
        )
        self.assertTrue(r.self_suspected)
        self.assertEqual(r.ignored, ("n0",))

    def test_mapping_update_accepted(self):
        r = self.node.receive_gossip(
            [{
                "node_id": "n1",
                "status": "suspect",
                "incarnation": 0,
                "origin_seq": 2,
            }],
            seq=3,
        )
        self.assertEqual(r.applied, ("n1",))

    def test_bad_update_type(self):
        with self.assertRaises(TypeError):
            self.node.receive_gossip(["nope"], seq=3)  # type: ignore

    def test_new_news_resets_gossip_budget(self):
        self.node.receive_gossip(
            [MembershipUpdate("n1", MemberStatus.SUSPECT, 0, 2)], seq=3
        )
        piggy = self.node.disseminate(seq=4)
        n1_updates = [u for u in piggy if u.node_id == "n1"]
        self.assertTrue(n1_updates)
        self.assertEqual(n1_updates[0].gossip_count, 1)


class TestDissemination(unittest.TestCase):
    def test_piggyback_limit(self):
        node = SwimNode("n0", piggyback_limit=2)
        for i in range(1, 5):
            node.add_member(f"n{i}", seq=1)
        piggy = node.disseminate(seq=2)
        self.assertLessEqual(len(piggy), 2)

    def test_gossip_budget_exhausts(self):
        node = SwimNode("n0", gossip_lambda=1, piggyback_limit=10)
        node.add_member("n1", seq=1)
        seen = 0
        for s in range(2, 40):
            piggy = node.disseminate(seq=s)
            if any(u.node_id == "n1" for u in piggy):
                seen += 1
        # budget = ceil(1 * log2(2)) = 1 for n=2 members total
        self.assertEqual(seen, 1)

    def test_disseminate_deterministic_order(self):
        node = SwimNode("n0", piggyback_limit=10)
        node.add_member("n2", seq=1)
        node.add_member("n1", seq=1)
        piggy = node.disseminate(seq=2)
        ids = [u.node_id for u in piggy]
        self.assertEqual(ids, sorted(ids))


class TestDigest(unittest.TestCase):
    def test_digest_deterministic(self):
        a = SwimNode("n0")
        b = SwimNode("n0")
        for n in (a, b):
            n.add_member("n1", seq=1)
            n.suspect("n1", seq=2)
        self.assertEqual(a.membership_digest(), b.membership_digest())

    def test_digest_changes_on_state_change(self):
        node = SwimNode("n0")
        node.add_member("n1", seq=1)
        d1 = node.membership_digest()
        node.suspect("n1", seq=2)
        self.assertNotEqual(d1, node.membership_digest())


class TestAudit(unittest.TestCase):
    def test_audit_event_shape(self):
        ev = swim_audit_event("suspected", "n1", 7, "no ack")
        self.assertEqual(ev["event"], "audit.ndjson/1")
        self.assertEqual(ev["kind"], "suspected")
        self.assertEqual(ev["schema"], SWIM_PROTOCOL_SCHEMA)

    def test_audit_bad_kind(self):
        with self.assertRaises(ValueError):
            swim_audit_event("bogus", "n1", 1)

    def test_audit_bad_seq(self):
        with self.assertRaises(TypeError):
            swim_audit_event("suspected", "n1", True)  # type: ignore


if __name__ == "__main__":
    unittest.main()
