"""Tests for leader_election: deterministic rule, lease expiry, elector state."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from leader_election import (
    Candidate,
    LeaderElector,
    LeaderLease,
    elect,
    leader_election_audit_event,
    LEADER_ELECTION_SCHEMA,
    LEADER_ELECTION_VERSION,
    EVENT_ELECTED,
)


class TestVersionPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(LEADER_ELECTION_VERSION, "leader-election.v1")

    def test_schema_pin(self):
        self.assertEqual(LEADER_ELECTION_SCHEMA, "northstar.leader-election.v1")


class TestCandidate(unittest.TestCase):
    def test_valid(self):
        c = Candidate(node_id="host-1", priority=3)
        self.assertEqual(c.node_id, "host-1")
        self.assertEqual(c.priority, 3)

    def test_frozen(self):
        c = Candidate(node_id="a", priority=1)
        with self.assertRaises(Exception):
            c.priority = 9  # type: ignore[misc]

    def test_empty_node_id_rejected(self):
        with self.assertRaises(ValueError):
            Candidate(node_id="   ", priority=1)

    def test_non_str_node_id_rejected(self):
        with self.assertRaises(TypeError):
            Candidate(node_id=7, priority=1)  # type: ignore[arg-type]

    def test_negative_priority_rejected(self):
        with self.assertRaises(ValueError):
            Candidate(node_id="a", priority=-1)

    def test_bool_priority_rejected(self):
        with self.assertRaises(TypeError):
            Candidate(node_id="a", priority=True)  # type: ignore[arg-type]

    def test_as_dict_schema(self):
        d = Candidate(node_id="a", priority=2).as_dict()
        self.assertEqual(d["schema"], LEADER_ELECTION_SCHEMA)
        self.assertEqual(d["version"], LEADER_ELECTION_VERSION)


class TestElect(unittest.TestCase):
    def test_highest_priority_wins(self):
        winner = elect(
            [Candidate(node_id="a", priority=1), Candidate(node_id="b", priority=9)]
        )
        self.assertEqual(winner.node_id, "b")

    def test_tie_breaks_on_lowest_node_id(self):
        winner = elect(
            [Candidate(node_id="zebra", priority=4), Candidate(node_id="apple", priority=4)]
        )
        self.assertEqual(winner.node_id, "apple")

    def test_single_candidate(self):
        winner = elect([Candidate(node_id="solo", priority=0)])
        self.assertEqual(winner.node_id, "solo")

    def test_empty_rejected(self):
        with self.assertRaises(ValueError):
            elect([])

    def test_duplicate_node_id_rejected(self):
        with self.assertRaises(ValueError):
            elect([Candidate(node_id="a", priority=1), Candidate(node_id="a", priority=2)])

    def test_non_candidate_rejected(self):
        with self.assertRaises(TypeError):
            elect(["a"])  # type: ignore[list-item]

    def test_non_iterable_rejected(self):
        with self.assertRaises(TypeError):
            elect("abc")  # type: ignore[arg-type]


class TestLeaderLease(unittest.TestCase):
    def test_valid(self):
        lease = LeaderLease(leader_id="b", term=3, expiry_seq=100)
        self.assertEqual(lease.term, 3)

    def test_not_expired_at_expiry(self):
        lease = LeaderLease(leader_id="b", term=1, expiry_seq=10)
        self.assertFalse(lease.is_expired(10))

    def test_expired_past_expiry(self):
        lease = LeaderLease(leader_id="b", term=1, expiry_seq=10)
        self.assertTrue(lease.is_expired(11))

    def test_zero_term_rejected(self):
        with self.assertRaises(ValueError):
            LeaderLease(leader_id="b", term=0, expiry_seq=10)

    def test_bool_seq_rejected(self):
        with self.assertRaises(TypeError):
            LeaderLease(leader_id="b", term=1, expiry_seq=True)  # type: ignore[arg-type]

    def test_malformed_current_seq_raises(self):
        lease = LeaderLease(leader_id="b", term=1, expiry_seq=10)
        with self.assertRaises(TypeError):
            lease.is_expired(-5.5)  # type: ignore[arg-type]

    def test_as_dict_shape(self):
        d = LeaderLease(leader_id="b", term=2, expiry_seq=50).as_dict()
        self.assertEqual(d["leader_id"], "b")
        self.assertEqual(d["schema"], LEADER_ELECTION_SCHEMA)


class TestLeaderElector(unittest.TestCase):
    def _elector(self):
        return LeaderElector(
            [Candidate(node_id="a", priority=1), Candidate(node_id="b", priority=5)]
        )

    def test_term_starts_zero(self):
        self.assertEqual(self._elector().term, 0)

    def test_elect_new_term_mints_lease(self):
        lease = self._elector().elect_new_term(term=1, lease_duration_seqs=10, current_seq=0)
        self.assertEqual(lease.leader_id, "b")
        self.assertEqual(lease.term, 1)
        self.assertEqual(lease.expiry_seq, 10)

    def test_term_must_advance(self):
        e = self._elector()
        e.elect_new_term(term=1, lease_duration_seqs=10, current_seq=0)
        with self.assertRaises(ValueError):
            e.elect_new_term(term=1, lease_duration_seqs=10, current_seq=11)
        with self.assertRaises(ValueError):
            e.elect_new_term(term=0, lease_duration_seqs=10, current_seq=11)

    def test_is_leader_true_while_live(self):
        e = self._elector()
        e.elect_new_term(term=1, lease_duration_seqs=10, current_seq=0)
        self.assertTrue(e.is_leader("b", current_seq=5))

    def test_is_leader_false_for_loser(self):
        e = self._elector()
        e.elect_new_term(term=1, lease_duration_seqs=10, current_seq=0)
        self.assertFalse(e.is_leader("a", current_seq=5))

    def test_is_leader_false_after_expiry(self):
        e = self._elector()
        e.elect_new_term(term=1, lease_duration_seqs=10, current_seq=0)
        self.assertFalse(e.is_leader("b", current_seq=11))

    def test_is_leader_never_raises_on_policy(self):
        e = self._elector()
        self.assertFalse(e.is_leader("", current_seq=5))
        self.assertFalse(e.is_leader("unknown", current_seq=-1))

    def test_renew_extends_expiry_same_term(self):
        e = self._elector()
        e.elect_new_term(term=1, lease_duration_seqs=10, current_seq=0)
        renewed = e.renew_lease(lease_duration_seqs=20, current_seq=5)
        self.assertEqual(renewed.term, 1)
        self.assertEqual(renewed.expiry_seq, 25)
        self.assertEqual(renewed.leader_id, "b")

    def test_renew_expired_fails(self):
        e = self._elector()
        e.elect_new_term(term=1, lease_duration_seqs=10, current_seq=0)
        with self.assertRaises(LookupError):
            e.renew_lease(lease_duration_seqs=10, current_seq=11)

    def test_renew_without_lease_fails(self):
        with self.assertRaises(LookupError):
            self._elector().renew_lease(lease_duration_seqs=10, current_seq=0)

    def test_add_candidate(self):
        e = self._elector()
        e.add_candidate(Candidate(node_id="c", priority=100))
        self.assertIn("c", e.candidate_ids())
        lease = e.elect_new_term(term=1, lease_duration_seqs=10, current_seq=0)
        self.assertEqual(lease.leader_id, "c")

    def test_add_duplicate_fails(self):
        e = self._elector()
        with self.assertRaises(ValueError):
            e.add_candidate(Candidate(node_id="a", priority=9))

    def test_remove_candidate(self):
        e = self._elector()
        e.remove_candidate("a")
        self.assertEqual(e.candidate_ids(), ("b",))

    def test_remove_leader_resigns_lease(self):
        e = self._elector()
        e.elect_new_term(term=1, lease_duration_seqs=10, current_seq=0)
        e.remove_candidate("b")
        self.assertIsNone(e.current_lease())
        self.assertFalse(e.is_leader("b", current_seq=5))

    def test_remove_unknown_raises_keyerror(self):
        with self.assertRaises(KeyError):
            self._elector().remove_candidate("ghost")

    def test_new_term_after_expiry_reelects(self):
        e = self._elector()
        e.elect_new_term(term=1, lease_duration_seqs=5, current_seq=0)
        lease2 = e.elect_new_term(term=2, lease_duration_seqs=5, current_seq=6)
        self.assertEqual(lease2.term, 2)
        self.assertTrue(e.is_leader(lease2.leader_id, current_seq=6))


class TestAuditEvent(unittest.TestCase):
    def test_elected_event_shape(self):
        lease = LeaderLease(leader_id="b", term=1, expiry_seq=10)
        ev = leader_election_audit_event(EVENT_ELECTED, lease, seq=7)
        self.assertEqual(ev["audit_seq"], 7)
        self.assertEqual(ev["event"], EVENT_ELECTED)
        self.assertEqual(ev["module"], LEADER_ELECTION_VERSION)
        self.assertEqual(ev["lease"]["leader_id"], "b")

    def test_none_lease_allowed(self):
        ev = leader_election_audit_event("leader-resigned", None, seq=8)
        self.assertIsNone(ev["lease"])

    def test_unknown_event_rejected(self):
        with self.assertRaises(ValueError):
            leader_election_audit_event("leader-coup", None, seq=1)

    def test_bad_seq_rejected(self):
        with self.assertRaises(TypeError):
            leader_election_audit_event(EVENT_ELECTED, None, seq=True)  # type: ignore[arg-type]


class TestMain(unittest.TestCase):
    def test_main_self_check(self):
        from leader_election import main

        main()  # raises on failure


if __name__ == "__main__":
    unittest.main()
