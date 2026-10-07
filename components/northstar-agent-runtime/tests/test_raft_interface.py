"""Tests for raft_interface.py."""

import hashlib
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import raft_interface as ri


def _vote_req(candidate="c1", term=1, lli=0, llt=0, seq=1):
    return ri.VoteRequest(
        candidate_id=candidate, term=term, last_log_index=lli,
        last_log_term=llt, seq=seq,
    )


def _ae_req(leader="l1", term=1, pli=0, plt=0, entries=(), commit=0, seq=1):
    return ri.AppendEntriesRequest(
        leader_id=leader, term=term, prev_log_index=pli, prev_log_term=plt,
        entries=entries, leader_commit=commit, seq=seq,
    )


def _entry(term=1, index=1, payload=None):
    return ri.LogEntry(
        term=term, index=index,
        payload_digest=ri._payload_digest(payload or {"op": "set"}),
    )


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(ri.RAFT_INTERFACE_VERSION, "raft-interface.v1")
        self.assertEqual(ri.RAFT_INTERFACE_SCHEMA, "northstar.raft-interface.v1")

    def test_state_values(self):
        self.assertEqual({s.value for s in ri.State}, {"follower", "candidate", "leader"})


class TestRecords(unittest.TestCase):
    def test_log_entry_frozen(self):
        e = _entry()
        with self.assertRaises(Exception):
            e.term = 2  # type: ignore

    def test_log_entry_validation(self):
        with self.assertRaises(TypeError):
            ri.LogEntry(term=True, index=1, payload_digest="sha256:" + "a" * 64)
        with self.assertRaises(ValueError):
            ri.LogEntry(term=1, index=0, payload_digest="sha256:" + "a" * 64)
        with self.assertRaises(ValueError):
            ri.LogEntry(term=1, index=1, payload_digest="bad")
        with self.assertRaises(ValueError):
            ri.LogEntry(term=1, index=1, payload_digest="sha256:" + "a" * 64, schema="x")

    def test_vote_request_schema_pin(self):
        with self.assertRaises(ValueError):
            ri.VoteRequest(candidate_id="c", term=1, last_log_index=0,
                           last_log_term=0, seq=1, schema="nope")

    def test_append_entries_entry_type(self):
        with self.assertRaises(TypeError):
            _ae_req(entries=("not-an-entry",))

    def test_append_entries_frozen(self):
        d = _ae_req().as_dict()
        self.assertEqual(d["schema"], ri.RAFT_INTERFACE_SCHEMA)
        self.assertEqual(d["entries"], [])


class TestNode(unittest.TestCase):
    def test_initial_state(self):
        n = ri.RaftNode("n1", 3)
        self.assertEqual(n.state, ri.State.FOLLOWER)
        self.assertEqual(n.current_term, 0)
        self.assertIsNone(n.voted_for)
        self.assertEqual(n.quorum, 2)
        self.assertEqual(n.last_log_index(), 0)
        self.assertEqual(n.last_log_term(), 0)

    def test_constructor_validation(self):
        with self.assertRaises(ValueError):
            ri.RaftNode("", 3)
        with self.assertRaises(TypeError):
            ri.RaftNode("n", True)
        with self.assertRaises(ValueError):
            ri.RaftNode("n", 0)

    def test_quorum_math(self):
        self.assertEqual(ri.RaftNode("n", 1).quorum, 1)
        self.assertEqual(ri.RaftNode("n", 4).quorum, 3)
        self.assertEqual(ri.RaftNode("n", 5).quorum, 3)


class TestVote(unittest.TestCase):
    def test_grant_first_vote(self):
        n = ri.RaftNode("n1", 3)
        r = n.request_vote(_vote_req(term=1, seq=1))
        self.assertTrue(r.vote_granted)
        self.assertEqual(r.term, 1)
        self.assertEqual(n.voted_for, "c1")

    def test_deny_double_vote(self):
        n = ri.RaftNode("n1", 3)
        n.request_vote(_vote_req(candidate="c1", term=1, seq=1))
        r = n.request_vote(_vote_req(candidate="c2", term=1, seq=2))
        self.assertFalse(r.vote_granted)

    def test_same_candidate_revote_granted(self):
        n = ri.RaftNode("n1", 3)
        n.request_vote(_vote_req(candidate="c1", term=1, seq=1))
        r = n.request_vote(_vote_req(candidate="c1", term=1, seq=2))
        self.assertTrue(r.vote_granted)

    def test_stale_term_denied(self):
        n = ri.RaftNode("n1", 3)
        n.request_vote(_vote_req(candidate="c1", term=2, seq=1))
        r = n.request_vote(_vote_req(candidate="c2", term=1, seq=2))
        self.assertFalse(r.vote_granted)
        self.assertEqual(r.term, 2)

    def test_higher_term_resets_vote(self):
        n = ri.RaftNode("n1", 3)
        n.request_vote(_vote_req(candidate="c1", term=1, seq=1))
        r = n.request_vote(_vote_req(candidate="c2", term=2, seq=2))
        self.assertTrue(r.vote_granted)
        self.assertEqual(n.voted_for, "c2")

    def test_stale_log_denied(self):
        n = ri.RaftNode("n1", 3)
        n._log.append(_entry(term=2, index=1))
        n._term = 2
        r = n.request_vote(_vote_req(candidate="c1", term=2, lli=0, llt=0, seq=1))
        self.assertFalse(r.vote_granted)

    def test_up_to_date_log_granted(self):
        n = ri.RaftNode("n1", 3)
        n._log.append(_entry(term=1, index=1))
        n._term = 1
        r = n.request_vote(_vote_req(candidate="c1", term=1, lli=1, llt=1, seq=1))
        self.assertTrue(r.vote_granted)

    def test_vote_bad_type(self):
        n = ri.RaftNode("n1", 3)
        with self.assertRaises(TypeError):
            n.request_vote("nope")  # type: ignore


class TestAppendEntries(unittest.TestCase):
    def test_heartbeat_ok(self):
        n = ri.RaftNode("n1", 3)
        r = n.append_entries(_ae_req(term=1, seq=1))
        self.assertTrue(r.success)
        self.assertEqual(r.term, 1)

    def test_stale_term_rejected(self):
        n = ri.RaftNode("n1", 3)
        n._term = 3
        r = n.append_entries(_ae_req(term=2, seq=1))
        self.assertFalse(r.success)
        self.assertEqual(r.term, 3)

    def test_prev_log_mismatch_beyond_log(self):
        n = ri.RaftNode("n1", 3)
        r = n.append_entries(_ae_req(term=1, pli=5, plt=1, seq=1))
        self.assertFalse(r.success)

    def test_prev_log_term_mismatch_truncates(self):
        n = ri.RaftNode("n1", 3)
        n._log.append(_entry(term=1, index=1))
        r = n.append_entries(_ae_req(term=1, pli=1, plt=2, seq=1))
        self.assertFalse(r.success)
        self.assertEqual(n.last_log_index(), 0)

    def test_append_new_entries(self):
        n = ri.RaftNode("n1", 3)
        e1, e2 = _entry(term=1, index=1), _entry(term=1, index=2, payload={"op": "del"})
        r = n.append_entries(_ae_req(term=1, entries=(e1, e2), seq=1))
        self.assertTrue(r.success)
        self.assertEqual(r.match_index, 2)
        self.assertEqual(n.last_log_index(), 2)

    def test_duplicate_entries_skipped(self):
        n = ri.RaftNode("n1", 3)
        e1 = _entry(term=1, index=1)
        n.append_entries(_ae_req(term=1, entries=(e1,), seq=1))
        r = n.append_entries(_ae_req(term=1, pli=1, plt=1, entries=(e1,), seq=2))
        self.assertTrue(r.success)
        self.assertEqual(n.last_log_index(), 1)

    def test_conflicting_entry_truncates(self):
        n = ri.RaftNode("n1", 3)
        n._log.append(_entry(term=1, index=1))
        n._log.append(_entry(term=1, index=2, payload={"op": "old"}))
        e2 = _entry(term=2, index=2, payload={"op": "new"})
        r = n.append_entries(_ae_req(term=2, pli=1, plt=1, entries=(e2,), seq=1))
        self.assertTrue(r.success)
        self.assertEqual(n.last_log_index(), 2)
        self.assertEqual(n.log()[1].term, 2)

    def test_leader_commit_advances(self):
        n = ri.RaftNode("n1", 3)
        e1 = _entry(term=1, index=1)
        n.append_entries(_ae_req(term=1, entries=(e1,), commit=1, seq=1))
        self.assertEqual(n.commit_index, 1)

    def test_leader_commit_capped_by_log(self):
        n = ri.RaftNode("n1", 3)
        e1 = _entry(term=1, index=1)
        n.append_entries(_ae_req(term=1, entries=(e1,), commit=99, seq=1))
        self.assertEqual(n.commit_index, 1)

    def test_candidate_steps_down_on_valid_leader(self):
        n = ri.RaftNode("n1", 3)
        n.start_election(seq=1)
        self.assertEqual(n.state, ri.State.CANDIDATE)
        n.append_entries(_ae_req(leader="l1", term=1, seq=2))
        self.assertEqual(n.state, ri.State.FOLLOWER)

    def test_append_bad_type(self):
        n = ri.RaftNode("n1", 3)
        with self.assertRaises(TypeError):
            n.append_entries(42)  # type: ignore


class TestTransitions(unittest.TestCase):
    def test_start_election(self):
        n = ri.RaftNode("n1", 3)
        req = n.start_election(seq=1)
        self.assertEqual(n.state, ri.State.CANDIDATE)
        self.assertEqual(n.current_term, 1)
        self.assertEqual(n.voted_for, "n1")
        self.assertEqual(req.candidate_id, "n1")
        self.assertEqual(req.term, 1)

    def test_become_leader(self):
        n = ri.RaftNode("n1", 3)
        n.start_election(seq=1)
        n.become_leader(seq=2, votes=2)
        self.assertEqual(n.state, ri.State.LEADER)

    def test_become_leader_needs_quorum(self):
        n = ri.RaftNode("n1", 3)
        n.start_election(seq=1)
        with self.assertRaises(ri.RaftError):
            n.become_leader(seq=2, votes=1)

    def test_become_leader_only_candidate(self):
        n = ri.RaftNode("n1", 3)
        with self.assertRaises(ri.RaftError):
            n.become_leader(seq=1, votes=2)

    def test_step_down(self):
        n = ri.RaftNode("n1", 3)
        n.start_election(seq=1)
        n.become_leader(seq=2, votes=2)
        n.step_down(seq=3)
        self.assertEqual(n.state, ri.State.FOLLOWER)

    def test_append_local(self):
        n = ri.RaftNode("n1", 3)
        n.start_election(seq=1)
        n.become_leader(seq=2, votes=2)
        e = n.append_local({"op": "set", "k": "x"}, seq=3)
        self.assertEqual(e.index, 1)
        self.assertEqual(e.term, 1)
        self.assertTrue(e.payload_digest.startswith("sha256:"))

    def test_append_local_follower_raises(self):
        n = ri.RaftNode("n1", 3)
        with self.assertRaises(ri.RaftError):
            n.append_local({"op": "set"}, seq=1)

    def test_payload_digest_deterministic(self):
        d1 = ri._payload_digest({"b": 2, "a": 1})
        d2 = ri._payload_digest({"a": 1, "b": 2})
        self.assertEqual(d1, d2)
        with self.assertRaises(TypeError):
            ri._payload_digest({"a": object()})  # type: ignore
        with self.assertRaises(ValueError):
            ri._payload_digest({"a": float("nan")})


class TestAudit(unittest.TestCase):
    def test_audit_trail(self):
        n = ri.RaftNode("n1", 3)
        n.request_vote(_vote_req(term=1, seq=1))
        n.start_election(seq=2)
        kinds = [r.kind for r in n.audit()]
        self.assertIn(ri.EVENT_VOTE_GRANTED, kinds)
        self.assertIn(ri.EVENT_ELECTION_STARTED, kinds)

    def test_raft_audit_event(self):
        n = ri.RaftNode("n1", 3)
        n.start_election(seq=1)
        rec = n.audit()[0]
        ev = ri.raft_audit_event(rec, audit_seq=7)
        self.assertEqual(ev["audit_seq"], 7)
        self.assertEqual(ev["schema"], ri.RAFT_INTERFACE_SCHEMA)
        with self.assertRaises(TypeError):
            ri.raft_audit_event("x", 1)  # type: ignore
        with self.assertRaises(ValueError):
            ri.raft_audit_event(rec, -1)

    def test_main_runs(self):
        ri.main()


if __name__ == "__main__":
    unittest.main()
