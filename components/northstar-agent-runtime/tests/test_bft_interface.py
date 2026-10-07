"""Tests for bft_interface: PBFT pre-prepare/prepare/commit bookkeeping."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from bft_interface import (
    BFTError,
    BFTNode,
    ClientRequest,
    CommitMessage,
    CommitRecord,
    MessageValidationError,
    PrePrepare,
    Prepare,
    ReplicaSetError,
    Reply,
    SlotConflictError,
    bft_audit_event,
    bft_quorum,
    bft_replica_count,
    BFT_INTERFACE_VERSION,
    BFT_INTERFACE_SCHEMA,
    EVENT_REQUEST,
    EVENT_COMMITTED,
)


def _node(node_id="r0", f=1, replicas=("r0", "r1", "r2", "r3")):
    return BFTNode(node_id, f, replicas)


def _req(node, seq=1):
    return node.request("client-1", {"op": "halt"}, seq=seq)


def _full_commit(node, view=0, seq=1, seq_no=7):
    """Drive one slot to committed on ``node`` (node must know pre-prepare)."""
    pp = node._pre_prepares[(view, seq)]
    key = (view, seq, pp.digest)
    seen_p = node._prepares.get(key, set())
    for r in node._replicas:
        if r not in seen_p:
            node.receive_prepare(Prepare(view=view, seq=seq, digest=pp.digest, replica_id=r))
    seen_c = node._commits.get(key, set())
    for r in node._replicas:
        if r not in seen_c:
            node.receive_commit(CommitMessage(view=view, seq=seq, digest=pp.digest, replica_id=r))
    return node.commit_record(view, seq, committed_seq=seq_no)


class TestVersionPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(BFT_INTERFACE_VERSION, "bft-interface.v1")

    def test_schema_pin(self):
        self.assertEqual(BFT_INTERFACE_SCHEMA, "northstar.bft-interface.v1")


class TestQuorumMath(unittest.TestCase):
    def test_quorum(self):
        self.assertEqual(bft_quorum(0), 1)
        self.assertEqual(bft_quorum(1), 3)
        self.assertEqual(bft_quorum(2), 5)

    def test_replica_count(self):
        self.assertEqual(bft_replica_count(0), 1)
        self.assertEqual(bft_replica_count(1), 4)
        self.assertEqual(bft_replica_count(2), 7)

    def test_bad_f(self):
        with self.assertRaises(TypeError):
            bft_quorum(True)
        with self.assertRaises(ValueError):
            bft_quorum(-1)
        with self.assertRaises(TypeError):
            bft_replica_count("1")


class TestConstruction(unittest.TestCase):
    def test_node_not_in_replicas(self):
        with self.assertRaises(ReplicaSetError):
            BFTNode("r9", 1, ("r0", "r1", "r2", "r3"))

    def test_too_few_replicas(self):
        with self.assertRaises(ReplicaSetError):
            BFTNode("r0", 1, ("r0", "r1", "r2"))  # 3 < 4

    def test_duplicate_replicas(self):
        with self.assertRaises(ReplicaSetError):
            BFTNode("r0", 1, ("r0", "r0", "r1", "r2"))

    def test_properties(self):
        n = _node()
        self.assertEqual(n.node_id, "r0")
        self.assertEqual(n.f, 1)
        self.assertEqual(n.quorum, 3)
        self.assertEqual(n.replica_count, 4)


class TestPrimary(unittest.TestCase):
    def test_primary_of_view_0(self):
        n = _node()
        self.assertEqual(n.primary_of(0), "r0")
        self.assertTrue(n.is_primary(0))
        self.assertFalse(_node("r1").is_primary(0))

    def test_primary_rotates(self):
        n = _node()
        self.assertEqual(n.primary_of(1), "r1")
        self.assertEqual(n.primary_of(4), "r0")


class TestRequest(unittest.TestCase):
    def test_request_pins_digest(self):
        n = _node()
        r1 = n.request("client-1", {"op": "halt"}, seq=1)
        r2 = n.request("client-1", {"op": "halt"}, seq=1)
        self.assertEqual(r1.operation_digest, r2.operation_digest)
        self.assertTrue(r1.operation_digest.startswith("sha256:"))
        r3 = n.request("client-1", {"op": "go"}, seq=1)
        self.assertNotEqual(r1.operation_digest, r3.operation_digest)

    def test_request_validation(self):
        n = _node()
        with self.assertRaises(TypeError):
            n.request("c", ["not", "a", "mapping"], seq=1)
        with self.assertRaises(ValueError):
            n.request("", {"op": "x"}, seq=1)
        with self.assertRaises(ValueError):
            n.request("c", {"op": "x"}, seq=-1)


class TestPrePrepare(unittest.TestCase):
    def test_primary_mints(self):
        n = _node()
        req = _req(n)
        pp = n.pre_prepare_for(view=0, seq=1, req=req)
        self.assertEqual(pp.primary_id, "r0")
        self.assertEqual(pp.digest, req.operation_digest)

    def test_non_primary_refused(self):
        n = _node("r1")
        req = _req(n)
        with self.assertRaises(MessageValidationError):
            n.pre_prepare_for(view=0, seq=1, req=req)

    def test_slot_conflict(self):
        n = _node()
        req = _req(n)
        n.pre_prepare_for(view=0, seq=1, req=req)
        with self.assertRaises(SlotConflictError):
            n.pre_prepare_for(view=0, seq=1, req=req)

    def test_backup_accepts(self):
        primary, backup = _node("r0"), _node("r1")
        req = _req(primary)
        pp = primary.pre_prepare_for(view=0, seq=1, req=req)
        self.assertTrue(backup.receive_pre_prepare(pp))

    def test_backup_rejects_wrong_primary(self):
        backup = _node("r1")
        n = _node("r0")
        req = _req(n)
        pp = PrePrepare(view=0, seq=1, request_id=req.request_id,
                        digest=req.operation_digest, primary_id="r2")
        with self.assertRaises(MessageValidationError):
            backup.receive_pre_prepare(pp)

    def test_backup_rejects_duplicate_slot(self):
        primary, backup = _node("r0"), _node("r1")
        req = _req(primary)
        pp = primary.pre_prepare_for(view=0, seq=1, req=req)
        backup.receive_pre_prepare(pp)
        with self.assertRaises(SlotConflictError):
            backup.receive_pre_prepare(pp)


class TestPrepare(unittest.TestCase):
    def _primed(self):
        primary, node = _node("r0"), _node("r1")
        req = _req(primary)
        pp = primary.pre_prepare_for(view=0, seq=1, req=req)
        node.receive_pre_prepare(pp)
        return node, pp

    def test_prepare_needs_pre_prepare(self):
        node, pp = self._primed()
        with self.assertRaises(MessageValidationError):
            node.receive_prepare(Prepare(view=0, seq=9, digest=pp.digest, replica_id="r0"))

    def test_digest_mismatch(self):
        node, pp = self._primed()
        bad = "sha256:" + "ab" * 32
        with self.assertRaises(MessageValidationError):
            node.receive_prepare(Prepare(view=0, seq=1, digest=bad, replica_id="r0"))

    def test_unknown_replica(self):
        node, pp = self._primed()
        with self.assertRaises(MessageValidationError):
            node.receive_prepare(Prepare(view=0, seq=1, digest=pp.digest, replica_id="rx"))

    def test_duplicate_prepare(self):
        node, pp = self._primed()
        p = Prepare(view=0, seq=1, digest=pp.digest, replica_id="r0")
        node.receive_prepare(p)
        with self.assertRaises(MessageValidationError):
            node.receive_prepare(p)

    def test_prepared_at_2f_others(self):
        node, pp = self._primed()
        self.assertFalse(node.is_prepared(0, 1))
        node.receive_prepare(Prepare(view=0, seq=1, digest=pp.digest, replica_id="r1"))
        self.assertFalse(node.is_prepared(0, 1))  # own only
        node.receive_prepare(Prepare(view=0, seq=1, digest=pp.digest, replica_id="r0"))
        self.assertFalse(node.is_prepared(0, 1))  # 1 other
        self.assertTrue(node.receive_prepare(
            Prepare(view=0, seq=1, digest=pp.digest, replica_id="r2")))
        self.assertTrue(node.is_prepared(0, 1))  # 2 others = 2f


class TestCommit(unittest.TestCase):
    def _prepared(self):
        node = _node("r1")
        primary = _node("r0")
        req = _req(primary)
        pp = primary.pre_prepare_for(view=0, seq=1, req=req)
        node.receive_pre_prepare(pp)
        for r in ("r0", "r2"):
            node.receive_prepare(Prepare(view=0, seq=1, digest=pp.digest, replica_id=r))
        return node, pp

    def test_needs_prepared(self):
        node, pp = self._prepared()
        node2 = _node("r2")
        primary = _node("r0")
        req = _req(primary)
        pp2 = primary.pre_prepare_for(view=0, seq=2, req=req)
        node2.receive_pre_prepare(pp2)
        # only 2 commits, no prepares -> not committed
        for r in ("r0", "r1"):
            node2.receive_commit(CommitMessage(view=0, seq=2, digest=pp2.digest, replica_id=r))
        self.assertFalse(node2.is_committed(0, 2))
        self.assertIsNone(node2.commit_record(0, 2, committed_seq=5))

    def test_committed_at_2f_plus_1(self):
        node, pp = self._prepared()
        flags = [node.receive_commit(
            CommitMessage(view=0, seq=1, digest=pp.digest, replica_id=r))
            for r in ("r0", "r1", "r2")]
        self.assertEqual(flags, [False, False, True])
        self.assertTrue(node.is_committed(0, 1))

    def test_commit_record(self):
        node, pp = self._prepared()
        rec = _full_commit(node)
        self.assertIsInstance(rec, CommitRecord)
        self.assertEqual(rec.quorum, 3)
        self.assertEqual(rec.digest, pp.digest)
        self.assertEqual(rec.request_id, pp.request_id)
        self.assertEqual(len(rec.prepares), 4)
        self.assertEqual(len(rec.commits), 4)
        self.assertEqual(rec.committed_seq, 7)

    def test_commit_digest_mismatch(self):
        node, pp = self._prepared()
        bad = "sha256:" + "cd" * 32
        with self.assertRaises(MessageValidationError):
            node.receive_commit(CommitMessage(view=0, seq=1, digest=bad, replica_id="r0"))

    def test_duplicate_commit(self):
        node, pp = self._prepared()
        c = CommitMessage(view=0, seq=1, digest=pp.digest, replica_id="r0")
        node.receive_commit(c)
        with self.assertRaises(MessageValidationError):
            node.receive_commit(c)


class TestReply(unittest.TestCase):
    def test_reply_only_when_committed(self):
        primary = _node("r0")
        node = _node("r1")
        req = _req(primary)
        pp = primary.pre_prepare_for(view=0, seq=1, req=req)
        node.receive_pre_prepare(pp)
        self.assertIsNone(node.reply(req, {"ok": True}, view=0, seq=1))

    def test_reply_after_commit(self):
        primary = _node("r0")
        node = _node("r1")
        req = _req(primary)
        pp = primary.pre_prepare_for(view=0, seq=1, req=req)
        node.receive_pre_prepare(pp)
        _full_commit(node)
        rep = node.reply(req, {"ok": True}, view=0, seq=1)
        self.assertIsInstance(rep, Reply)
        self.assertEqual(rep.client_id, "client-1")
        self.assertEqual(rep.request_id, req.request_id)
        self.assertEqual(rep.replica_id, "r1")
        self.assertTrue(rep.result_digest.startswith("sha256:"))


class TestAuditEvent(unittest.TestCase):
    def test_event_shape(self):
        n = _node()
        req = _req(n)
        ev = bft_audit_event(EVENT_REQUEST, req, 3)
        self.assertEqual(ev["schema"], "audit.ndjson/1")
        self.assertEqual(ev["kind"], EVENT_REQUEST)
        self.assertEqual(ev["seq"], 3)
        self.assertEqual(ev["body"]["request_id"], req.request_id)

    def test_bad_kind(self):
        n = _node()
        with self.assertRaises(ValueError):
            bft_audit_event("nope", _req(n), 1)

    def test_bad_seq(self):
        n = _node()
        with self.assertRaises(ValueError):
            bft_audit_event(EVENT_COMMITTED, _req(n), -1)


class TestMain(unittest.TestCase):
    def test_main_self_check(self):
        import bft_interface
        bft_interface.main()


if __name__ == "__main__":
    unittest.main()
