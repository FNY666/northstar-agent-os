"""Tests for distributed_consensus."""

import ast
import subprocess
import sys
from pathlib import Path

import pytest

import distributed_consensus as dc
from distributed_consensus import (
    DistributedConsensus,
    BadDecisionError,
    BadDigestError,
    BadProposalError,
    BadProtocolError,
    BadQuorumError,
    BadVoterError,
    DistributedConsensusError,
    DuplicateProposalError,
    DuplicateVoteError,
    QuorumNotReachedError,
    RejectedProposalError,
    SeqOrderError,
    TerminalProposalError,
    UnknownProposalError,
    UnknownVoterError,
    distributed_consensus_audit_event,
)

DIGEST_A = "sha256:" + "aa" * 32
DIGEST_B = "sha256:" + "bb" * 32


def _mod(voters=("n1", "n2", "n3"), quorum=2, protocol="simulated"):
    return DistributedConsensus(quorum=quorum, voters=voters, protocol=protocol)


def test_version_and_schema_pins():
    assert dc.DISTRIBUTED_CONSENSUS_VERSION == "distributed-consensus.v1"
    assert dc.DISTRIBUTED_CONSENSUS_SCHEMA == "northstar.distributed-consensus.v1"
    assert dc.PROTOCOLS == ("simulated", "paxos", "raft")
    assert dc.DECISIONS == ("accept", "reject")


def test_stdlib_only():
    src = Path(dc.__file__).read_text()
    tree = ast.parse(src)
    allowed = {
        "hashlib", "threading", "dataclasses", "typing", "json",
        "canonical_json", "__future__",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                assert a.name.split(".")[0] in allowed, a.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module


def test_constructor_bad_inputs():
    with pytest.raises(BadQuorumError):
        DistributedConsensus(quorum=0)
    with pytest.raises(BadQuorumError):
        DistributedConsensus(quorum=True)
    with pytest.raises(BadQuorumError):
        DistributedConsensus(quorum=5, voters=("a", "b"))
    with pytest.raises(BadProtocolError):
        DistributedConsensus(protocol="zab")
    with pytest.raises(BadVoterError):
        DistributedConsensus(voters=("a", "a"))


def test_propose_roundtrip():
    m = _mod()
    rec = m.propose("p1", DIGEST_A, 1)
    assert rec.verify()
    assert rec.value_digest == DIGEST_A
    assert m.round_state("p1", 2) == "open"
    with pytest.raises(DuplicateProposalError):
        m.propose("p1", DIGEST_B, 3)
    with pytest.raises(BadProposalError):
        m.propose("  ", DIGEST_A, 4)
    with pytest.raises(BadDigestError):
        m.propose("p2", "not-a-digest", 5)
    with pytest.raises(BadDigestError):
        m.propose("p2", "sha256:" + "ZZ" * 32, 6)


def test_seq_ordering_and_failed_mutation_consumes_seq():
    m = _mod()
    m.propose("p1", DIGEST_A, 1)
    with pytest.raises(SeqOrderError):
        m.propose("p2", DIGEST_A, 1)  # rewind
    with pytest.raises(SeqOrderError):
        m.vote("p1", "n1", "accept", True)  # bool seq
    with pytest.raises(SeqOrderError):
        m.vote("p1", "n1", "accept", "2")  # non-int seq
    with pytest.raises(UnknownProposalError):
        m.vote("nope", "n1", "accept", 2)  # consumes seq 2
    with pytest.raises(SeqOrderError):
        m.propose("p2", DIGEST_A, 2)  # seq 2 was consumed by the failure
    m.propose("p2", DIGEST_A, 3)  # fresh seq works


def test_vote_roundtrip_and_duplicate():
    m = _mod()
    m.propose("p1", DIGEST_A, 1)
    v = m.vote("p1", "n1", "accept", 2)
    assert v.verify()
    v2 = m.vote("p1", "n2", "reject", 3)
    assert v2.verify()
    with pytest.raises(DuplicateVoteError):
        m.vote("p1", "n1", "reject", 4)
    with pytest.raises(BadDecisionError):
        m.vote("p1", "n3", "abstain", 5)
    with pytest.raises(UnknownVoterError):
        m.vote("p1", "n9", "accept", 6)
    votes = m.votes_for("p1", 7)
    assert [x.voter for x in votes] == ["n1", "n2"]


def test_commit_happy_path():
    m = _mod()
    m.propose("p1", DIGEST_A, 1)
    m.vote("p1", "n1", "accept", 2)
    with pytest.raises(QuorumNotReachedError):
        m.commit("p1", 3)
    m.vote("p1", "n2", "accept", 4)
    c = m.commit("p1", 5)
    assert c.verify()
    assert c.accepts == 2 and c.quorum == 2
    assert m.round_state("p1", 6) == "committed"
    with pytest.raises(TerminalProposalError):
        m.commit("p1", 7)
    with pytest.raises(TerminalProposalError):
        m.vote("p1", "n3", "accept", 8)


def test_reject_quorum_marks_terminal():
    m = _mod()
    m.propose("p1", DIGEST_A, 1)
    m.vote("p1", "n1", "reject", 2)
    m.vote("p1", "n2", "reject", 3)
    with pytest.raises(RejectedProposalError):
        m.commit("p1", 4)
    assert m.round_state("p1", 5) == "rejected"
    with pytest.raises(TerminalProposalError):
        m.withdraw("p1", 6, reason="too late")


def test_withdraw_terminality():
    m = _mod()
    m.propose("p1", DIGEST_A, 1)
    w = m.withdraw("p1", 2, reason="superseded")
    assert w.verify()
    assert m.round_state("p1", 3) == "withdrawn"
    with pytest.raises(TerminalProposalError):
        m.vote("p1", "n1", "accept", 4)
    with pytest.raises(TerminalProposalError):
        m.withdraw("p1", 5)
    with pytest.raises(TerminalProposalError):
        m.commit("p1", 6)


def test_view_read_semantics():
    m = _mod()
    m.propose("p1", DIGEST_A, 1)
    m.vote("p1", "n1", "accept", 2)
    m.vote("p1", "n2", "accept", 3)
    m.commit("p1", 4)
    m.propose("p2", DIGEST_B, 5)
    v = m.view(6)
    assert v.verify()
    assert v.committed == ("p1",)
    assert v.open == ("p2",)
    assert v.rejected == () and v.withdrawn == ()
    assert v.quorum == 2 and v.protocol == "simulated"
    tally = {t.proposal_id: t for t in v.tallies}
    assert tally["p1"].accepts == 2 and tally["p1"].state == "committed"
    assert tally["p2"].state == "open"
    # read view consumes nothing: same seq still valid for another read
    m.view(6)
    m.proposal("p1", 7)
    assert m.proposal_ids(8) == ("p1", "p2")


def test_mixed_votes_commit_wins_on_accept_quorum():
    m = _mod(quorum=2)
    m.propose("p1", DIGEST_A, 1)
    m.vote("p1", "n1", "accept", 2)
    m.vote("p1", "n2", "reject", 3)
    with pytest.raises(QuorumNotReachedError):
        m.commit("p1", 4)
    m.vote("p1", "n3", "accept", 5)
    c = m.commit("p1", 6)
    assert c.verify()


def test_audit_shapes_and_banned_keys():
    m = _mod()
    m.propose("p1", DIGEST_A, 1)
    m.vote("p1", "n1", "accept", 2)
    m.vote("p1", "n2", "accept", 3)
    m.commit("p1", 4)
    kinds = [e["kind"] for e in m.audit_log()]
    assert kinds == [
        "consensus.proposed", "consensus.vote-recorded",
        "consensus.vote-recorded", "consensus.committed",
    ]
    for e in m.audit_log():
        assert e["schema"] == "audit.ndjson/1"
        assert "value" not in e["detail"] and "votes" not in e["detail"]
    with pytest.raises(DistributedConsensusError):
        distributed_consensus_audit_event("bogus", 1)
    with pytest.raises(DistributedConsensusError):
        distributed_consensus_audit_event(
            "consensus.proposed", 1, value="leak"
        )


def test_no_voter_allowlist_means_any_voter():
    m = DistributedConsensus(quorum=1)
    m.propose("p1", DIGEST_A, 1)
    m.vote("p1", "whoever", "accept", 2)
    c = m.commit("p1", 3)
    assert c.verify()


def test_protocol_pin_paxos():
    m = DistributedConsensus(quorum=1, protocol="paxos")
    rec = m.propose("p1", DIGEST_A, 1)
    assert rec.protocol == "paxos"
    v = m.view(2)
    assert v.protocol == "paxos"


def test_main_self_check():
    r = subprocess.run(
        [sys.executable, dc.__file__], capture_output=True, text=True
    )
    assert r.returncode == 0, r.stderr
    assert "distributed-consensus OK" in r.stdout
