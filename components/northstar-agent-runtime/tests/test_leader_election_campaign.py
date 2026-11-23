"""Tests for the LeaderElection campaign/stepdown/leader facade.

Additive coverage for the facade layered over the batch-8 elector:
campaign outcomes, auto-registration, step-down refusal taxonomy, the
pure leader() view, term advance across resignation, and audit wiring.
The pre-existing elector suite (test_leader_election.py) is untouched.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from leader_election import (
    EVENT_ELECTED,
    EVENT_RESIGNED,
    CampaignResult,
    LeaderElection,
    StepDownResult,
    leader_election_audit_event,
)


def test_campaign_first_node_becomes_leader():
    el = LeaderElection(lease_duration_seqs=5)
    res = el.campaign("n1", seq=0)
    assert isinstance(res, CampaignResult)
    assert res.outcome == "leader"
    assert res.term == 1
    assert res.node_id == "n1"
    assert el.leader(seq=0).leader_id == "n1"


def test_campaign_second_node_is_follower_when_lower_priority():
    el = LeaderElection(lease_duration_seqs=10)
    el.campaign("high", seq=0, priority=9)
    res = el.campaign("low", seq=1, priority=1)
    assert res.outcome == "follower"
    assert res.term == 1  # no new election: live lease stands
    assert el.leader(seq=1).leader_id == "high"


def test_campaign_higher_priority_wins_open_term():
    el = LeaderElection(lease_duration_seqs=10)
    el.campaign("low", seq=0, priority=1)
    el.stepdown("low", seq=1)
    res = el.campaign("high", seq=2, priority=9)
    assert res.outcome == "leader"
    assert res.term == 2


def test_campaign_auto_registers_unknown_node():
    el = LeaderElection()
    el.campaign("a", seq=0)
    el.campaign("b", seq=1)
    assert el.candidate_ids() == ("a", "b")


def test_campaign_bad_node_id_fails_closed():
    el = LeaderElection()
    with pytest.raises((TypeError, ValueError)):
        el.campaign("", seq=0)
    with pytest.raises((TypeError, ValueError)):
        el.campaign("   ", seq=0)
    with pytest.raises((TypeError, ValueError)):
        el.campaign(123, seq=0)  # type: ignore[arg-type]
    with pytest.raises((TypeError, ValueError)):
        el.campaign("ok", seq=-1)
    with pytest.raises((TypeError, ValueError)):
        el.campaign("ok", seq=True)  # type: ignore[arg-type]


def test_campaign_bad_priority_fails_closed():
    el = LeaderElection()
    with pytest.raises((TypeError, ValueError)):
        el.campaign("a", seq=0, priority=-1)
    with pytest.raises((TypeError, ValueError)):
        el.campaign("a", seq=0, priority=True)  # type: ignore[arg-type]


def test_campaign_idempotent_when_already_leader():
    el = LeaderElection(lease_duration_seqs=10)
    first = el.campaign("n1", seq=0)
    again = el.campaign("n1", seq=1)
    assert again.outcome == "leader"
    assert again.term == first.term  # no term churn on re-campaign


def test_stepdown_vacates_leadership():
    el = LeaderElection(lease_duration_seqs=10)
    el.campaign("n1", seq=0)
    down = el.stepdown("n1", seq=1)
    assert isinstance(down, StepDownResult)
    assert down.vacated is True
    assert down.resigned_term == 1
    assert el.leader(seq=2) is None


def test_stepdown_non_leader_raises():
    el = LeaderElection(lease_duration_seqs=10)
    el.campaign("n1", seq=0)
    el.campaign("n2", seq=1)
    with pytest.raises(ValueError):
        el.stepdown("n2", seq=2)
    # Leadership is untouched by the refused step-down.
    assert el.leader(seq=2).leader_id == "n1"


def test_stepdown_no_live_leader_raises():
    el = LeaderElection()
    with pytest.raises(ValueError):
        el.stepdown("ghost", seq=0)


def test_stepdown_after_expiry_raises():
    el = LeaderElection(lease_duration_seqs=2)
    el.campaign("n1", seq=0)
    assert el.leader(seq=5) is None  # expired
    with pytest.raises(ValueError):
        el.stepdown("n1", seq=5)


def test_leader_view_returns_live_lease():
    el = LeaderElection(lease_duration_seqs=10)
    el.campaign("n1", seq=0)
    lease = el.leader(seq=3)
    assert lease is not None
    assert lease.leader_id == "n1"
    assert lease.term == 1


def test_leader_view_bad_seq_raises():
    el = LeaderElection()
    with pytest.raises((TypeError, ValueError)):
        el.leader(seq=-1)
    with pytest.raises((TypeError, ValueError)):
        el.leader(seq="0")  # type: ignore[arg-type]


def test_campaign_after_stepdown_advances_term():
    el = LeaderElection(lease_duration_seqs=10)
    el.campaign("n1", seq=0)
    el.stepdown("n1", seq=1)
    # n2 outranks n1, so it wins the fresh term deterministically.
    res = el.campaign("n2", seq=2, priority=1)
    assert res.term == 2
    assert res.outcome == "leader"
    assert el.leader(seq=2).leader_id == "n2"


def test_audit_event_wiring_for_campaign_and_stepdown():
    el = LeaderElection(lease_duration_seqs=10)
    res = el.campaign("n1", seq=0)
    assert res.outcome == "leader"
    elected = leader_election_audit_event(
        EVENT_ELECTED, el.leader(seq=0), seq=0, detail="term 1"
    )
    assert elected["event"] == EVENT_ELECTED
    assert elected["lease"]["leader_id"] == "n1"
    el.stepdown("n1", seq=1)
    resigned = leader_election_audit_event(
        EVENT_RESIGNED, el.leader(seq=1), seq=1, detail="voluntary"
    )
    assert resigned["event"] == EVENT_RESIGNED
    assert resigned["lease"] is None
    with pytest.raises(ValueError):
        leader_election_audit_event("bogus-kind", None, seq=0)
