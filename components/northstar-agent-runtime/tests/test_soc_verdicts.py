"""Tests for soc_verdicts (ninety-ninth batch): SOC verdict cards + kill-switch mandate."""
import hashlib
import unittest

from ed25519 import public_key

from soc_verdicts import (
    DENY_CARD_DIGEST_MISMATCH,
    DENY_COUNTERSIGN_CARD_MISMATCH,
    DENY_COUNTERSIGN_INVALID,
    DENY_COUNTERSIGN_SELF,
    DENY_COUNTERSIGN_UNKNOWN_ANALYST,
    DENY_KILLSWITCH_ACTION_MISMATCH,
    DENY_KILLSWITCH_TIMEOUT_EXCEEDS_WINDOW,
    DENY_KILLSWITCH_TIMEOUT_NONPOSITIVE,
    DENY_KILLSWITCH_UNREACHABLE,
    DENY_MALFORMED_CARD,
    DENY_NOT_RUNTIME_BUILT,
    DENY_NO_SAFEGUARD,
    SOC_EXECUTION_DENIED_EVENT,
    Countersign,
    KillSwitch,
    SocVerdictError,
    VerdictCard,
    build_verdict_card,
    check_killswitch_reachable,
    gate_execution,
    issue_countersign,
    soc_execution_denied_event,
    verify_countersign,
)


def _secret(label: str) -> bytes:
    return hashlib.sha256(f"northstar-soc-test:{label}".encode()).digest()


def _card(**kw):
    base = dict(
        alert_id="alert-1",
        verdict="quarantine",
        evidence_digest="ev" * 32,
        recommended_action="isolate host-7",
        blast_radius_window_s=60,
        agent_id="agent:soc-1",
        created_unix=1000,
    )
    base.update(kw)
    return build_verdict_card(**base)


def _keys(*labels):
    return {f"analyst:{l}": public_key(_secret(l)) for l in labels}


class BuildCardTests(unittest.TestCase):
    def test_valid_card_binds_action_digest(self):
        card = _card()
        self.assertEqual(
            card.action_digest,
            __import__("canonical_json").jcs_sha256_hex(
                {"alert_id": "alert-1", "recommended_action": "isolate host-7"}
            ),
        )

    def test_unknown_verdict_rejected_at_construction(self):
        with self.assertRaises(SocVerdictError):
            _card(verdict="nuke")

    def test_nonpositive_window_rejected_at_construction(self):
        with self.assertRaises(SocVerdictError):
            _card(blast_radius_window_s=0)

    def test_card_digest_deterministic(self):
        self.assertEqual(_card().card_digest(), _card().card_digest())

    def test_card_digest_changes_with_verdict(self):
        self.assertNotEqual(
            _card(verdict="allow").card_digest(),
            _card(verdict="escalate").card_digest(),
        )


class CountersignTests(unittest.TestCase):
    def test_valid_countersign(self):
        card = _card()
        cs = issue_countersign(
            analyst_secret=_secret("a"), analyst_id="analyst:a", card=card
        )
        ok, basis = verify_countersign(cs, card, _keys("a"))
        self.assertTrue(ok)
        self.assertEqual(basis, "human_countersigned")

    def test_countersign_wrong_card_digest(self):
        card = _card()
        cs = issue_countersign(
            analyst_secret=_secret("a"), analyst_id="analyst:a", card=card
        )
        other = _card(alert_id="alert-2")
        ok, basis = verify_countersign(cs, other, _keys("a"))
        self.assertFalse(ok)
        self.assertEqual(basis, DENY_COUNTERSIGN_CARD_MISMATCH)

    def test_countersign_self_is_analyst_equals_agent(self):
        card = _card(agent_id="analyst:a")
        cs = issue_countersign(
            analyst_secret=_secret("a"), analyst_id="analyst:a", card=card
        )
        ok, basis = verify_countersign(cs, card, _keys("a"))
        self.assertFalse(ok)
        self.assertEqual(basis, DENY_COUNTERSIGN_SELF)

    def test_countersign_unknown_analyst(self):
        card = _card()
        cs = issue_countersign(
            analyst_secret=_secret("a"), analyst_id="analyst:a", card=card
        )
        ok, basis = verify_countersign(cs, card, _keys("b"))
        self.assertFalse(ok)
        self.assertEqual(basis, DENY_COUNTERSIGN_UNKNOWN_ANALYST)

    def test_countersign_bad_signature(self):
        card = _card()
        cs = issue_countersign(
            analyst_secret=_secret("a"), analyst_id="analyst:a", card=card
        )
        bad = Countersign(cs.analyst_id, cs.card_digest, "00" * 64)
        ok, basis = verify_countersign(bad, card, _keys("a"))
        self.assertFalse(ok)
        self.assertEqual(basis, DENY_COUNTERSIGN_INVALID)

    def test_countersign_wrong_key(self):
        card = _card()
        cs = issue_countersign(
            analyst_secret=_secret("a"), analyst_id="analyst:a", card=card
        )
        ok, basis = verify_countersign(cs, card, {"analyst:a": public_key(_secret("evil"))})
        self.assertFalse(ok)
        self.assertEqual(basis, DENY_COUNTERSIGN_INVALID)


class KillSwitchTests(unittest.TestCase):
    def _switch(self, card, **kw):
        base = dict(
            switch_id="ks-1",
            endpoint_id="ep-1",
            timeout_s=10,
            action_digest=card.action_digest,
        )
        base.update(kw)
        return KillSwitch(**base)

    def test_reachable_within_window(self):
        card = _card()
        ok, basis = check_killswitch_reachable(
            self._switch(card),
            reachable_endpoints=frozenset({"ep-1"}),
            blast_radius_window_s=60,
            action_digest=card.action_digest,
        )
        self.assertTrue(ok)
        self.assertEqual(basis, "kill_switch_armed")

    def test_unreachable_endpoint(self):
        card = _card()
        ok, basis = check_killswitch_reachable(
            self._switch(card),
            reachable_endpoints=frozenset({"ep-9"}),
            blast_radius_window_s=60,
            action_digest=card.action_digest,
        )
        self.assertFalse(ok)
        self.assertEqual(basis, DENY_KILLSWITCH_UNREACHABLE)

    def test_timeout_exceeds_window(self):
        card = _card()
        ok, basis = check_killswitch_reachable(
            self._switch(card, timeout_s=61),
            reachable_endpoints=frozenset({"ep-1"}),
            blast_radius_window_s=60,
            action_digest=card.action_digest,
        )
        self.assertFalse(ok)
        self.assertEqual(basis, DENY_KILLSWITCH_TIMEOUT_EXCEEDS_WINDOW)

    def test_timeout_equal_to_window_allowed(self):
        card = _card()
        ok, _ = check_killswitch_reachable(
            self._switch(card, timeout_s=60),
            reachable_endpoints=frozenset({"ep-1"}),
            blast_radius_window_s=60,
            action_digest=card.action_digest,
        )
        self.assertTrue(ok)

    def test_timeout_nonpositive(self):
        card = _card()
        ok, basis = check_killswitch_reachable(
            self._switch(card, timeout_s=0),
            reachable_endpoints=frozenset({"ep-1"}),
            blast_radius_window_s=60,
            action_digest=card.action_digest,
        )
        self.assertFalse(ok)
        self.assertEqual(basis, DENY_KILLSWITCH_TIMEOUT_NONPOSITIVE)

    def test_action_mismatch(self):
        card = _card()
        ok, basis = check_killswitch_reachable(
            self._switch(card, action_digest="0" * 64),
            reachable_endpoints=frozenset({"ep-1"}),
            blast_radius_window_s=60,
            action_digest=card.action_digest,
        )
        self.assertFalse(ok)
        self.assertEqual(basis, DENY_KILLSWITCH_ACTION_MISMATCH)


class GateTests(unittest.TestCase):
    def test_human_countersign_allows(self):
        card = _card()
        cs = issue_countersign(
            analyst_secret=_secret("a"), analyst_id="analyst:a", card=card
        )
        res = gate_execution(card, countersign=cs, analyst_keys=_keys("a"))
        self.assertTrue(res.allowed)
        self.assertEqual(res.basis, "human_countersigned")

    def test_killswitch_armed_allows(self):
        card = _card()
        ks = KillSwitch("ks-1", "ep-1", 10, card.action_digest)
        res = gate_execution(card, kill_switch=ks, reachable_endpoints=frozenset({"ep-1"}))
        self.assertTrue(res.allowed)
        self.assertEqual(res.basis, "kill_switch_armed")

    def test_no_safeguard_denies(self):
        res = gate_execution(_card())
        self.assertFalse(res.allowed)
        self.assertEqual(res.basis, DENY_NO_SAFEGUARD)

    def test_bad_countersign_denies_even_with_killswitch(self):
        # countersign present but invalid -> deny; kill-switch is not consulted
        card = _card()
        bad = Countersign("analyst:a", card.card_digest(), "00" * 64)
        ks = KillSwitch("ks-1", "ep-1", 10, card.action_digest)
        res = gate_execution(
            card, countersign=bad, analyst_keys=_keys("a"),
            kill_switch=ks, reachable_endpoints=frozenset({"ep-1"}),
        )
        self.assertFalse(res.allowed)
        self.assertEqual(res.basis, DENY_COUNTERSIGN_INVALID)

    def test_unreachable_killswitch_denies(self):
        card = _card()
        ks = KillSwitch("ks-1", "ep-1", 10, card.action_digest)
        res = gate_execution(card, kill_switch=ks, reachable_endpoints=frozenset())
        self.assertFalse(res.allowed)
        self.assertEqual(res.basis, DENY_KILLSWITCH_UNREACHABLE)

    def test_malformed_card_denies_before_safeguards(self):
        card = _card()
        forged = VerdictCard(
            card_id=card.card_id, alert_id=card.alert_id, verdict="quarantine",
            evidence_digest=card.evidence_digest,
            recommended_action=card.recommended_action,
            action_digest=card.action_digest,
            blast_radius_window_s=card.blast_radius_window_s,
            agent_id=card.agent_id, built_by="agent", created_unix=1000,
        )
        cs = issue_countersign(
            analyst_secret=_secret("a"), analyst_id="analyst:a", card=card
        )
        res = gate_execution(forged, countersign=cs, analyst_keys=_keys("a"))
        self.assertFalse(res.allowed)
        self.assertEqual(res.basis, DENY_NOT_RUNTIME_BUILT)

    def test_countersign_beats_killswitch(self):
        card = _card()
        cs = issue_countersign(
            analyst_secret=_secret("a"), analyst_id="analyst:a", card=card
        )
        ks = KillSwitch("ks-1", "ep-1", 10, card.action_digest)
        res = gate_execution(
            card, countersign=cs, analyst_keys=_keys("a"),
            kill_switch=ks, reachable_endpoints=frozenset({"ep-1"}),
        )
        self.assertTrue(res.allowed)
        self.assertEqual(res.basis, "human_countersigned")


class AuditTests(unittest.TestCase):
    def test_denied_event_shape(self):
        card = _card()
        ev = soc_execution_denied_event(card, DENY_NO_SAFEGUARD, created_unix=42)
        self.assertEqual(ev["event"], SOC_EXECUTION_DENIED_EVENT)
        self.assertEqual(ev["card_id"], card.card_id)
        self.assertEqual(ev["reason"], DENY_NO_SAFEGUARD)
        self.assertEqual(ev["created_unix"], 42)


if __name__ == "__main__":
    unittest.main()
