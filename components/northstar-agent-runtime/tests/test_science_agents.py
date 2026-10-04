"""Tests for science_agents.py (one-hundred-sixty-second batch)."""

import hashlib
import sys
import unittest

sys.path.insert(0, ".")  # run from components/northstar-agent-runtime

import ed25519
from science_agents import (
    AuthorityRegistry,
    CitationVerificationRegistry,
    DiscoveryAttributionRegistry,
    DualUseScreeningRegistry,
    LabIncidentLedger,
    LabRobotEnvelopeRegistry,
    ReproductionBindingRegistry,
    ScienceError,
    WetlabExecutionRegistry,
    discovery_attribution_receipt,
    dual_use_screen,
    hypothesis_evidence_tier,
    lab_incident_reporting,
    lab_robot_capability_envelope,
    reproducibility_lock,
    synthesis_order_binding,
    wetlab_human_action_gate,
)

SEC = b"sc-bench-auth-" + b"0" * 18  # 32 bytes
assert len(SEC) == 32
PUB = ed25519.public_key(SEC).hex()
T0 = 1_800_000_000
HEX64 = "ab" * 32
HEX64_B = "cd" * 32
HEX64_C = "ef" * 32


def _auth() -> AuthorityRegistry:
    reg = AuthorityRegistry()
    reg.register("bench-sci-op", PUB)
    return reg


def _sign(payload_bytes: bytes) -> str:
    return ed25519.sign(SEC, payload_bytes).hex()


class TierTests(unittest.TestCase):
    def setUp(self):
        self.auth = _auth()
        self.ver = CitationVerificationRegistry(self.auth)

    def _verify(self, cid):
        self.ver.issue(
            receipt_id=f"cv-{cid}",
            citation_id=cid,
            doi=f"10.1038/x-{cid}",
            title=f"A real study {cid}",
            resolved_at=T0,
            authority_id="bench-sci-op",
            sign=_sign,
        )

    def test_verified_citation_allows(self):
        self._verify("c1")
        v = hypothesis_evidence_tier(
            hypothesis_id="h1",
            tier="evidence",
            formal_record="paper",
            citation_ids=("c1",),
            verifications=self.ver,
        )
        self.assertTrue(v.allowed)

    def test_signal_tier_denies_formal_record(self):
        v = hypothesis_evidence_tier(
            hypothesis_id="h1",
            tier="signal",
            formal_record="paper",
            citation_ids=(),
            verifications=self.ver,
        )
        self.assertFalse(v.allowed)
        self.assertIn("unverified_tier", v.reason)

    def test_missing_citation_verification_denies(self):
        v = hypothesis_evidence_tier(
            hypothesis_id="h1",
            tier="evidence",
            formal_record="grant_application",
            citation_ids=("ghost-cite",),
            verifications=self.ver,
        )
        self.assertFalse(v.allowed)
        self.assertIn("unverified_citation", v.reason)

    def test_chain_verify(self):
        self._verify("c1")
        self.ver.verify_chain()


class WetlabGateTests(unittest.TestCase):
    def setUp(self):
        self.auth = _auth()
        self.exe = WetlabExecutionRegistry(self.auth)

    def _exec(self, action="pipette", target="well-a1"):
        self.exe.issue(
            receipt_id="we-1",
            action=action,
            target=target,
            executor_id="dr-chen",
            executed_at=T0,
            authority_id="bench-sci-op",
            sign=_sign,
        )

    def test_no_receipt_denies(self):
        v = wetlab_human_action_gate(
            action="handle_pathogen",
            target="vial-7",
            agent_instruction_digest=HEX64,
            executions=self.exe,
            now=T0,
        )
        self.assertFalse(v.allowed)
        self.assertIn("ungated_wetlab", v.reason)

    def test_receipt_allows(self):
        self._exec()
        v = wetlab_human_action_gate(
            action="pipette",
            target="well-a1",
            agent_instruction_digest=HEX64,
            executions=self.exe,
            now=T0,
        )
        self.assertTrue(v.allowed)
        self.assertEqual(v.classification, "authoritative")

    def test_unknown_action_raises(self):
        with self.assertRaises(ScienceError):
            wetlab_human_action_gate(
                action="launch_missile",
                target="x",
                agent_instruction_digest=HEX64,
                executions=self.exe,
                now=T0,
            )


class DualUseTests(unittest.TestCase):
    def setUp(self):
        self.auth = _auth()
        self.reg = DualUseScreeningRegistry(self.auth)

    def _screen(self, categories, result="clear"):
        return self.reg.issue(
            receipt_id="ds-1",
            workflow_id="wf-bio",
            categories_evaluated=categories,
            screen_result=result,
            screened_at=T0,
            institution_id="uni-lab",
            authority_id="bench-sci-op",
            sign=_sign,
        )

    def test_no_screening_denies(self):
        v = dual_use_screen(workflow_id="wf-bio", screenings=self.reg)
        self.assertFalse(v.allowed)
        self.assertIn("unscreened_dual_use", v.reason)

    def test_homology_only_denies(self):
        self._screen(("sequence_homology", "end_use_screen"))
        v = dual_use_screen(workflow_id="wf-bio", screenings=self.reg)
        self.assertFalse(v.allowed)
        self.assertIn("homology_only_screen", v.reason)

    def test_hit_denies(self):
        self._screen(("function_equivalence", "institution_qualification"), "hit")
        v = dual_use_screen(workflow_id="wf-bio", screenings=self.reg)
        self.assertFalse(v.allowed)
        self.assertIn("unscreened_dual_use", v.reason)

    def test_full_screen_allows(self):
        self._screen(("sequence_homology", "function_equivalence",
                       "institution_qualification", "end_use_screen"))
        v = dual_use_screen(workflow_id="wf-bio", screenings=self.reg)
        self.assertTrue(v.allowed)


class SynthesisOrderTests(unittest.TestCase):
    def setUp(self):
        self.auth = _auth()
        self.reg = DualUseScreeningRegistry(self.auth)
        self.reg.issue(
            receipt_id="ds-9",
            workflow_id="wf-synth",
            categories_evaluated=("function_equivalence", "institution_qualification"),
            screen_result="clear",
            screened_at=T0,
            institution_id="uni-lab",
            authority_id="bench-sci-op",
            sign=_sign,
        )

    def test_unbound_order_denies(self):
        v = synthesis_order_binding(
            order_id="so-1",
            orderer_id="pi-wang",
            sequence_digest=HEX64,
            screenings=self.reg,
            workflow_id="wf-nonexistent",
        )
        self.assertFalse(v.allowed)
        self.assertIn("unbound_synthesis_order", v.reason)

    def test_bound_order_allows(self):
        v = synthesis_order_binding(
            order_id="so-2",
            orderer_id="pi-wang",
            sequence_digest=HEX64,
            screenings=self.reg,
            workflow_id="wf-synth",
        )
        self.assertTrue(v.allowed)


class ReproducibilityTests(unittest.TestCase):
    def setUp(self):
        self.auth = _auth()
        self.reg = ReproductionBindingRegistry(self.auth)
        self.reg.issue(
            receipt_id="rb-1",
            tool_id="align-tool",
            tool_version="2.1.0",
            paper_digest=HEX64,
            reproduced_result_digest=HEX64_B,
            bound_at=T0,
            authority_id="bench-sci-op",
            sign=_sign,
        )

    def test_matching_digest_allows(self):
        v = reproducibility_lock(
            tool_id="align-tool",
            tool_version="2.1.0",
            current_result_digest=HEX64_B,
            bindings=self.reg,
        )
        self.assertTrue(v.allowed)

    def test_drift_invalidates_tool(self):
        v = reproducibility_lock(
            tool_id="align-tool",
            tool_version="2.1.0",
            current_result_digest=HEX64_C,
            bindings=self.reg,
        )
        self.assertFalse(v.allowed)
        self.assertIn("reproduction_drift", v.reason)

    def test_unbound_tool_denies(self):
        v = reproducibility_lock(
            tool_id="new-tool",
            tool_version="0.1.0",
            current_result_digest=HEX64,
            bindings=self.reg,
        )
        self.assertFalse(v.allowed)
        self.assertIn("reproduction_drift", v.reason)


class EnvelopeTests(unittest.TestCase):
    def setUp(self):
        self.auth = _auth()
        self.reg = LabRobotEnvelopeRegistry(self.auth)
        self.reg.issue(
            receipt_id="env-1",
            robot_id="medra-1",
            instrument_allowlist=("pipettor", "centrifuge"),
            max_force_newtons=5.0,
            max_temperature_celsius=37.0,
            exclusion_zones=("pathogen-room",),
            declared_at=T0,
            authority_id="bench-sci-op",
            sign=_sign,
        )

    def test_in_envelope_allows(self):
        v = lab_robot_capability_envelope(
            robot_id="medra-1",
            instrument="pipettor",
            force_newtons=2.0,
            temperature_celsius=25.0,
            zone="bench-a",
            envelopes=self.reg,
        )
        self.assertTrue(v.allowed)

    def test_undeclared_instrument_denies(self):
        v = lab_robot_capability_envelope(
            robot_id="medra-1",
            instrument="laser-cutter",
            force_newtons=1.0,
            temperature_celsius=25.0,
            zone="bench-a",
            envelopes=self.reg,
        )
        self.assertFalse(v.allowed)
        self.assertIn("envelope_violation", v.reason)

    def test_force_over_limit_denies(self):
        v = lab_robot_capability_envelope(
            robot_id="medra-1",
            instrument="pipettor",
            force_newtons=50.0,
            temperature_celsius=25.0,
            zone="bench-a",
            envelopes=self.reg,
        )
        self.assertFalse(v.allowed)
        self.assertIn("envelope_violation", v.reason)

    def test_exclusion_zone_denies(self):
        v = lab_robot_capability_envelope(
            robot_id="medra-1",
            instrument="pipettor",
            force_newtons=1.0,
            temperature_celsius=25.0,
            zone="pathogen-room",
            envelopes=self.reg,
        )
        self.assertFalse(v.allowed)
        self.assertIn("envelope_violation", v.reason)

    def test_no_envelope_denies(self):
        v = lab_robot_capability_envelope(
            robot_id="ghost-bot",
            instrument="pipettor",
            force_newtons=1.0,
            temperature_celsius=25.0,
            zone="bench-a",
            envelopes=self.reg,
        )
        self.assertFalse(v.allowed)
        self.assertIn("envelope_violation", v.reason)


class AttributionTests(unittest.TestCase):
    def setUp(self):
        self.auth = _auth()
        self.reg = DiscoveryAttributionRegistry(self.auth)
        self.reg.issue(
            receipt_id="da-1",
            discovery_id="art-enzyme",
            goal_setter_id="anthropic-team",
            candidate_screener_id="ai:claude-art",
            wetlab_validator_id="dr-zhang",
            formal_record="paper",
            discovery_claim="AI-assisted discovery of a novel phage enzyme system",
            attributed_at=T0,
            authority_id="bench-sci-op",
            sign=_sign,
        )

    def test_proper_attribution_allows(self):
        v = discovery_attribution_receipt(
            discovery_id="art-enzyme",
            formal_record="paper",
            discovery_claim="AI-assisted discovery of a novel phage enzyme system",
            attributions=self.reg,
        )
        self.assertTrue(v.allowed)

    def test_marketing_claim_denies(self):
        v = discovery_attribution_receipt(
            discovery_id="art-enzyme",
            formal_record="paper",
            discovery_claim="AI independently discovered a novel enzyme system",
            attributions=self.reg,
        )
        self.assertFalse(v.allowed)
        self.assertIn("false_discovery_attribution", v.reason)

    def test_missing_receipt_denies(self):
        v = discovery_attribution_receipt(
            discovery_id="unknown",
            formal_record="paper",
            discovery_claim="Some careful claim",
            attributions=self.reg,
        )
        self.assertFalse(v.allowed)
        self.assertIn("false_discovery_attribution", v.reason)

    def test_ai_validator_rejected_at_issue(self):
        with self.assertRaises(ScienceError):
            self.reg.issue(
                receipt_id="da-2",
                discovery_id="x",
                goal_setter_id="team",
                candidate_screener_id="ai:bot",
                wetlab_validator_id="ai:bot",  # AI cannot validate itself
                formal_record="paper",
                discovery_claim="careful claim",
                attributed_at=T0,
                authority_id="bench-sci-op",
                sign=_sign,
            )


class IncidentLedgerTests(unittest.TestCase):
    def test_report_and_chain(self):
        ledger = LabIncidentLedger()
        v = lab_incident_reporting(
            incident_id="inc-1",
            incident_class="interlock_trip",
            institution_id="lab-east",
            robot_id="medra-1",
            description_digest=HEX64,
            reported_at=T0,
            reporter_signing_key=SEC,
            authority_pubkey_hex=PUB,
            ledger=ledger,
        )
        self.assertTrue(v.allowed)
        ledger.verify_chain()

    def test_bad_class_raises(self):
        ledger = LabIncidentLedger()
        with self.assertRaises(ScienceError):
            lab_incident_reporting(
                incident_id="inc-2",
                incident_class="meteor_strike",
                institution_id="lab-east",
                robot_id="medra-1",
                description_digest=HEX64,
                reported_at=T0,
                reporter_signing_key=SEC,
                authority_pubkey_hex=PUB,
                ledger=ledger,
            )


class SecurityRegressionTests(unittest.TestCase):
    def test_tampered_signature_rejected(self):
        # 147th-batch finding: ed25519.verify returns bool and never
        # raises; a tampered signature must deny, not pass silently.
        auth = _auth()
        reg = CitationVerificationRegistry(auth)
        rec = reg.issue(
            receipt_id="cv-x",
            citation_id="cx",
            doi="10.1038/x",
            title="t",
            resolved_at=T0,
            authority_id="bench-sci-op",
            sign=_sign,
        )
        tampered = rec.__class__(**{**rec.__dict__, "signature_hex": "ff" * 64})
        reg2 = CitationVerificationRegistry(auth)
        reg2.log.append(tampered)
        with self.assertRaises(ScienceError):
            reg2.verify_chain()

    def test_chain_break_detected(self):
        auth = _auth()
        reg = CitationVerificationRegistry(auth)
        r1 = reg.issue(
            receipt_id="cv-1", citation_id="a", doi="10.1/a", title="t",
            resolved_at=T0, authority_id="bench-sci-op", sign=_sign,
        )
        r2 = reg.issue(
            receipt_id="cv-2", citation_id="b", doi="10.1/b", title="t",
            resolved_at=T0, authority_id="bench-sci-op", sign=_sign,
        )
        broken = r2.__class__(**{**r2.__dict__, "prev_digest": "00" * 32})
        reg2 = CitationVerificationRegistry(auth)
        reg2.log.extend([r1, broken])
        with self.assertRaises(ScienceError):
            reg2.verify_chain()


if __name__ == "__main__":
    unittest.main()
