"""Tests for procurement_agents (one-hundred-thirty-eighth batch)."""

import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ed25519
from canonical_json import jcs_canonical_json

from procurement_agents import (
    DENY_AI_CONCLUDED,
    DENY_UNGROUNDED_CLAIM,
    DENY_UNSCREENED_DOC,
    DENY_COLLUSION_LEAD,
    DENY_INCOMPLETE_COLLUSION,
    DENY_MISSING_LOSING_BIDS,
    DENY_INCUMBENCY_BIAS,
    DENY_UNREGISTERED_ALGORITHM,
    DENY_REVOKED_ALGORITHM,
    DENY_INCOMPLETE_TRACE,
    DENY_UNSIGNED_REASONS,
    DENY_CHAIN_BROKEN,
    ProcurementError,
    AuthorityRegistry,
    SourceLocation,
    GroundedClaimReceipt,
    ClaimGroundingRegistry,
    HealthCheckReceipt,
    HealthCheckRegistry,
    AlgorithmRegistrationReceipt,
    AlgorithmRegistry,
    AwardTrace,
    advisory_only_gate,
    source_grounding_receipt,
    tender_doc_screen,
    collusion_probe,
    losing_bid_data_gate,
    incumbency_bias_probe,
    algorithm_registry_receipt,
    full_trace_award,
)


SEC = b"\x07" * 32
PUB = ed25519.public_key(SEC).hex()
T0 = 1_800_000_000
HEX64 = "ab" * 32
HEX64_B = "cd" * 32
HEX64_C = "ef" * 32


def _authorities():
    reg = AuthorityRegistry()
    reg.register("bench-op", PUB)
    return reg


def _issue_grounding(reg, receipt_id, claim_id, claim_digest, locations,
                     issued_at=T0):
    prev = reg.log[-1].receipt_digest if reg.log else "genesis"
    r = GroundedClaimReceipt(
        receipt_id=receipt_id, claim_id=claim_id, claim_digest=claim_digest,
        evaluation_id="eval-1", locations=tuple(locations),
        authority_id="bench-op", authority_pubkey_hex=PUB,
        signature_hex="00" * 64, issued_at=issued_at, prev_digest=prev)
    sig = ed25519.sign(SEC, jcs_canonical_json(r._payload()))
    return reg.issue(
        receipt_id=receipt_id, claim_id=claim_id, claim_digest=claim_digest,
        evaluation_id="eval-1", locations=tuple(locations),
        authority_id="bench-op", signature=sig, issued_at=issued_at)


def _issue_health(reg, receipt_id, doc_id, doc_digest, checks,
                  issued_at=T0, expires_at=T0 + 3600):
    prev = reg.log[-1].receipt_digest if reg.log else "genesis"
    r = HealthCheckReceipt(
        receipt_id=receipt_id, doc_id=doc_id, doc_digest=doc_digest,
        checks_run=tuple(checks), authority_id="bench-op",
        authority_pubkey_hex=PUB, signature_hex="00" * 64,
        issued_at=issued_at, expires_at=expires_at, prev_digest=prev)
    sig = ed25519.sign(SEC, jcs_canonical_json(r._payload()))
    return reg.issue(
        receipt_id=receipt_id, doc_id=doc_id, doc_digest=doc_digest,
        checks_run=tuple(checks), authority_id="bench-op", signature=sig,
        issued_at=issued_at, expires_at=expires_at)


def _issue_algorithm(reg, receipt_id, algorithm_id, version,
                     registered_at=T0, expires_at=T0 + 3600):
    prev = reg.log[-1].receipt_digest if reg.log else "genesis"
    r = AlgorithmRegistrationReceipt(
        receipt_id=receipt_id, algorithm_id=algorithm_id, version=version,
        review_digest=HEX64_C, authority_id="bench-op",
        authority_pubkey_hex=PUB, signature_hex="00" * 64,
        registered_at=registered_at, expires_at=expires_at, prev_digest=prev)
    sig = ed25519.sign(SEC, jcs_canonical_json(r._payload()))
    return reg.issue(
        receipt_id=receipt_id, algorithm_id=algorithm_id, version=version,
        review_digest=HEX64_C, authority_id="bench-op", signature=sig,
        registered_at=registered_at, expires_at=expires_at)


def _sign_reasons(award_id, evaluator_id, reasons_digest):
    payload = {"award_id": award_id, "evaluator_id": evaluator_id,
               "final_reasons_digest": reasons_digest}
    return ed25519.sign(SEC, jcs_canonical_json(payload)).hex()


class AdvisoryOnlyTest(unittest.TestCase):
    def test_ai_concluded_deny(self):
        v = advisory_only_gate("a-1", "eval-zhang", ai_scored=True,
                               human_scored=True, human_wrote_reasons=False,
                               human_signed=True)
        self.assertFalse(v.allowed)
        self.assertIn(DENY_AI_CONCLUDED, v.reason)

    def test_full_human_allow(self):
        v = advisory_only_gate("a-1", "eval-zhang", ai_scored=True,
                               human_scored=True, human_wrote_reasons=True,
                               human_signed=True)
        self.assertTrue(v.allowed)

    def test_no_ai_full_human_allow(self):
        v = advisory_only_gate("a-2", "eval-li", ai_scored=False,
                               human_scored=True, human_wrote_reasons=True,
                               human_signed=True)
        self.assertTrue(v.allowed)

    def test_no_human_no_ai_deny(self):
        v = advisory_only_gate("a-3", "eval-li", ai_scored=False,
                               human_scored=False, human_wrote_reasons=False,
                               human_signed=False)
        self.assertFalse(v.allowed)
        self.assertIn("no_human_accountability", v.reason)

    def test_malformed_raises(self):
        with self.assertRaises(ProcurementError):
            advisory_only_gate("", "eval-li", ai_scored=False,
                               human_scored=True, human_wrote_reasons=True,
                               human_signed=True)


class SourceGroundingTest(unittest.TestCase):
    def test_grounded_claim_allow(self):
        reg = ClaimGroundingRegistry(_authorities())
        loc = SourceLocation("tender-9", "section-4.2", HEX64_B)
        _issue_grounding(reg, "g-1", "claim-1", HEX64, (loc,))
        v = source_grounding_receipt(reg, "claim-1", HEX64)
        self.assertTrue(v.allowed)
        self.assertTrue(v.receipt_digest)

    def test_ungrounded_claim_deny(self):
        reg = ClaimGroundingRegistry(_authorities())
        v = source_grounding_receipt(reg, "claim-9", HEX64)
        self.assertFalse(v.allowed)
        self.assertIn(DENY_UNGROUNDED_CLAIM, v.reason)

    def test_tampered_chain_deny(self):
        reg = ClaimGroundingRegistry(_authorities())
        loc = SourceLocation("tender-9", "section-4.2", HEX64_B)
        sealed = _issue_grounding(reg, "g-1", "claim-1", HEX64, (loc,))
        reg.log[0] = type(sealed)(**{**sealed.__dict__, "claim_id": "claim-X"})
        v = source_grounding_receipt(reg, "claim-1", HEX64)
        self.assertFalse(v.allowed)
        self.assertIn(DENY_CHAIN_BROKEN, v.reason)

    def test_empty_locations_raise(self):
        reg = ClaimGroundingRegistry(_authorities())
        with self.assertRaises(ProcurementError):
            _issue_grounding(reg, "g-2", "claim-2", HEX64, ())


class TenderDocScreenTest(unittest.TestCase):
    def test_screened_doc_allow(self):
        reg = HealthCheckRegistry(_authorities())
        _issue_health(reg, "h-1", "doc-1", HEX64,
                      ("suspicious_clauses", "consistency"))
        v = tender_doc_screen(reg, "doc-1", HEX64, T0)
        self.assertTrue(v.allowed)

    def test_unscreened_doc_deny(self):
        reg = HealthCheckRegistry(_authorities())
        v = tender_doc_screen(reg, "doc-9", HEX64, T0)
        self.assertFalse(v.allowed)
        self.assertIn(DENY_UNSCREENED_DOC, v.reason)

    def test_expired_screen_deny(self):
        reg = HealthCheckRegistry(_authorities())
        _issue_health(reg, "h-1", "doc-1", HEX64, ("consistency",),
                      issued_at=T0 - 7200, expires_at=T0 - 3600)
        v = tender_doc_screen(reg, "doc-1", HEX64, T0)
        self.assertFalse(v.allowed)
        self.assertIn(DENY_UNSCREENED_DOC, v.reason)

    def test_wrong_doc_digest_deny(self):
        reg = HealthCheckRegistry(_authorities())
        _issue_health(reg, "h-1", "doc-1", HEX64, ("consistency",))
        v = tender_doc_screen(reg, "doc-1", HEX64_B, T0)
        self.assertFalse(v.allowed)
        self.assertIn(DENY_UNSCREENED_DOC, v.reason)


class CollusionProbeTest(unittest.TestCase):
    def test_collusion_lead_is_not_conviction(self):
        v = collusion_probe(HEX64, HEX64_B, HEX64_C, 0.85, 0.7)
        self.assertFalse(v.allowed)
        self.assertIn(DENY_COLLUSION_LEAD, v.reason)
        self.assertIn("not a conviction", v.reason)

    def test_incomplete_evidence_deny(self):
        v = collusion_probe(HEX64, None, HEX64_C, 0.9, 0.7)
        self.assertFalse(v.allowed)
        self.assertIn(DENY_INCOMPLETE_COLLUSION, v.reason)

    def test_below_threshold_allow(self):
        v = collusion_probe(HEX64, HEX64_B, HEX64_C, 0.3, 0.7)
        self.assertTrue(v.allowed)

    def test_bad_threshold_raises(self):
        with self.assertRaises(ProcurementError):
            collusion_probe(HEX64, HEX64_B, HEX64_C, 0.9, 1.5)


class LosingBidDataTest(unittest.TestCase):
    def test_missing_losing_bids_deny(self):
        v = losing_bid_data_gate("eval-1", 3, 1, 5)
        self.assertFalse(v.allowed)
        self.assertIn(DENY_MISSING_LOSING_BIDS, v.reason)

    def test_sufficient_losing_bids_allow(self):
        v = losing_bid_data_gate("eval-1", 3, 12, 5)
        self.assertTrue(v.allowed)

    def test_negative_raises(self):
        with self.assertRaises(ProcurementError):
            losing_bid_data_gate("eval-1", 3, -1, 5)


class IncumbencyBiasTest(unittest.TestCase):
    def test_incumbency_bias_deny(self):
        # 80% new-supplier rejection vs 20% incumbent: the 4x anecdote shape.
        v = incumbency_bias_probe(8, 10, 2, 10, 0.25)
        self.assertFalse(v.allowed)
        self.assertIn(DENY_INCUMBENCY_BIAS, v.reason)

    def test_within_tolerance_allow(self):
        v = incumbency_bias_probe(3, 10, 2, 10, 0.25)
        self.assertTrue(v.allowed)

    def test_zero_total_raises(self):
        with self.assertRaises(ProcurementError):
            incumbency_bias_probe(0, 0, 2, 10, 0.25)


class AlgorithmRegistryTest(unittest.TestCase):
    def test_registered_algorithm_allow(self):
        reg = AlgorithmRegistry(_authorities())
        _issue_algorithm(reg, "r-1", "eval-scorer", "1.4.2")
        v = algorithm_registry_receipt(reg, "eval-scorer", "1.4.2", T0)
        self.assertTrue(v.allowed)

    def test_unregistered_deny(self):
        reg = AlgorithmRegistry(_authorities())
        v = algorithm_registry_receipt(reg, "ghost-scorer", "9.9.9", T0)
        self.assertFalse(v.allowed)
        self.assertIn(DENY_UNREGISTERED_ALGORITHM, v.reason)

    def test_wrong_version_deny(self):
        reg = AlgorithmRegistry(_authorities())
        _issue_algorithm(reg, "r-1", "eval-scorer", "1.4.2")
        v = algorithm_registry_receipt(reg, "eval-scorer", "2.0.0", T0)
        self.assertFalse(v.allowed)
        self.assertIn(DENY_UNREGISTERED_ALGORITHM, v.reason)

    def test_revoked_deny(self):
        reg = AlgorithmRegistry(_authorities())
        _issue_algorithm(reg, "r-1", "eval-scorer", "1.4.2")
        reg.revoke("r-1")
        v = algorithm_registry_receipt(reg, "eval-scorer", "1.4.2", T0)
        self.assertFalse(v.allowed)
        self.assertIn(DENY_REVOKED_ALGORITHM, v.reason)

    def test_expired_deny(self):
        reg = AlgorithmRegistry(_authorities())
        _issue_algorithm(reg, "r-1", "eval-scorer", "1.4.2",
                         registered_at=T0 - 7200, expires_at=T0 - 3600)
        v = algorithm_registry_receipt(reg, "eval-scorer", "1.4.2", T0)
        self.assertFalse(v.allowed)
        self.assertIn(DENY_UNREGISTERED_ALGORITHM, v.reason)


class FullTraceAwardTest(unittest.TestCase):
    def _trace(self, **kw):
        base = dict(trace_id="t-1", award_id="a-1", evaluator_id="eval-zhang",
                    ai_input_digest=HEX64, ai_output_digest=HEX64_B,
                    human_edits_digest=HEX64_C, final_reasons_digest=HEX64,
                    reasons_signature_hex=_sign_reasons("a-1", "eval-zhang", HEX64),
                    reasons_pubkey_hex=PUB, traced_at=T0)
        base.update(kw)
        return AwardTrace(**base)

    def test_full_trace_allow(self):
        v = full_trace_award(self._trace())
        self.assertTrue(v.allowed)

    def test_missing_ai_segment_deny(self):
        v = full_trace_award(self._trace(ai_input_digest=None))
        self.assertFalse(v.allowed)
        self.assertIn(DENY_INCOMPLETE_TRACE, v.reason)

    def test_missing_human_segment_deny(self):
        v = full_trace_award(self._trace(final_reasons_digest=None))
        self.assertFalse(v.allowed)
        self.assertIn(DENY_INCOMPLETE_TRACE, v.reason)

    def test_unsigned_reasons_deny(self):
        v = full_trace_award(self._trace(reasons_signature_hex=None))
        self.assertFalse(v.allowed)
        self.assertIn(DENY_UNSIGNED_REASONS, v.reason)

    def test_no_ai_involved_allow(self):
        v = full_trace_award(
            self._trace(ai_input_digest=None, ai_output_digest=None),
            no_ai_involved=True)
        self.assertTrue(v.allowed)


if __name__ == "__main__":
    unittest.main()
