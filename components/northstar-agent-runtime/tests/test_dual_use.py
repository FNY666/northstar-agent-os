"""Tests for dual_use.py (one-hundred-eleventh batch)."""

import unittest

from canonical_json import jcs_sha256_hex
from dual_use import (
    CALL_ALLOW,
    CALL_ESCALATE,
    CALL_NON_AUTHORITATIVE,
    CITATION_FINDING_THRESHOLD,
    CLAIM_AUTHORITATIVE,
    CLAIM_NON_AUTHORITATIVE,
    CLAIM_UNUNDERSTOOD,
    CONSTRAINT_EVENT,
    DUAL_USE_HIT_EVENT,
    DENY_CONSTRAINT_TAMPER,
    DENY_DUAL_USE_HIT,
    DENY_NO_CONSTRAINTS,
    DENY_VERIFIER_REJECT,
    AuthorityRegistry,
    ClaimRegistry,
    DualUseError,
    MechanicalVerifier,
    ScienceTaskGate,
    authority_keypair,
    check_citations,
    issue_constraint_binding,
    screen_tool_call,
    sign_binding_digest,
    _binding_digest_for_signing,
)

T0 = 1_789_000_000
LIST_DIGEST = jcs_sha256_hex({"constraints": ["no pathogens", "physics only"]})


def _registry_with_authority():
    pub, seed = authority_keypair(b"\x01" * 32)
    return AuthorityRegistry({"lab-director": pub}), seed


def _signed_binding(seed, **over):
    kw = dict(
        task_id="task-1",
        constraint_list_digest=LIST_DIGEST,
        constraint_source="lab-safety-manual-v3",
        issued_by="lab-director",
        issued_at=T0,
        prev_hash="",
    )
    kw.update(over)
    digest = _binding_digest_for_signing(
        task_id=kw["task_id"],
        constraint_list_digest=kw["constraint_list_digest"],
        constraint_source=kw["constraint_source"],
        issued_by=kw["issued_by"],
        issued_at=kw["issued_at"],
        prev_hash=kw["prev_hash"],
    )
    return kw, sign_binding_digest(seed, digest)


class ConstraintBindingTests(unittest.TestCase):
    def test_issue_and_register(self):
        registry, seed = _registry_with_authority()
        kw, sig = _signed_binding(seed)
        gate = ScienceTaskGate(registry)
        binding = issue_constraint_binding(registry, signature=sig, **kw)
        gate.register(binding)
        verdict = gate.require_binding("task-1", T0)
        self.assertTrue(verdict.allowed)
        self.assertEqual(verdict.reason, "constraints_bound")
        self.assertEqual(verdict.audit_event["event"], CONSTRAINT_EVENT)

    def test_missing_binding_denies(self):
        registry, _seed = _registry_with_authority()
        gate = ScienceTaskGate(registry)
        verdict = gate.require_binding("no-such-task", T0)
        self.assertFalse(verdict.allowed)
        self.assertEqual(verdict.reason, DENY_NO_CONSTRAINTS)

    def test_unknown_authority_fails_loud(self):
        registry, seed = _registry_with_authority()
        kw, sig = _signed_binding(seed, issued_by="impostor")
        with self.assertRaises(DualUseError):
            issue_constraint_binding(registry, signature=sig, **kw)

    def test_bad_signature_fails_loud(self):
        registry, seed = _registry_with_authority()
        kw, sig = _signed_binding(seed)
        bad = bytearray(sig)
        bad[0] ^= 0xFF
        with self.assertRaises(DualUseError):
            issue_constraint_binding(registry, signature=bytes(bad), **kw)

    def test_chain_gap_rejected(self):
        registry, seed = _registry_with_authority()
        gate = ScienceTaskGate(registry)
        kw, sig = _signed_binding(seed)
        gate.register(issue_constraint_binding(registry, signature=sig, **kw))
        kw2, sig2 = _signed_binding(seed, prev_hash=jcs_sha256_hex({"x": 1}))
        with self.assertRaises(DualUseError):
            gate.register(issue_constraint_binding(registry, signature=sig2, **kw2))

    def test_second_binding_chains(self):
        registry, seed = _registry_with_authority()
        gate = ScienceTaskGate(registry)
        kw, sig = _signed_binding(seed)
        first = issue_constraint_binding(registry, signature=sig, **kw)
        gate.register(first)
        kw2, sig2 = _signed_binding(
            seed, prev_hash=first.binding_digest, issued_at=T0 + 10
        )
        second = issue_constraint_binding(registry, signature=sig2, **kw2)
        gate.register(second)
        self.assertTrue(gate.require_binding("task-1", T0).allowed)


class ScreenToolCallTests(unittest.TestCase):
    def test_clean_call_allows(self):
        v = screen_tool_call("task-1", "search_papers", {"query": "perovskite"}, T0)
        self.assertTrue(v.allowed)
        self.assertEqual(v.classification, CALL_ALLOW)

    def test_watchlist_hit_escalates(self):
        v = screen_tool_call(
            "task-1", "order_reagents", {"item": "dna synthesis kit"}, T0
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.classification, CALL_ESCALATE)
        self.assertEqual(v.reason, DENY_DUAL_USE_HIT)
        self.assertEqual(v.audit_event["event"], DUAL_USE_HIT_EVENT)
        self.assertEqual(v.matched_family, "bio:pathogen_synthesis")

    def test_screening_bypass_hit(self):
        v = screen_tool_call(
            "task-1",
            "run_experiment",
            {"note": "screening bypass requested for speed"},
            T0,
        )
        self.assertEqual(v.classification, CALL_ESCALATE)
        self.assertEqual(v.matched_family, "bio:screening_bypass")

    def test_opentrons_hit(self):
        v = screen_tool_call(
            "task-1", "opentrons", {"protocol": "pipette"}, T0
        )
        self.assertEqual(v.classification, CALL_ESCALATE)
        self.assertEqual(v.matched_family, "robotics:wetlab")

    def test_near_hit_non_authoritative(self):
        v = screen_tool_call(
            "task-1", "run_sim", {"target": "crispr off-target model"}, T0
        )
        self.assertFalse(v.allowed)
        self.assertEqual(v.classification, CALL_NON_AUTHORITATIVE)

    def test_case_insensitive(self):
        v = screen_tool_call(
            "task-1", "ORDER", {"item": "DNA SYNTHESIS"}, T0
        )
        self.assertEqual(v.classification, CALL_ESCALATE)

    def test_malformed_raises(self):
        with self.assertRaises(DualUseError):
            screen_tool_call("", "tool", {}, T0)


class ClaimRegistryTests(unittest.TestCase):
    def test_claim_starts_non_authoritative(self):
        reg = ClaimRegistry()
        claim = reg.register_claim(
            claim_id="c1", assertion="X cures Y", produced_by="model-a",
            method_digest=LIST_DIGEST, created_unix=T0,
        )
        self.assertEqual(claim.classification, CLAIM_NON_AUTHORITATIVE)
        self.assertEqual(reg.reusable_conclusions(), ())

    def test_replication_promotes_on_match(self):
        reg = ClaimRegistry()
        reg.register_claim(
            claim_id="c1", assertion="X", produced_by="model-a",
            method_digest=LIST_DIGEST, created_unix=T0,
        )
        updated = reg.record_replication("c1", LIST_DIGEST, T0)
        self.assertEqual(updated.classification, CLAIM_AUTHORITATIVE)
        self.assertEqual(len(reg.reusable_conclusions()), 1)

    def test_replication_mismatch_fails_loud(self):
        reg = ClaimRegistry()
        reg.register_claim(
            claim_id="c1", assertion="X", produced_by="model-a",
            method_digest=LIST_DIGEST, created_unix=T0,
        )
        with self.assertRaises(DualUseError):
            reg.record_replication("c1", jcs_sha256_hex({"other": 1}), T0)

    def test_countersign_promotes(self):
        reg = ClaimRegistry()
        reg.register_claim(
            claim_id="c1", assertion="X", produced_by="model-a", created_unix=T0,
        )
        updated = reg.countersign("c1", "dr-expert", T0)
        self.assertEqual(updated.classification, CLAIM_AUTHORITATIVE)
        self.assertEqual(updated.countersigned_by, "dr-expert")

    def test_self_countersign_refused(self):
        reg = ClaimRegistry()
        reg.register_claim(
            claim_id="c1", assertion="X", produced_by="model-a", created_unix=T0,
        )
        with self.assertRaises(DualUseError):
            reg.countersign("c1", "model-a", T0)

    def test_ununderstood_never_promotes(self):
        reg = ClaimRegistry()
        reg.register_claim(
            claim_id="c1", assertion="breakthrough!", produced_by="model-a",
            created_unix=T0,
        )
        reg.mark_ununderstood("c1", T0)
        with self.assertRaises(DualUseError):
            reg.countersign("c1", "dr-expert", T0)
        with self.assertRaises(DualUseError):
            reg.record_replication("c1", LIST_DIGEST, T0)
        self.assertEqual(reg.reusable_conclusions(), ())


class CitationTests(unittest.TestCase):
    def test_clean_citations_authoritative(self):
        doc = (
            "[1] Smith et al., Nature 2026. doi:10.1038/s41586-026-12345\n"
            "[2] arXiv:2608.22118\n"
        )
        v = check_citations(doc, T0)
        self.assertEqual(v.classification, CLAIM_AUTHORITATIVE)
        self.assertEqual(v.n_findings, 0)

    def test_mass_unparseable_non_authoritative(self):
        doc = (
            "[1] some vague mention\n"
            "[2] another vague mention\n"
            "[3] totally fabricated ref\n"
            "[4] Smith et al., Nature 2026\n"
        )
        v = check_citations(doc, T0)
        self.assertGreater(v.n_findings / v.n_slots, CITATION_FINDING_THRESHOLD)
        self.assertEqual(v.classification, CLAIM_NON_AUTHORITATIVE)

    def test_empty_doc_authoritative(self):
        v = check_citations("no citations here\n", T0)
        self.assertEqual(v.n_slots, 0)
        self.assertEqual(v.classification, CLAIM_AUTHORITATIVE)


class MechanicalVerifierTests(unittest.TestCase):
    def test_accept_authorizes(self):
        mv = MechanicalVerifier()
        mv.declare("g1", "generator-a", "lean-checker", T0)
        v = mv.gate("g1", True, T0)
        self.assertTrue(v.allowed)

    def test_reject_rejects_no_override(self):
        mv = MechanicalVerifier()
        mv.declare("g1", "generator-a", "lean-checker", T0)
        v = mv.gate("g1", False, T0)
        self.assertFalse(v.allowed)
        self.assertEqual(v.reason, DENY_VERIFIER_REJECT)

    def test_self_verifier_refused(self):
        mv = MechanicalVerifier()
        with self.assertRaises(DualUseError):
            mv.declare("g1", "generator-a", "generator-a", T0)

    def test_unknown_task_denies(self):
        mv = MechanicalVerifier()
        v = mv.gate("nope", True, T0)
        self.assertFalse(v.allowed)


if __name__ == "__main__":
    unittest.main()
