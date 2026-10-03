"""Tests for pharma_agents.py (one-hundred-thirty-fifth batch).

Deterministic: fixed 32-byte seeds, injected integer timestamps.
"""

import unittest

import ed25519

from pharma_agents import (
    ALCOA_ATTRIBUTES,
    CLASS_AUTHORITATIVE,
    CLASS_NON_AUTHORITATIVE,
    DOC_CLASSES,
    MODEL_CLASSES,
    PHARMA_SCHEMA_VERSION,
    AlcoaProbeVerdict,
    GmpDocumentChainLog,
    PharmaError,
    alcoa_probe,
    check_model_lineage,
    context_of_use_binding,
    context_of_use_receipt,
    drift_monitor_gate,
    drift_monitor_receipt,
    full_production_gate,
    generative_exclusion_gate,
    gmp_document_receipt,
    model_deployment_receipt,
    model_lineage_receipt,
    pharma_claim_evidence,
    pharma_claim_receipt,
    quality_unit_countersign,
    static_model_only,
    use_in_production,
)
from canonical_json import jcs_sha256_hex

SEED_AUTH = bytes(range(32))
SEED_COUNTER = bytes(32 - i for i in range(32))
PUB_AUTH = ed25519.public_key(SEED_AUTH).hex()
PUB_COUNTER = ed25519.public_key(SEED_COUNTER).hex()
NOW = 1_800_000_000


def _doc(drafted_by_ai=True, **kw):
    args = dict(
        receipt_id="doc-1",
        prev_digest="genesis",
        doc_class="batch_record",
        doc_digest=jcs_sha256_hex({"doc": "batch-record-42"}),
        drafted_by_ai=drafted_by_ai,
        counter_public_hex=PUB_COUNTER,
        counter_at=NOW - 100,
        counter_secret=SEED_COUNTER if drafted_by_ai else None,
        authority_pubkey_hex=PUB_AUTH,
        authority_secret=SEED_AUTH,
    )
    args.update(kw)
    return gmp_document_receipt(**args)


def _model(model_class="static_deterministic", criticality="critical", **kw):
    args = dict(
        receipt_id="model-1",
        prev_digest="genesis",
        model_id="hplc-qc-7",
        model_class=model_class,
        model_version="v2.3.1",
        model_digest=jcs_sha256_hex({"weights": "frozen"}),
        locked=True,
        criticality=criticality,
        authority_pubkey_hex=PUB_AUTH,
        authority_secret=SEED_AUTH,
    )
    args.update(kw)
    return model_deployment_receipt(**args)


def _lineage(**kw):
    args = dict(
        receipt_id="lin-1",
        prev_digest="genesis",
        model_version="v2.3.1",
        training_data_digest=jcs_sha256_hex({"train": "batch-7"}),
        input_digest=jcs_sha256_hex({"in": "spectra"}),
        output_digest=jcs_sha256_hex({"out": "pass"}),
        authority_pubkey_hex=PUB_AUTH,
        authority_secret=SEED_AUTH,
    )
    args.update(kw)
    return model_lineage_receipt(**args)


def _drift(metric=0.02, tolerance=0.05, **kw):
    args = dict(
        receipt_id="drift-1",
        prev_digest="genesis",
        model_id="hplc-qc-7",
        drift_metric=metric,
        tolerance=tolerance,
        checked_at=NOW - 1000,
        authority_pubkey_hex=PUB_AUTH,
        authority_secret=SEED_AUTH,
    )
    args.update(kw)
    return drift_monitor_receipt(**args)


class CountersignTests(unittest.TestCase):
    def test_ai_draft_with_live_countersign_allows(self):
        r = _doc()
        v = quality_unit_countersign(r, r.countersignature_hex, now=NOW)
        self.assertTrue(v.allowed)
        self.assertEqual(v.classification, CLASS_AUTHORITATIVE)

    def test_ai_draft_without_countersign_is_non_authoritative(self):
        r = _doc()
        v = quality_unit_countersign(r, "", now=NOW)
        self.assertFalse(v.allowed)
        self.assertIn("pharma.unsigned_draft", v.reason)
        self.assertEqual(v.classification, CLASS_NON_AUTHORITATIVE)

    def test_ai_draft_with_tampered_countersign_denies(self):
        r = _doc()
        bad = "00" * 64
        v = quality_unit_countersign(r, bad, now=NOW)
        self.assertFalse(v.allowed)
        self.assertIn("pharma.unsigned_draft", v.reason)

    def test_stale_countersign_denies(self):
        r = _doc(counter_at=NOW - 31 * 86_400)
        v = quality_unit_countersign(r, r.countersignature_hex, now=NOW)
        self.assertFalse(v.allowed)
        self.assertIn("pharma.unsigned_draft", v.reason)

    def test_human_authored_needs_no_countersign(self):
        r = _doc(drafted_by_ai=False)
        v = quality_unit_countersign(r, "", now=NOW)
        self.assertTrue(v.allowed)

    def test_production_use_of_unsigned_ai_draft_is_judgment(self):
        r = _doc()
        v = use_in_production(r, "", now=NOW)
        self.assertFalse(v.allowed)
        self.assertIn("pharma.undisclosed_judgment", v.reason)

    def test_production_use_of_signed_ai_draft_allows(self):
        r = _doc()
        v = use_in_production(r, r.countersignature_hex, now=NOW)
        self.assertTrue(v.allowed)


class StaticModelTests(unittest.TestCase):
    def test_static_locked_model_on_critical_allows(self):
        self.assertTrue(static_model_only(_model()).allowed)

    def test_dynamic_model_on_critical_denies(self):
        v = static_model_only(_model(model_class="dynamic_adaptive"))
        self.assertFalse(v.allowed)
        self.assertIn("pharma.dynamic_model", v.reason)

    def test_continuous_learning_on_critical_denies(self):
        v = static_model_only(_model(model_class="continuous_learning"))
        self.assertFalse(v.allowed)
        self.assertIn("pharma.dynamic_model", v.reason)

    def test_generative_in_critical_denies(self):
        v = static_model_only(_model(model_class="generative_llm"))
        self.assertFalse(v.allowed)
        self.assertIn("pharma.generative_in_critical", v.reason)

    def test_dynamic_on_non_critical_allows_static_gate(self):
        self.assertTrue(static_model_only(_model(model_class="dynamic_adaptive", criticality="non_critical")).allowed)

    def test_generative_noncritical_needs_qualified_person(self):
        r = _model(model_class="generative_llm", criticality="non_critical")
        v = generative_exclusion_gate(r, qualified_person_in_loop=False)
        self.assertFalse(v.allowed)
        self.assertIn("pharma.unreviewed_generation", v.reason)
        self.assertTrue(generative_exclusion_gate(r, qualified_person_in_loop=True).allowed)

    def test_unknown_model_class_raises(self):
        with self.assertRaises(PharmaError):
            _model(model_class="self_improving")


class LineageTests(unittest.TestCase):
    def test_full_lineage_allows(self):
        v = check_model_lineage(_lineage(), model_version="v2.3.1")
        self.assertTrue(v.allowed)

    def test_missing_lineage_denies(self):
        v = check_model_lineage(None, model_version="v2.3.1")
        self.assertFalse(v.allowed)
        self.assertIn("pharma.missing_lineage", v.reason)

    def test_version_mismatch_denies(self):
        v = check_model_lineage(_lineage(), model_version="v9.9.9")
        self.assertFalse(v.allowed)
        self.assertIn("pharma.missing_lineage", v.reason)


class AlcoaTests(unittest.TestCase):
    def test_all_nine_attributes_pass(self):
        v = alcoa_probe({a: True for a in ALCOA_ATTRIBUTES})
        self.assertIsInstance(v, AlcoaProbeVerdict)
        self.assertTrue(v.passed)

    def test_missing_attribute_fails_and_names_it(self):
        attrs = {a: True for a in ALCOA_ATTRIBUTES}
        attrs["contemporaneous"] = False
        v = alcoa_probe(attrs)
        self.assertFalse(v.passed)
        self.assertIn("contemporaneous", v.missing_attributes)
        self.assertIn("pharma.alcoa_violation", v.reason)

    def test_none_map_fails(self):
        v = alcoa_probe(None)
        self.assertFalse(v.passed)
        self.assertEqual(len(v.missing_attributes), 9)


class ContextTests(unittest.TestCase):
    def _ctx(self, **kw):
        args = dict(
            receipt_id="ctx-1",
            prev_digest="genesis",
            model_id="hplc-qc-7",
            context_digest=jcs_sha256_hex({"context": "peptide-hplc"}),
            authority_pubkey_hex=PUB_AUTH,
            authority_secret=SEED_AUTH,
        )
        args.update(kw)
        return context_of_use_receipt(**args)

    def test_matching_context_allows(self):
        r = self._ctx()
        v = context_of_use_binding(r, actual_context_digest=r.context_digest)
        self.assertTrue(v.allowed)

    def test_outside_context_degrades(self):
        r = self._ctx()
        v = context_of_use_binding(
            r, actual_context_digest=jcs_sha256_hex({"context": "vaccine-fill"}))
        self.assertFalse(v.allowed)
        self.assertIn("pharma.context_violation", v.reason)
        self.assertEqual(v.classification, CLASS_NON_AUTHORITATIVE)

    def test_no_declaration_denies(self):
        v = context_of_use_binding(None, actual_context_digest=jcs_sha256_hex({"x": 1}))
        self.assertFalse(v.allowed)
        self.assertIn("pharma.undeclared_context", v.reason)


class DriftTests(unittest.TestCase):
    def test_within_tolerance_allows(self):
        self.assertTrue(drift_monitor_gate(_drift(), now=NOW).allowed)

    def test_beyond_tolerance_requires_revalidation(self):
        v = drift_monitor_gate(_drift(metric=0.09, tolerance=0.05), now=NOW)
        self.assertFalse(v.allowed)
        self.assertIn("pharma.revalidation_required", v.reason)

    def test_no_monitor_is_non_authoritative(self):
        v = drift_monitor_gate(None, now=NOW)
        self.assertFalse(v.allowed)
        self.assertIn("pharma.drift_unmonitored", v.reason)

    def test_stale_monitor_counts_as_no_monitor(self):
        v = drift_monitor_gate(_drift(checked_at=NOW - 8 * 86_400), now=NOW)
        self.assertFalse(v.allowed)
        self.assertIn("pharma.drift_unmonitored", v.reason)


class ClaimTests(unittest.TestCase):
    def _claim(self, **kw):
        args = dict(
            receipt_id="claim-1",
            prev_digest="genesis",
            claim_digest=jcs_sha256_hex({"numbers": "70pct"}),
            evidence_digest=jcs_sha256_hex({"trial": "protocol-7"}),
            authority_pubkey_hex=PUB_AUTH,
            authority_secret=SEED_AUTH,
        )
        args.update(kw)
        return pharma_claim_receipt(**args)

    def test_bound_evidence_allows(self):
        r = self._claim()
        v = pharma_claim_evidence(r, claimed_numbers_digest=r.claim_digest)
        self.assertTrue(v.allowed)

    def test_no_evidence_denies(self):
        v = pharma_claim_evidence(None, claimed_numbers_digest=jcs_sha256_hex({"n": 1}))
        self.assertFalse(v.allowed)
        self.assertIn("pharma.unverified_claim", v.reason)

    def test_mismatched_numbers_deny(self):
        r = self._claim()
        v = pharma_claim_evidence(r, claimed_numbers_digest=jcs_sha256_hex({"numbers": "99pct"}))
        self.assertFalse(v.allowed)
        self.assertIn("pharma.unverified_claim", v.reason)


class ChainLogTests(unittest.TestCase):
    def test_chain_break_detected(self):
        log = GmpDocumentChainLog(PUB_AUTH)
        r1 = _doc(receipt_id="doc-1")
        log.append(r1)
        r2 = _doc(receipt_id="doc-2", prev_digest="ab" * 32)  # valid hex, wrong chain head
        with self.assertRaises(PharmaError):
            log.append(r2)


class FullGateTests(unittest.TestCase):
    def test_full_gate_all_pass(self):
        doc = _doc()
        model = _model()
        lin = _lineage()
        ctx = context_of_use_receipt(
            receipt_id="ctx-9", prev_digest="genesis", model_id="hplc-qc-7",
            context_digest=jcs_sha256_hex({"context": "peptide-hplc"}),
            authority_pubkey_hex=PUB_AUTH, authority_secret=SEED_AUTH)
        claim = pharma_claim_receipt(
            receipt_id="cl-9", prev_digest="genesis",
            claim_digest=jcs_sha256_hex({"numbers": "70pct"}),
            evidence_digest=jcs_sha256_hex({"trial": "protocol-7"}),
            authority_pubkey_hex=PUB_AUTH, authority_secret=SEED_AUTH)
        out = full_production_gate(
            doc_receipt=doc, countersignature_hex=doc.countersignature_hex,
            model_receipt=model, lineage=lin,
            alcoa_attributes={a: True for a in ALCOA_ATTRIBUTES},
            context_receipt=ctx,
            actual_context_digest=ctx.context_digest,
            drift=_drift(), claim=claim,
            claimed_numbers_digest=claim.claim_digest,
            generative_qualified_person=False, now=NOW)
        for name, v in out.items():
            self.assertTrue(v.passed if isinstance(v, AlcoaProbeVerdict) else v.allowed, name)

    def test_full_gate_fail_closed(self):
        doc = _doc()
        out = full_production_gate(
            doc_receipt=doc, countersignature_hex="",
            model_receipt=_model(model_class="dynamic_adaptive"),
            lineage=None, alcoa_attributes=None,
            context_receipt=None,
            actual_context_digest=jcs_sha256_hex({"c": "other"}),
            drift=None, claim=None,
            claimed_numbers_digest=jcs_sha256_hex({"n": 1}),
            generative_qualified_person=False, now=NOW)
        bad = [n for n, v in out.items()
               if not (v.passed if isinstance(v, AlcoaProbeVerdict) else v.allowed)]
        # generative_exclusion passes: a dynamic model is not a generative one
        self.assertEqual(sorted(bad), sorted(set(out) - {"generative_exclusion"}))


if __name__ == "__main__":
    unittest.main()
