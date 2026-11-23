"""Tests for deception_detector: false claims, evidence concealment, fabrication."""

import unittest

from deception_detector import (
    DECEPTION_DETECTOR_VERSION,
    SCHEMA_PIN,
    DeceptionType,
    DetectionResult,
    Evidence,
    analyze_deception,
    classify_deception,
    detect_deception,
)


def ev(**kw):
    facts = kw.get("facts", {"highest_bid": "120", "failures": "3"})
    sources = kw.get("sources", {"bid-log": "round 3: agent_a bid 120, highest"})
    return Evidence(facts=facts, sources=sources)


class TestFalseClaim(unittest.TestCase):
    def test_numeric_contradiction(self):
        r = analyze_deception("our bid of 150 was the highest", ev())
        self.assertTrue(r.deceptive)
        self.assertEqual(r.deception_type, DeceptionType.FALSE_CLAIM)
        self.assertIn("120", r.detail)

    def test_reversed_shape(self):
        r = analyze_deception("150 was the highest bid", ev())
        self.assertTrue(r.deceptive)
        self.assertEqual(r.deception_type, DeceptionType.FALSE_CLAIM)

    def test_assertion_shape(self):
        e = ev(facts={"winner": "agent_a"})
        r = analyze_deception("the winner was agent_b", e)
        self.assertTrue(r.deceptive)
        self.assertEqual(r.deception_type, DeceptionType.FALSE_CLAIM)

    def test_consistent_claim_is_clean(self):
        r = analyze_deception("the highest bid was 120 with 3 failures", ev())
        self.assertFalse(r.deceptive)
        self.assertIsNone(r.deception_type)

    def test_negation_denial_over_adverse_fact(self):
        r = analyze_deception("no failures occurred", ev())
        self.assertTrue(r.deceptive)
        self.assertEqual(r.deception_type, DeceptionType.FALSE_CLAIM)

    def test_unrelated_numbers_do_not_fire(self):
        # "3 bids" is about count, evidence highest_bid=120 is untouched.
        r = analyze_deception("we placed 3 bids today", ev(facts={"highest_bid": "120"}))
        self.assertFalse(r.deceptive)

    def test_detect_deception_bool(self):
        self.assertTrue(detect_deception("our bid of 150 was the highest", ev()))
        self.assertFalse(detect_deception("highest bid was 120", ev()))

    def test_classify(self):
        self.assertEqual(
            classify_deception("our bid of 150 was the highest", ev()),
            DeceptionType.FALSE_CLAIM,
        )
        self.assertIsNone(classify_deception("highest bid was 120", ev()))


class TestEvidenceConcealment(unittest.TestCase):
    def test_completeness_over_adverse_facts(self):
        r = analyze_deception("all tests passed", ev())
        self.assertTrue(r.deceptive)
        self.assertEqual(r.deception_type, DeceptionType.EVIDENCE_CONCEALMENT)
        self.assertIn("failures", r.detail)

    def test_disclosed_adverse_fact_is_clean(self):
        r = analyze_deception("all tests passed except 3 failures", ev())
        self.assertFalse(r.deceptive)

    def test_no_completeness_claim_no_concealment(self):
        r = analyze_deception("the bid was 120", ev())
        self.assertFalse(r.deceptive)

    def test_benign_zero_is_not_adverse(self):
        e = ev(facts={"failures": "0"})
        r = analyze_deception("all tests passed", e)
        self.assertFalse(r.deceptive)


class TestSourceFabrication(unittest.TestCase):
    def test_citation_to_absent_source(self):
        r = analyze_deception("per https://fake.example/report the bid was 120", ev())
        self.assertTrue(r.deceptive)
        self.assertEqual(r.deception_type, DeceptionType.SOURCE_FABRICATION)

    def test_citation_to_held_source_is_clean(self):
        r = analyze_deception("per bid-log the bid was 120", ev())
        self.assertFalse(r.deceptive)

    def test_fabricated_quote(self):
        e = ev(sources={"report": "the sky is blue today"})
        r = analyze_deception(
            'according to report, "the market crashed 50 percent" happened', e
        )
        self.assertTrue(r.deceptive)
        self.assertEqual(r.deception_type, DeceptionType.SOURCE_FABRICATION)

    def test_matching_quote_is_clean(self):
        e = ev(sources={"report": "the market crashed 50 percent yesterday"})
        r = analyze_deception(
            'according to report, "the market crashed 50 percent" happened', e
        )
        self.assertFalse(r.deceptive)


class TestStructure(unittest.TestCase):
    def test_version_pins(self):
        self.assertEqual(DECEPTION_DETECTOR_VERSION, "deception-detector.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.deception-detector.v1")

    def test_result_schema_pin(self):
        r = analyze_deception("hello", ev())
        self.assertEqual(r.schema, SCHEMA_PIN)

    def test_empty_claim_is_clean(self):
        r = analyze_deception("   ", ev())
        self.assertFalse(r.deceptive)

    def test_bad_inputs_raise(self):
        with self.assertRaises(TypeError):
            analyze_deception(123, ev())
        with self.assertRaises(TypeError):
            analyze_deception("x", {"facts": {}})
        with self.assertRaises(TypeError):
            Evidence(facts="nope")
        with self.assertRaises(ValueError):
            Evidence(facts={"": "x"})

    def test_result_invariants(self):
        with self.assertRaises(ValueError):
            DetectionResult(deceptive=True, deception_type=None, detail="x")
        with self.assertRaises(ValueError):
            DetectionResult(
                deceptive=False,
                deception_type=DeceptionType.FALSE_CLAIM,
                detail="x",
            )

    def test_first_hit_wins_order(self):
        # False-claim is checked before concealment.
        r = analyze_deception("no failures, all tests passed", ev())
        self.assertEqual(r.deception_type, DeceptionType.FALSE_CLAIM)

    def test_frozen(self):
        import dataclasses

        e = ev()
        with self.assertRaises(dataclasses.FrozenInstanceError):
            e.facts = {}


if __name__ == "__main__":
    unittest.main()
