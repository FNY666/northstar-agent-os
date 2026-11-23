"""Tests for interpretability_probe.py."""

import importlib.util
import sys
import unittest

from interpretability_probe import (
    INTERPRETABILITY_PROBE_VERSION,
    SCHEMA_PIN,
    ActivationProbe,
    Concept,
    InterpretabilityProbeError,
    ProbeDirection,
    ProbeFinding,
    fit_direction,
    probe_audit_event,
    score_projection,
)

POS = [(4.0, 0.1), (4.2, -0.1), (3.8, 0.0)]
NEG = [(0.0, 0.1), (0.2, -0.1), (-0.1, 0.0)]


def make_concept(cid="deception"):
    return Concept(concept_id=cid, name="deceptive reasoning")


def make_probe(cid="deception"):
    probe = ActivationProbe()
    probe.register(make_concept(cid), POS, NEG)
    return probe


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(INTERPRETABILITY_PROBE_VERSION, "interpretability-probe.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.interpretability-probe.v1")


class TestConcept(unittest.TestCase):
    def test_frozen(self):
        c = make_concept()
        with self.assertRaises(Exception):
            c.name = "other"  # type: ignore

    def test_empty_id_rejected(self):
        with self.assertRaises(InterpretabilityProbeError):
            Concept(concept_id="", name="x")

    def test_empty_name_rejected(self):
        with self.assertRaises(InterpretabilityProbeError):
            Concept(concept_id="x", name="   ")

    def test_non_str_rejected(self):
        with self.assertRaises(InterpretabilityProbeError):
            Concept(concept_id=7, name="x")  # type: ignore

    def test_as_dict(self):
        d = make_concept().as_dict()
        self.assertEqual(d["concept_id"], "deception")
        self.assertEqual(d["schema"], SCHEMA_PIN)


class TestFitDirection(unittest.TestCase):
    def test_unit_norm(self):
        import math

        fitted = fit_direction(POS, NEG, "deception")
        norm = math.sqrt(sum(x * x for x in fitted.direction))
        self.assertAlmostEqual(norm, 1.0, places=9)

    def test_counts(self):
        fitted = fit_direction(POS, NEG, "deception")
        self.assertEqual(fitted.n_positive, 3)
        self.assertEqual(fitted.n_negative, 3)

    def test_empty_class_rejected(self):
        with self.assertRaises(InterpretabilityProbeError):
            fit_direction([], NEG, "deception")
        with self.assertRaises(InterpretabilityProbeError):
            fit_direction(POS, [], "deception")

    def test_dim_mismatch_rejected(self):
        with self.assertRaises(InterpretabilityProbeError):
            fit_direction([(1.0, 2.0)], [(1.0, 2.0, 3.0)], "deception")

    def test_zero_separation_rejected(self):
        same = [(1.0, 2.0), (1.0, 2.0)]
        with self.assertRaises(InterpretabilityProbeError):
            fit_direction(same, same, "deception")

    def test_nan_rejected(self):
        with self.assertRaises(InterpretabilityProbeError):
            fit_direction([(float("nan"), 0.0)], NEG, "deception")

    def test_bool_rejected(self):
        with self.assertRaises(InterpretabilityProbeError):
            fit_direction([(True, 0.0)], NEG, "deception")

    def test_bad_concept_id_rejected(self):
        with self.assertRaises(InterpretabilityProbeError):
            fit_direction(POS, NEG, "")


class TestProbe(unittest.TestCase):
    def test_strong_positive_high(self):
        probe = make_probe()
        self.assertGreater(probe.probe((4.0, 0.0), make_concept()), 0.8)

    def test_weak_negative_low(self):
        probe = make_probe()
        self.assertLess(probe.probe((0.0, 0.0), make_concept()), 0.2)

    def test_score_in_unit_interval(self):
        probe = make_probe()
        for vec in POS + NEG + [(100.0, 50.0), (-100.0, -50.0)]:
            score = probe.probe(vec, make_concept())
            self.assertGreaterEqual(score, 0.0)
            self.assertLessEqual(score, 1.0)

    def test_clamps_extremes(self):
        probe = make_probe()
        self.assertEqual(probe.probe((1e9, 1e9), make_concept()), 1.0)
        self.assertEqual(probe.probe((-1e9, -1e9), make_concept()), 0.0)

    def test_monotonic_along_direction(self):
        probe = make_probe()
        concept = make_concept()
        s1 = probe.probe((1.0, 0.0), concept)
        s2 = probe.probe((2.0, 0.0), concept)
        s3 = probe.probe((3.0, 0.0), concept)
        self.assertLess(s1, s2)
        self.assertLess(s2, s3)

    def test_deterministic(self):
        probe = make_probe()
        concept = make_concept()
        self.assertEqual(
            probe.probe((2.5, 0.3), concept), probe.probe((2.5, 0.3), concept)
        )

    def test_unregistered_concept_keyerror(self):
        probe = ActivationProbe()
        with self.assertRaises(KeyError):
            probe.probe((1.0, 1.0), make_concept("never-registered"))

    def test_dim_mismatch_rejected(self):
        probe = make_probe()
        with self.assertRaises(InterpretabilityProbeError):
            probe.probe((1.0, 2.0, 3.0), make_concept())

    def test_non_numeric_rejected(self):
        probe = make_probe()
        with self.assertRaises(InterpretabilityProbeError):
            probe.probe(("x", 0.0), make_concept())  # type: ignore

    def test_string_input_rejected(self):
        probe = make_probe()
        with self.assertRaises(TypeError):
            probe.probe("10", make_concept())  # type: ignore

    def test_register_non_concept_rejected(self):
        probe = ActivationProbe()
        with self.assertRaises(TypeError):
            probe.register("not-a-concept", POS, NEG)  # type: ignore

    def test_registered_listing(self):
        probe = make_probe("a")
        probe.register(make_concept("b"), POS, NEG)
        self.assertEqual(probe.registered(), ("a", "b"))

    def test_reregister_replaces(self):
        probe = make_probe()
        concept = make_concept()
        probe.register(concept, [(0.0, 4.0)], [(0.0, 0.0)])
        # New direction points along +y: (0,4) strong, (4,0) weak.
        self.assertGreater(probe.probe((0.0, 4.0), concept), 0.8)
        self.assertLess(probe.probe((4.0, 0.0), concept), 0.2)


class TestFindingAndAudit(unittest.TestCase):
    def test_finding_shape(self):
        probe = make_probe()
        finding = probe.probe_finding((4.0, 0.0), make_concept())
        self.assertIsInstance(finding, ProbeFinding)
        self.assertEqual(finding.concept_id, "deception")
        self.assertGreater(finding.presence_score, 0.8)
        d = finding.as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)

    def test_finding_frozen(self):
        finding = ProbeFinding("x", 0.5, 1, 1)
        with self.assertRaises(Exception):
            finding.presence_score = 0.9  # type: ignore

    def test_audit_event_shape(self):
        ev = probe_audit_event("deception", 0.75, 7)
        self.assertEqual(ev["type"], "interpretability-probe")
        self.assertEqual(ev["presence_score"], 0.75)
        self.assertEqual(ev["seq"], 7)
        self.assertEqual(ev["schema"], SCHEMA_PIN)

    def test_audit_event_validation(self):
        with self.assertRaises(InterpretabilityProbeError):
            probe_audit_event("", 0.5, 1)
        with self.assertRaises(InterpretabilityProbeError):
            probe_audit_event("x", 1.5, 1)
        with self.assertRaises(InterpretabilityProbeError):
            probe_audit_event("x", 0.5, -1)
        with self.assertRaises(InterpretabilityProbeError):
            probe_audit_event("x", 0.5, True)


class TestStandalone(unittest.TestCase):
    def test_module_importable_standalone(self):
        spec = importlib.util.spec_from_file_location(
            "interpretability_probe_sa",
            "interpretability_probe.py",
        )
        mod = importlib.util.module_from_spec(spec)
        sys.modules["interpretability_probe_sa"] = mod  # dataclasses need this
        try:
            spec.loader.exec_module(mod)
        finally:
            sys.modules.pop("interpretability_probe_sa", None)
        fitted = mod.fit_direction(POS, NEG, "deception")
        self.assertGreater(mod.score_projection((4.0, 0.0), fitted), 0.8)


class TestMain(unittest.TestCase):
    def test_main_runs(self):
        import interpretability_probe as mod

        mod.main()  # asserts internally


if __name__ == "__main__":
    unittest.main()
