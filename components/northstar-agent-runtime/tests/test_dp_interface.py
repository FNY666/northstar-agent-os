"""Tests for dp_interface: Laplace/Gaussian mechanisms + sequential composition."""

import math
import unittest

from dp_interface import (
    DP_INTERFACE_SCHEMA,
    DP_INTERFACE_VERSION,
    DPBudgetExhausted,
    DPCalibrationError,
    DPComposer,
    DPError,
    DPMechanism,
    NoisyResult,
    SpendRecord,
    gaussian_sigma,
    laplace_scale,
)


class TestCalibration(unittest.TestCase):
    def test_version_pins(self):
        self.assertEqual(DP_INTERFACE_VERSION, "dp-interface.v1")
        self.assertEqual(DP_INTERFACE_SCHEMA, "northstar.dp-interface.v1")

    def test_laplace_scale(self):
        self.assertEqual(laplace_scale(2.0, 0.5), 4.0)
        self.assertEqual(laplace_scale(1, 1), 1.0)

    def test_laplace_scale_rejects(self):
        for sens, eps in [(0, 1), (-1, 1), (1, 0), (1, -0.5), (True, 1), (1, True)]:
            with self.assertRaises((DPError, DPCalibrationError)):
                laplace_scale(sens, eps)

    def test_gaussian_sigma_classic(self):
        sigma = gaussian_sigma(1.0, 0.5, 1e-5)
        expected = math.sqrt(2.0 * math.log(1.25 / 1e-5)) / 0.5
        self.assertAlmostEqual(sigma, expected, places=12)

    def test_gaussian_sigma_rejects_regime(self):
        with self.assertRaises(DPCalibrationError):
            gaussian_sigma(1.0, 1.0, 1e-5)  # epsilon >= 1 out of regime
        with self.assertRaises(DPCalibrationError):
            gaussian_sigma(1.0, 0.5, 0.0)  # delta must be in (0,1)
        with self.assertRaises(DPCalibrationError):
            gaussian_sigma(1.0, 0.5, 1.5)


class TestLaplace(unittest.TestCase):
    def test_happy_path(self):
        mech = DPMechanism(noise_seed=b"test")
        r = mech.laplace(100.0, 1.0, 1.0)
        self.assertIsInstance(r, NoisyResult)
        self.assertEqual(r.mechanism, "laplace")
        self.assertEqual(r.delta, 0.0)
        self.assertEqual(r.epsilon, 1.0)
        self.assertEqual(r.sensitivity, 1.0)
        self.assertAlmostEqual(r.value - r.true_value, r.noise, places=12)

    def test_deterministic_seed_replays(self):
        a = DPMechanism(noise_seed=b"replay").laplace(5.0, 2.0, 0.5)
        b = DPMechanism(noise_seed=b"replay").laplace(5.0, 2.0, 0.5)
        self.assertEqual(a.noise, b.noise)
        self.assertEqual(a.value, b.value)

    def test_counter_advances_noise_differs(self):
        mech = DPMechanism(noise_seed=b"counter")
        r1 = mech.laplace(5.0, 1.0, 1.0)
        r2 = mech.laplace(5.0, 1.0, 1.0)
        self.assertNotEqual(r1.noise, r2.noise)

    def test_different_seeds_differ(self):
        a = DPMechanism(noise_seed=b"a").laplace(5.0, 1.0, 1.0)
        b = DPMechanism(noise_seed=b"b").laplace(5.0, 1.0, 1.0)
        self.assertNotEqual(a.noise, b.noise)

    def test_real_noise_works(self):
        mech = DPMechanism()  # secrets-backed
        r = mech.laplace(0.0, 1.0, 1.0)
        self.assertTrue(math.isfinite(r.noise))

    def test_rejects_bad_inputs(self):
        mech = DPMechanism(noise_seed=b"x")
        with self.assertRaises(DPError):
            mech.laplace(True, 1.0, 1.0)  # bool value
        with self.assertRaises((DPError, DPCalibrationError)):
            mech.laplace(1.0, 0.0, 1.0)  # zero sensitivity
        with self.assertRaises((DPError, DPCalibrationError)):
            mech.laplace(1.0, 1.0, float("nan"))  # non-finite epsilon
        with self.assertRaises(DPError):
            mech.laplace(float("inf"), 1.0, 1.0)

    def test_as_dict(self):
        r = DPMechanism(noise_seed=b"d").laplace(1.0, 1.0, 1.0)
        d = r.as_dict()
        self.assertEqual(d["schema"], DP_INTERFACE_SCHEMA)
        self.assertEqual(d["module_version"], DP_INTERFACE_VERSION)

    def test_bad_seed(self):
        with self.assertRaises(DPError):
            DPMechanism(noise_seed=b"")
        with self.assertRaises(DPError):
            DPMechanism(noise_seed="not-bytes")  # type: ignore[arg-type]


class TestGaussian(unittest.TestCase):
    def test_happy_path(self):
        mech = DPMechanism(noise_seed=b"g")
        r = mech.gaussian(50.0, 1.0, 0.5, delta=1e-5)
        self.assertEqual(r.mechanism, "gaussian")
        self.assertEqual(r.epsilon, 0.5)
        self.assertEqual(r.delta, 1e-5)

    def test_explicit_sigma(self):
        mech = DPMechanism(noise_seed=b"sg")
        r = mech.gaussian(50.0, 1.0, 0.5, delta=1e-5, sigma=2.0)
        self.assertEqual(r.epsilon, 0.5)  # accounting still declared
        self.assertEqual(r.delta, 1e-5)

    def test_requires_delta(self):
        mech = DPMechanism(noise_seed=b"nd")
        with self.assertRaises(DPCalibrationError):
            mech.gaussian(1.0, 1.0, 0.5)  # delta defaults to 0

    def test_rejects_regime(self):
        mech = DPMechanism(noise_seed=b"rg")
        with self.assertRaises(DPCalibrationError):
            mech.gaussian(1.0, 1.0, 2.0, delta=1e-5)  # epsilon >= 1

    def test_deterministic_replay(self):
        a = DPMechanism(noise_seed=b"gr").gaussian(1.0, 1.0, 0.5, delta=1e-6)
        b = DPMechanism(noise_seed=b"gr").gaussian(1.0, 1.0, 0.5, delta=1e-6)
        self.assertEqual(a.noise, b.noise)


class TestComposer(unittest.TestCase):
    def test_spend_and_remaining(self):
        comp = DPComposer(2.0, 1e-5)
        comp.spend(0.5, 1e-6, mechanism="laplace")
        comp.spend(0.5, 0.0, mechanism="laplace")
        self.assertEqual(comp.spent(), (1.0, 1e-6))
        self.assertEqual(comp.remaining(), (1.0, 9e-6))

    def test_spend_result(self):
        mech = DPMechanism(noise_seed=b"sr")
        comp = DPComposer(1.0, 1e-5)
        r = mech.laplace(10.0, 1.0, 0.4)
        rec = comp.spend_result(r)
        self.assertIsInstance(rec, SpendRecord)
        self.assertEqual(rec.mechanism, "laplace")
        self.assertEqual(comp.spent(), (0.4, 0.0))

    def test_budget_exhausted_fail_closed(self):
        comp = DPComposer(1.0, 1e-5)
        comp.spend(0.9, 0.0)
        with self.assertRaises(DPBudgetExhausted):
            comp.spend(0.2, 0.0)
        self.assertEqual(comp.spent(), (0.9, 0.0))  # refused spend unrecorded

    def test_delta_budget_exhausted(self):
        comp = DPComposer(10.0, 1e-5)
        with self.assertRaises(DPBudgetExhausted):
            comp.spend(0.1, 2e-5)

    def test_compose_merges(self):
        a = DPComposer(2.0, 1e-5)
        b = DPComposer(2.0, 1e-5)
        a.spend(0.5, 1e-6, mechanism="laplace")
        b.spend(0.25, 0.0, mechanism="gaussian")
        merged = a.compose(b)
        self.assertEqual(merged.spent(), (0.75, 1e-6))
        self.assertEqual(merged.remaining(), (1.25, 9e-6))
        # originals untouched
        self.assertEqual(a.spent(), (0.5, 1e-6))
        self.assertEqual(b.spent(), (0.25, 0.0))

    def test_compose_rejects_mismatched_budgets(self):
        a = DPComposer(2.0, 1e-5)
        b = DPComposer(3.0, 1e-5)
        with self.assertRaises(DPCalibrationError):
            a.compose(b)

    def test_ledger_immutable_view(self):
        comp = DPComposer(1.0, 0.0)
        comp.spend(0.1, 0.0)
        ledger = comp.ledger()
        self.assertEqual(len(ledger), 1)
        self.assertIsInstance(ledger, tuple)

    def test_rejects_negative_spend(self):
        comp = DPComposer(1.0, 1e-5)
        with self.assertRaises(DPCalibrationError):
            comp.spend(-0.1, 0.0)

    def test_rejects_bad_budget(self):
        with self.assertRaises(DPCalibrationError):
            DPComposer(0.0, 1e-5)
        with self.assertRaises(DPCalibrationError):
            DPComposer(1.0, -1e-5)

    def test_audit_event_shape(self):
        comp = DPComposer(2.0, 1e-5)
        comp.spend(0.5, 1e-6, mechanism="laplace")
        ev = comp.audit_event(seq=7)
        self.assertEqual(ev["schema"], "audit.ndjson/1")
        self.assertEqual(ev["module"], "dp_interface")
        self.assertEqual(ev["seq"], 7)
        self.assertEqual(ev["spend_count"], 1)
        self.assertEqual(ev["spent_epsilon"], 0.5)

    def test_spend_record_as_dict(self):
        rec = SpendRecord(epsilon=0.5, delta=1e-6, mechanism="laplace", seq=3)
        d = rec.as_dict()
        self.assertEqual(d["seq"], 3)
        self.assertEqual(d["mechanism"], "laplace")


class TestMain(unittest.TestCase):
    def test_main_self_check(self):
        import dp_interface
        dp_interface.main()  # raises on failure


if __name__ == "__main__":
    unittest.main()
