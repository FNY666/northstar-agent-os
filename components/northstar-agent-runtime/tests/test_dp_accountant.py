"""Tests for dp_accountant (differential privacy budget accounting)."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dp_accountant import (  # noqa: E402
    DP_ACCOUNTANT_SCHEMA,
    DP_ACCOUNTANT_VERSION,
    PrivacyAccountant,
    PrivacyBudgetExhausted,
    RDPAccountant,
    RDPStep,
    SpendRecord,
)


class TestVersionPin(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(DP_ACCOUNTANT_VERSION, "dp-accountant.v1")

    def test_schema_pin(self):
        self.assertEqual(DP_ACCOUNTANT_SCHEMA, "northstar.dp-accountant.v1")


class TestSpendRecord(unittest.TestCase):
    def test_frozen(self):
        rec = SpendRecord(seq=1, epsilon=0.1, delta=1e-6, label="s1")
        with self.assertRaises(AttributeError):
            rec.epsilon = 0.5  # type: ignore[misc]

    def test_valid_record(self):
        rec = SpendRecord(seq=0, epsilon=0.25, delta=0.0)
        self.assertEqual(rec.seq, 0)
        self.assertEqual(rec.label, "")

    def test_zero_epsilon_with_delta_rejected(self):
        with self.assertRaises(ValueError):
            SpendRecord(seq=0, epsilon=0.0, delta=1e-6)

    def test_negative_epsilon_rejected(self):
        with self.assertRaises(ValueError):
            SpendRecord(seq=0, epsilon=-0.1, delta=0.0)

    def test_bool_epsilon_rejected(self):
        with self.assertRaises(TypeError):
            SpendRecord(seq=0, epsilon=True, delta=0.0)  # type: ignore[arg-type]

    def test_non_increasing_seq_allowed_in_record(self):
        # SpendRecord itself is just a record; ordering is enforced by the accountant.
        rec = SpendRecord(seq=3, epsilon=0.1, delta=0.0)
        self.assertEqual(rec.seq, 3)


class TestPrivacyAccountantBasics(unittest.TestCase):
    def test_constructor_validation(self):
        with self.assertRaises(ValueError):
            PrivacyAccountant(0.0)
        with self.assertRaises(ValueError):
            PrivacyAccountant(-1.0)
        with self.assertRaises(TypeError):
            PrivacyAccountant(True)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            PrivacyAccountant(1.0, -0.1)

    def test_spend_and_get_spent(self):
        acc = PrivacyAccountant(1.0, 1e-5)
        acc.spend((0.3, 1e-6), seq=0)
        acc.spend((0.2, 2e-6), seq=1, label="second")
        self.assertEqual(acc.get_privacy_spent(), (0.5, 3e-6))

    def test_initial_spent_is_zero(self):
        acc = PrivacyAccountant(2.0)
        self.assertEqual(acc.get_privacy_spent(), (0.0, 0.0))

    def test_remaining(self):
        acc = PrivacyAccountant(1.0, 1e-5)
        acc.spend((0.4, 2e-6), seq=0)
        rem_e, rem_d = acc.remaining()
        self.assertAlmostEqual(rem_e, 0.6)
        self.assertAlmostEqual(rem_d, 8e-6)

    def test_spend_exactly_to_budget_ok(self):
        acc = PrivacyAccountant(0.5, 1e-5)
        acc.spend((0.5, 1e-5), seq=0)
        self.assertEqual(acc.get_privacy_spent(), (0.5, 1e-5))

    def test_over_budget_epsilon_raises_and_not_recorded(self):
        acc = PrivacyAccountant(1.0)
        acc.spend((0.9, 0.0), seq=0)
        with self.assertRaises(PrivacyBudgetExhausted):
            acc.spend((0.2, 0.0), seq=1)
        self.assertEqual(acc.get_privacy_spent(), (0.9, 0.0))
        self.assertEqual(len(acc.ledger()), 1)

    def test_over_budget_delta_raises(self):
        acc = PrivacyAccountant(10.0, 1e-5)
        with self.assertRaises(PrivacyBudgetExhausted) as ctx:
            acc.spend((0.1, 2e-5), seq=0)
        self.assertEqual(ctx.exception.budget_delta, 1e-5)
        self.assertEqual(acc.get_privacy_spent(), (0.0, 0.0))

    def test_exhausted_exception_fields(self):
        acc = PrivacyAccountant(1.0, 0.0)
        with self.assertRaises(PrivacyBudgetExhausted) as ctx:
            acc.spend((2.0, 0.0), seq=0)
        exc = ctx.exception
        self.assertEqual(exc.epsilon, 2.0)
        self.assertEqual(exc.budget_epsilon, 1.0)

    def test_seq_must_increase(self):
        acc = PrivacyAccountant(5.0)
        acc.spend((0.1, 0.0), seq=5)
        with self.assertRaises(ValueError):
            acc.spend((0.1, 0.0), seq=5)
        with self.assertRaises(ValueError):
            acc.spend((0.1, 0.0), seq=3)

    def test_can_spend(self):
        acc = PrivacyAccountant(1.0, 1e-5)
        acc.spend((0.9, 0.0), seq=0)
        self.assertTrue(acc.can_spend((0.1, 1e-5)))
        self.assertFalse(acc.can_spend((0.11, 0.0)))
        self.assertFalse(acc.can_spend((0.0, 2e-5)))
        self.assertFalse(acc.can_spend("bad"))  # type: ignore[arg-type]

    def test_malformed_spend_rejected(self):
        acc = PrivacyAccountant(1.0)
        with self.assertRaises(TypeError):
            acc.spend((0.1,), seq=0)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            acc.spend("0.1,0.0", seq=0)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            acc.spend((0.0, 1e-6), seq=0)  # zero epsilon with delta
        with self.assertRaises(TypeError):
            acc.spend((True, 0.0), seq=0)  # type: ignore[arg-type]

    def test_ledger_order_and_shape(self):
        acc = PrivacyAccountant(3.0)
        r0 = acc.spend((0.2, 0.0), seq=0, label="a")
        r1 = acc.spend((0.3, 0.0), seq=1, label="b")
        ledger = acc.ledger()
        self.assertEqual(ledger, (r0, r1))
        self.assertIsInstance(ledger, tuple)

    def test_audit_event_shape(self):
        acc = PrivacyAccountant(1.0, 1e-5)
        acc.spend((0.25, 1e-6), seq=0)
        event = acc.audit_event(seq=7)
        self.assertEqual(event["schema"], "audit.ndjson/1")
        self.assertEqual(event["module"], "dp_accountant")
        self.assertEqual(event["module_version"], DP_ACCOUNTANT_VERSION)
        self.assertEqual(event["spend_count"], 1)
        self.assertEqual(event["spent_epsilon"], 0.25)


class TestCompose(unittest.TestCase):
    def test_compose_disjoint_ledgers(self):
        a = PrivacyAccountant(1.0, 1e-5)
        a.spend((0.3, 1e-6), seq=0)
        b = PrivacyAccountant(2.0, 2e-5)
        b.spend((0.4, 2e-6), seq=1)
        merged = a.compose(b)
        self.assertEqual(merged.get_privacy_spent(), (0.7, 3e-6))
        self.assertEqual(merged.budget_epsilon, 3.0)
        self.assertAlmostEqual(merged.budget_delta, 3e-5)
        # Originals unchanged.
        self.assertEqual(a.get_privacy_spent(), (0.3, 1e-6))
        self.assertEqual(b.get_privacy_spent(), (0.4, 2e-6))

    def test_compose_overlapping_seq_rejected(self):
        a = PrivacyAccountant(1.0)
        a.spend((0.1, 0.0), seq=0)
        b = PrivacyAccountant(1.0)
        b.spend((0.1, 0.0), seq=0)
        with self.assertRaises(ValueError):
            a.compose(b)

    def test_compose_type_rejected(self):
        a = PrivacyAccountant(1.0)
        with self.assertRaises(TypeError):
            a.compose("not-an-accountant")  # type: ignore[arg-type]

    def test_compose_empty_ledgers(self):
        a = PrivacyAccountant(1.0)
        b = PrivacyAccountant(2.0, 1e-6)
        merged = a.compose(b)
        self.assertEqual(merged.get_privacy_spent(), (0.0, 0.0))
        self.assertEqual(merged.budget_epsilon, 3.0)


class TestRDPAccountant(unittest.TestCase):
    ORDERS = (2.0, 4.0, 8.0)

    def _step(self, seq, costs):
        return RDPStep(seq=seq, orders=self.ORDERS, costs=costs)

    def test_constructor_validation(self):
        with self.assertRaises(ValueError):
            RDPAccountant((), 1.0, 1e-5)
        with self.assertRaises(ValueError):
            RDPAccountant((1.0,), 1.0, 1e-5)  # alpha must be > 1
        with self.assertRaises(ValueError):
            RDPAccountant((4.0, 2.0), 1.0, 1e-5)  # not increasing
        with self.assertRaises(ValueError):
            RDPAccountant((2.0, 2.0), 1.0, 1e-5)  # duplicate
        with self.assertRaises(ValueError):
            RDPAccountant(self.ORDERS, 1.0, 0.0)  # delta not in (0,1)
        with self.assertRaises(ValueError):
            RDPAccountant(self.ORDERS, 1.0, 1.0)
        with self.assertRaises(ValueError):
            RDPAccountant(self.ORDERS, 0.0, 1e-5)

    def test_rdp_step_validation(self):
        with self.assertRaises(ValueError):
            RDPStep(seq=0, orders=(2.0,), costs=(0.1, 0.2))
        with self.assertRaises(ValueError):
            RDPStep(seq=0, orders=(0.5,), costs=(0.1,))
        with self.assertRaises(TypeError):
            RDPStep(seq=True, orders=(2.0,), costs=(0.1,))  # type: ignore[arg-type]

    def test_spend_and_convert(self):
        rdp = RDPAccountant(self.ORDERS, budget_epsilon=10.0, target_delta=1e-5)
        rdp.spend(self._step(0, (0.05, 0.02, 0.01)))
        epsilon, delta = rdp.to_epsilon_delta()
        self.assertEqual(delta, 1e-5)
        # Hand-check: min over alpha of cost + log(1/1e-5)/(alpha-1).
        import math

        log_term = math.log(1e5)
        expected = min(
            0.05 + log_term / 1.0,
            0.02 + log_term / 3.0,
            0.01 + log_term / 7.0,
        )
        self.assertAlmostEqual(epsilon, expected)
        self.assertEqual(rdp.step_count(), 1)

    def test_takes_minimum_over_orders(self):
        rdp = RDPAccountant(self.ORDERS, budget_epsilon=10.0, target_delta=1e-5)
        # Costs shaped so alpha=8 wins.
        rdp.spend(self._step(0, (5.0, 2.0, 0.001)))
        epsilon, _ = rdp.to_epsilon_delta()
        import math

        log_term = math.log(1e5)
        self.assertAlmostEqual(epsilon, 0.001 + log_term / 7.0)

    def test_over_budget_raises_and_not_recorded(self):
        rdp = RDPAccountant(self.ORDERS, budget_epsilon=1.0, target_delta=1e-5)
        with self.assertRaises(PrivacyBudgetExhausted):
            rdp.spend(self._step(0, (5.0, 5.0, 5.0)))
        self.assertEqual(rdp.step_count(), 0)

    def test_order_mismatch_rejected(self):
        rdp = RDPAccountant(self.ORDERS, budget_epsilon=10.0, target_delta=1e-5)
        bad = RDPStep(seq=0, orders=(2.0, 8.0), costs=(0.1, 0.1))
        with self.assertRaises(ValueError):
            rdp.spend(bad)

    def test_seq_must_increase(self):
        rdp = RDPAccountant(self.ORDERS, budget_epsilon=10.0, target_delta=1e-5)
        rdp.spend(self._step(0, (0.01, 0.01, 0.01)))
        with self.assertRaises(ValueError):
            rdp.spend(self._step(0, (0.01, 0.01, 0.01)))

    def test_can_spend(self):
        rdp = RDPAccountant(self.ORDERS, budget_epsilon=3.0, target_delta=1e-5)
        self.assertTrue(rdp.can_spend((0.01, 0.01, 0.01)))
        self.assertFalse(rdp.can_spend((10.0, 10.0, 10.0)))
        self.assertFalse(rdp.can_spend((0.01,)))  # wrong arity
        self.assertFalse(rdp.can_spend((-0.1, 0.0, 0.0)))

    def test_audit_event_shape(self):
        rdp = RDPAccountant(self.ORDERS, budget_epsilon=10.0, target_delta=1e-5)
        rdp.spend(self._step(0, (0.05, 0.02, 0.01)))
        event = rdp.audit_event(seq=3)
        self.assertEqual(event["event"], "rdp-budget-state")
        self.assertEqual(event["module_version"], DP_ACCOUNTANT_VERSION)
        self.assertEqual(event["step_count"], 1)
        self.assertGreater(event["converted_epsilon"], 0.0)


class TestMain(unittest.TestCase):
    def test_main_self_check(self):
        import dp_accountant

        dp_accountant.main()  # must not raise


if __name__ == "__main__":
    unittest.main()
