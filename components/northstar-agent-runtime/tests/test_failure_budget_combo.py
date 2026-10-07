"""Tests for failure_budget_combo: budget exhaustion -> failure incident."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from failure_budget_combo import (
    BUDGET_CEILING_PER_CALL,
    BUDGET_CEILING_RUN,
    CEILINGS,
    FAILURE_BUDGET_COMBO_VERSION,
    SCHEMA_PIN,
    FailureBudgetBundle,
    FailureBudgetComboError,
    FailureBudgetManager,
    budget_bundle_from_exhaustion,
    failure_budget_audit_event,
    failure_budget_digest,
    failure_budget_ledger_digest,
    verify_failure_budget_digest,
)
from failure_bundle import (
    IncidentState,
    bundle_digest,
    verify_bundle_digest,
)
from per_call_budget import (
    CEILING_PER_CALL,
    CEILING_RUN,
    BudgetExhausted,
    PerCallBudget,
)


def _make_exhaustion(call_type="tool", needed=0.02, available=0.995,
                     ceiling=CEILING_PER_CALL):
    return BudgetExhausted(call_type=call_type, needed=needed,
                           available=available, ceiling=ceiling)


class TestVersion(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(FAILURE_BUDGET_COMBO_VERSION, "failure-budget-combo.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.failure-budget-combo.v1")

    def test_ceiling_reexports(self):
        self.assertEqual(BUDGET_CEILING_PER_CALL, CEILING_PER_CALL)
        self.assertEqual(BUDGET_CEILING_RUN, CEILING_RUN)
        self.assertEqual(CEILINGS, (CEILING_PER_CALL, CEILING_RUN))


class TestFailureBudgetBundle(unittest.TestCase):
    def _bundle(self, **kw):
        base = {
            "incident_id": "inc-1-budget.tool",
            "ceiling": "per_call",
            "call_type": "tool",
            "needed_usd": 0.02,
            "available_usd": 0.995,
            "max_budget_usd": 1.0,
            "total_spent_usd": 0.005,
            "created_seq": 1,
        }
        base.update(kw)
        return FailureBudgetBundle(**base)

    def test_frozen(self):
        b = self._bundle()
        with self.assertRaises(Exception):
            b.needed_usd = 0.0  # type: ignore[misc]

    def test_as_dict_shape(self):
        d = self._bundle().as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertEqual(d["incident_id"], "inc-1-budget.tool")
        self.assertEqual(d["ceiling"], "per_call")
        self.assertEqual(d["call_type"], "tool")
        self.assertAlmostEqual(d["needed_usd"], 0.02)
        self.assertAlmostEqual(d["available_usd"], 0.995)
        self.assertAlmostEqual(d["max_budget_usd"], 1.0)
        self.assertAlmostEqual(d["total_spent_usd"], 0.005)
        self.assertEqual(d["created_seq"], 1)

    def test_none_available_allowed(self):
        b = self._bundle(available_usd=None)
        self.assertIsNone(b.as_dict()["available_usd"])

    def test_bad_ceiling_rejected(self):
        with self.assertRaises(FailureBudgetComboError):
            self._bundle(ceiling="hourly")

    def test_negative_needed_rejected(self):
        with self.assertRaises(FailureBudgetComboError):
            self._bundle(needed_usd=-0.01)

    def test_bool_needed_rejected(self):
        with self.assertRaises(FailureBudgetComboError):
            self._bundle(needed_usd=True)

    def test_empty_incident_id_rejected(self):
        with self.assertRaises(FailureBudgetComboError):
            self._bundle(incident_id="")

    def test_negative_seq_rejected(self):
        with self.assertRaises(FailureBudgetComboError):
            self._bundle(created_seq=-1)

    def test_digest_roundtrip(self):
        b = self._bundle()
        digest = failure_budget_digest(b)
        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        self.assertTrue(verify_failure_budget_digest(b, digest))
        self.assertFalse(verify_failure_budget_digest(b, "00" * 32))

    def test_digest_wrong_type(self):
        with self.assertRaises(FailureBudgetComboError):
            failure_budget_digest("nope")  # type: ignore[arg-type]


class TestBudgetBundleFromExhaustion(unittest.TestCase):
    def test_builds_from_exception(self):
        budget = PerCallBudget(max_budget_usd=1.0)
        budget.check_and_charge("tool", 0.005)
        exc = _make_exhaustion(needed=0.02, available=0.995)
        bundle = budget_bundle_from_exhaustion(
            exc, budget=budget, incident_id="inc-1-x", seq=1)
        self.assertEqual(bundle.incident_id, "inc-1-x")
        self.assertEqual(bundle.ceiling, "per_call")
        self.assertEqual(bundle.call_type, "tool")
        self.assertAlmostEqual(bundle.needed_usd, 0.02)
        self.assertAlmostEqual(bundle.available_usd, 0.995)
        self.assertAlmostEqual(bundle.max_budget_usd, 1.0)
        self.assertAlmostEqual(bundle.total_spent_usd, 0.005)
        self.assertEqual(bundle.created_seq, 1)

    def test_run_ceiling_builder(self):
        budget = PerCallBudget(max_budget_usd=0.01)
        budget.check_and_charge("tool", 0.009)
        exc = _make_exhaustion(needed=0.009, available=0.001, ceiling=CEILING_RUN)
        bundle = budget_bundle_from_exhaustion(
            exc, budget=budget, incident_id="inc-2-y", seq=2)
        self.assertEqual(bundle.ceiling, "run")
        self.assertAlmostEqual(bundle.total_spent_usd, 0.009)

    def test_none_available_builder(self):
        budget = PerCallBudget()  # no run ceiling
        exc = _make_exhaustion(available=None)
        bundle = budget_bundle_from_exhaustion(
            exc, budget=budget, incident_id="inc-3-z", seq=3)
        self.assertIsNone(bundle.available_usd)
        self.assertIsNone(bundle.max_budget_usd)

    def test_wrong_exc_type(self):
        budget = PerCallBudget()
        with self.assertRaises(FailureBudgetComboError):
            budget_bundle_from_exhaustion(
                ValueError("x"), budget=budget, incident_id="i", seq=0)  # type: ignore[arg-type]


class TestGuardedCharge(unittest.TestCase):
    def test_happy_path_no_incident(self):
        mgr = FailureBudgetManager(max_budget_usd=1.0)
        remaining = mgr.guarded_charge("tool", 0.005, seq=0)
        self.assertAlmostEqual(remaining, 0.995)
        self.assertIs(mgr.state, IncidentState.NORMAL)
        self.assertIsNone(mgr.active_budget_bundle())
        self.assertEqual(mgr.budget_bundles(), ())

    def test_per_call_overrun_raises_and_incidents(self):
        mgr = FailureBudgetManager(max_budget_usd=1.0)
        with self.assertRaises(BudgetExhausted) as ctx:
            mgr.guarded_charge("tool", 0.02, seq=1)  # over $0.01 ceiling
        self.assertEqual(ctx.exception.ceiling, CEILING_PER_CALL)
        self.assertIs(mgr.state, IncidentState.FAILED)

    def test_run_overrun_raises_and_incidents(self):
        mgr = FailureBudgetManager(max_budget_usd=0.01)
        mgr.guarded_charge("tool", 0.009, seq=0)
        with self.assertRaises(BudgetExhausted) as ctx:
            mgr.guarded_charge("tool", 0.009, seq=1)
        self.assertEqual(ctx.exception.ceiling, CEILING_RUN)
        self.assertIs(mgr.state, IncidentState.FAILED)

    def test_budget_bundle_attached_to_incident(self):
        mgr = FailureBudgetManager(max_budget_usd=1.0)
        with self.assertRaises(BudgetExhausted):
            mgr.guarded_charge("tool", 0.02, seq=1)
        budget_bundle = mgr.active_budget_bundle()
        self.assertIsNotNone(budget_bundle)
        assert budget_bundle is not None
        self.assertEqual(budget_bundle.ceiling, "per_call")
        self.assertEqual(budget_bundle.call_type, "tool")
        self.assertAlmostEqual(budget_bundle.needed_usd, 0.02)
        self.assertEqual(budget_bundle.created_seq, 1)
        # linkage: incident ids match
        failure = mgr.incidents.active_bundle
        self.assertIsNotNone(failure)
        assert failure is not None
        self.assertEqual(failure.incident_id, budget_bundle.incident_id)

    def test_failure_bundle_snapshot_is_ledger_digest(self):
        mgr = FailureBudgetManager(max_budget_usd=1.0)
        mgr.guarded_charge("tool", 0.005, seq=0)
        with self.assertRaises(BudgetExhausted):
            mgr.guarded_charge("tool", 0.02, seq=1)
        failure = mgr.incidents.active_bundle
        assert failure is not None
        # The ledger digest at failure time pins spent=0.005 (the refused
        # call was never charged).
        expected_budget = PerCallBudget(max_budget_usd=1.0)
        expected_budget.check_and_charge("tool", 0.005)
        self.assertEqual(
            failure.state_snapshot_hash,
            failure_budget_ledger_digest(expected_budget))
        self.assertTrue(verify_bundle_digest(failure, bundle_digest(failure)))

    def test_second_overrun_while_failed_no_new_bundle(self):
        mgr = FailureBudgetManager(max_budget_usd=1.0)
        with self.assertRaises(BudgetExhausted):
            mgr.guarded_charge("tool", 0.02, seq=1)
        with self.assertRaises(BudgetExhausted):
            mgr.guarded_charge("model", 0.5, seq=2)  # also refused
        # still one incident, one budget bundle
        self.assertEqual(len(mgr.budget_bundles()), 1)
        self.assertIs(mgr.state, IncidentState.FAILED)
        self.assertEqual(len(mgr.transitions()), 1)

    def test_refused_call_not_charged(self):
        mgr = FailureBudgetManager(max_budget_usd=1.0)
        mgr.guarded_charge("tool", 0.005, seq=0)
        with self.assertRaises(BudgetExhausted):
            mgr.guarded_charge("tool", 0.02, seq=1)
        self.assertAlmostEqual(mgr.budget.total_spent_usd, 0.005)
        self.assertEqual(len(mgr.budget.charges), 1)

    def test_unknown_call_type_raises_without_incident(self):
        mgr = FailureBudgetManager()
        with self.assertRaises(ValueError):
            mgr.guarded_charge("teleport", 0.1, seq=0)
        self.assertIs(mgr.state, IncidentState.NORMAL)

    def test_full_recovery_cycle(self):
        mgr = FailureBudgetManager(max_budget_usd=1.0)
        with self.assertRaises(BudgetExhausted):
            mgr.guarded_charge("tool", 0.02, seq=1)
        self.assertIs(mgr.begin_recovery("operator ack", seq=2), IncidentState.RECOVERING)
        self.assertIs(mgr.complete_recovery("budget raised", seq=3), IncidentState.NORMAL)
        self.assertEqual(len(mgr.archived_bundles()), 1)
        self.assertIsNone(mgr.incidents.active_bundle)
        self.assertIsNone(mgr.active_budget_bundle())
        # the historical budget bundle still links to the archived incident
        archived = mgr.archived_bundles()[0]
        self.assertEqual(mgr.budget_bundles()[0].incident_id, archived.incident_id)

    def test_audit_event_shape(self):
        mgr = FailureBudgetManager(max_budget_usd=1.0)
        with self.assertRaises(BudgetExhausted):
            mgr.guarded_charge("tool", 0.02, seq=1)
        bundle = mgr.active_budget_bundle()
        assert bundle is not None
        event = failure_budget_audit_event(bundle, seq=9)
        self.assertEqual(event["schema"], SCHEMA_PIN)
        self.assertEqual(event["audit_seq"], 9)
        self.assertEqual(event["incident_id"], bundle.incident_id)

    def test_degrade_still_available(self):
        mgr = FailureBudgetManager()
        self.assertIs(mgr.degrade("partial", seq=0), IncidentState.DEGRADED)

    def test_main_self_check(self):
        import failure_budget_combo
        failure_budget_combo.main()


if __name__ == "__main__":
    unittest.main()
