"""Tests for cost_optimization (CloudHealth-shaped spend bookkeeping)."""

import ast
import subprocess
import sys
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parent.parent / "cost_optimization.py"

from cost_optimization import (
    AUDIT_SCHEMA,
    BUDGET_VERDICTS,
    COST_OPTIMIZATION_SCHEMA,
    COST_OPTIMIZATION_VERSION,
    REC_STATUS_APPLIED,
    REC_STATUS_DISMISSED,
    REC_STATUS_OPEN,
    RECOMMENDATION_KINDS,
    RESOURCE_CATEGORIES,
    BadAccountError,
    BadBreakdownError,
    BadBudgetError,
    BadRecommendationError,
    CostOptimization,
    CostOptimizationError,
    DuplicateAccountError,
    RecommendationStateError,
    SeqOrderError,
    UnknownAccountError,
    UnknownRecommendationError,
    cost_optimization_audit_event,
)


class TestPins(unittest.TestCase):
    def test_version_pins(self):
        self.assertEqual(COST_OPTIMIZATION_VERSION, "cost-optimization.v1")
        self.assertEqual(
            COST_OPTIMIZATION_SCHEMA, "northstar.cost-optimization.v1"
        )
        self.assertEqual(AUDIT_SCHEMA, "audit.ndjson/1")

    def test_vocabularies(self):
        self.assertIn("compute", RESOURCE_CATEGORIES)
        self.assertIn("data_transfer", RESOURCE_CATEGORIES)
        for kind in ("rightsize", "idle_resource", "reservation",
                     "savings_plan", "spot_migration"):
            self.assertIn(kind, RECOMMENDATION_KINDS)
        for verdict in ("within", "over", "unknown"):
            self.assertIn(verdict, BUDGET_VERDICTS)

    def test_stdlib_only(self):
        tree = ast.parse(MODULE_PATH.read_text())
        allowed = {
            "__future__", "hashlib", "json", "threading", "dataclasses",
            "typing",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertIn(alias.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed)

    def test_main_self_check(self):
        result = subprocess.run(
            [sys.executable, str(MODULE_PATH)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("cost-optimization OK", result.stdout)


class TestRegister(unittest.TestCase):
    def setUp(self):
        self.mgr = CostOptimization()

    def test_register_roundtrip(self):
        record = self.mgr.register_account("prod", seq=1)
        self.assertTrue(record.verify())
        self.assertEqual(record.account_id, "prod")
        self.assertEqual(record.digest, self.mgr.account("prod").digest)
        self.assertEqual(self.mgr.account_ids(), ("prod",))

    def test_register_bad_ids(self):
        seq = 10
        for bad in ("", "   ", None, 123, True):
            with self.assertRaises(BadAccountError):
                self.mgr.register_account(bad, seq=seq)
            # Failed mutations consume their seq (batch discipline).
            seq += 1

    def test_register_duplicate_refused(self):
        self.mgr.register_account("prod", seq=1)
        with self.assertRaises(DuplicateAccountError):
            self.mgr.register_account("prod", seq=2)

    def test_register_unknown_account_lookup(self):
        with self.assertRaises(UnknownAccountError):
            self.mgr.account("nope")


class TestAnalyze(unittest.TestCase):
    def setUp(self):
        self.mgr = CostOptimization()
        self.mgr.register_account("prod", seq=1)

    def test_analyze_roundtrip(self):
        record = self.mgr.analyze(
            "prod",
            {"compute": 120000, "storage": 30000, "network": 10000},
            seq=2,
        )
        self.assertTrue(record.verify())
        self.assertEqual(record.analysis_id, "ana-1")
        self.assertEqual(record.total_cents, 160000)
        self.assertEqual(record.per_category["compute"], 120000)

    def test_analyze_ids_increment(self):
        first = self.mgr.analyze("prod", {"compute": 1}, seq=2)
        second = self.mgr.analyze("prod", {"compute": 2}, seq=3)
        self.assertNotEqual(first.analysis_id, second.analysis_id)
        self.assertEqual(
            [a.analysis_id for a in self.mgr.analyses_for("prod")],
            [second.analysis_id, first.analysis_id],
        )

    def test_analyze_bad_breakdown(self):
        bad_cases = [
            ({}, "empty"),
            (None, "non-mapping"),
            ({"nope": 100}, "unknown category"),
            ({"compute": -1}, "negative"),
            ({"compute": 1.5}, "float"),
            ({"compute": True}, "bool"),
            ({"compute": "100"}, "string"),
        ]
        seq = 2
        for breakdown, _label in bad_cases:
            with self.assertRaises(BadBreakdownError):
                self.mgr.analyze("prod", breakdown, seq=seq)
            seq += 1

    def test_analyze_unknown_account(self):
        with self.assertRaises(UnknownAccountError):
            self.mgr.analyze("ghost", {"compute": 1}, seq=2)


class TestRecommend(unittest.TestCase):
    def setUp(self):
        self.mgr = CostOptimization()
        self.mgr.register_account("prod", seq=1)

    def test_recommend_roundtrip(self):
        record = self.mgr.recommend(
            "prod", "rightsize", seq=2,
            estimated_monthly_savings_cents=25000,
            note="downsize nodes",
        )
        self.assertTrue(record.verify())
        self.assertEqual(record.recommendation_id, "rec-1")
        self.assertEqual(record.kind, "rightsize")
        self.assertEqual(record.status, REC_STATUS_OPEN)
        self.assertEqual(record.estimated_monthly_savings_cents, 25000)

    def test_recommend_all_kinds(self):
        seq = 2
        for kind in RECOMMENDATION_KINDS:
            record = self.mgr.recommend("prod", kind, seq=seq)
            self.assertTrue(record.verify())
            seq += 1
        self.assertEqual(len(self.mgr.recommendations_for("prod")), 5)

    def test_recommend_bad_kind(self):
        with self.assertRaises(BadRecommendationError):
            self.mgr.recommend("prod", "time-travel", seq=2)

    def test_recommend_bad_savings_and_note(self):
        with self.assertRaises(BadBudgetError):
            self.mgr.recommend("prod", "rightsize", seq=2,
                               estimated_monthly_savings_cents=-5)
        with self.assertRaises(BadBudgetError):
            self.mgr.recommend("prod", "rightsize", seq=3,
                               estimated_monthly_savings_cents=1.5)
        with self.assertRaises(BadRecommendationError):
            self.mgr.recommend("prod", "rightsize", seq=4,
                               note="x" * 1025)

    def test_recommendation_lifecycle(self):
        self.mgr.recommend("prod", "idle_resource", seq=2)
        applied = self.mgr.apply_recommendation("rec-1", seq=3)
        self.assertTrue(applied.verify())
        self.assertEqual(applied.resolution, REC_STATUS_APPLIED)
        self.assertEqual(
            self.mgr.recommendation("rec-1").status, REC_STATUS_APPLIED
        )
        # Terminal: cannot apply or dismiss again.
        with self.assertRaises(RecommendationStateError):
            self.mgr.apply_recommendation("rec-1", seq=4)
        with self.assertRaises(RecommendationStateError):
            self.mgr.dismiss_recommendation("rec-1", seq=5)

        self.mgr.recommend("prod", "reservation", seq=6)
        dismissed = self.mgr.dismiss_recommendation("rec-2", seq=7)
        self.assertEqual(dismissed.resolution, REC_STATUS_DISMISSED)
        self.assertEqual(
            [r.status for r in
             self.mgr.recommendations_for("prod", status=REC_STATUS_OPEN)],
            [],
        )
        self.assertEqual(
            len(self.mgr.recommendations_for(
                "prod", status=REC_STATUS_DISMISSED)), 1
        )

    def test_recommendation_unknown(self):
        with self.assertRaises(UnknownRecommendationError):
            self.mgr.apply_recommendation("rec-999", seq=2)
        with self.assertRaises(UnknownRecommendationError):
            self.mgr.recommendation("rec-999")


class TestBudget(unittest.TestCase):
    def setUp(self):
        self.mgr = CostOptimization()
        self.mgr.register_account("prod", seq=1)

    def test_track_roundtrip(self):
        record = self.mgr.track("prod", seq=2, budget_cents=200000)
        self.assertTrue(record.verify())
        self.assertEqual(record.budget_cents, 200000)
        self.assertEqual(self.mgr.budget("prod").budget_cents, 200000)

    def test_track_latest_wins(self):
        self.mgr.track("prod", seq=2, budget_cents=200000)
        self.mgr.track("prod", seq=3, budget_cents=150000)
        self.assertEqual(self.mgr.budget("prod").budget_cents, 150000)

    def test_track_bad_budgets(self):
        for bad in (0, -1, 1.5, True, "100", None):
            with self.assertRaises((BadBudgetError, CostOptimizationError)):
                self.mgr.track("prod", seq=10, budget_cents=bad)

    def test_budget_check_within_over_unknown(self):
        self.mgr.track("prod", seq=2, budget_cents=200000)
        # No analysis booked yet -> unknown.
        check = self.mgr.budget_check("prod", seq=3)
        self.assertTrue(check.verify())
        self.assertEqual(check.verdict, "unknown")
        self.assertIsNone(check.observed_cents)

        self.mgr.analyze("prod", {"compute": 120000}, seq=4)
        within = self.mgr.budget_check("prod", seq=5)
        self.assertEqual(within.verdict, "within")
        self.assertEqual(within.observed_cents, 120000)

        self.mgr.analyze("prod", {"compute": 500000}, seq=6)
        over = self.mgr.budget_check("prod", seq=7)
        self.assertEqual(over.verdict, "over")
        self.assertEqual(over.observed_cents, 500000)

    def test_budget_check_is_read_view(self):
        self.mgr.track("prod", seq=2, budget_cents=100)
        # Reusing seq 2 must not raise: read views don't consume seq.
        self.mgr.budget_check("prod", seq=2)
        self.mgr.budget_check("prod", seq=2)

    def test_budget_check_no_budget(self):
        with self.assertRaises(UnknownAccountError):
            self.mgr.budget_check("prod", seq=2)


class TestSeqDiscipline(unittest.TestCase):
    def setUp(self):
        self.mgr = CostOptimization()

    def test_seq_rewind_refused(self):
        self.mgr.register_account("prod", seq=5)
        with self.assertRaises(SeqOrderError):
            self.mgr.register_account("other", seq=5)
        with self.assertRaises(SeqOrderError):
            self.mgr.register_account("other", seq=4)

    def test_seq_bad_shapes(self):
        for bad in (True, -1, 1.5, "2", None):
            with self.assertRaises(CostOptimizationError):
                self.mgr.register_account("prod", seq=bad)

    def test_failed_mutation_consumes_seq(self):
        self.mgr.register_account("prod", seq=1)
        with self.assertRaises(DuplicateAccountError):
            self.mgr.register_account("prod", seq=2)
        # seq 2 was consumed by the refused mutation.
        with self.assertRaises(SeqOrderError):
            self.mgr.register_account("other", seq=2)
        self.mgr.register_account("other", seq=3)


class TestAudit(unittest.TestCase):
    def setUp(self):
        self.mgr = CostOptimization()

    def test_audit_shapes(self):
        self.mgr.register_account("prod", seq=1)
        self.mgr.analyze("prod", {"compute": 100}, seq=2)
        self.mgr.recommend("prod", "rightsize", seq=3)
        self.mgr.track("prod", seq=4, budget_cents=1000)
        kinds = [event["kind"] for event in self.mgr.audit_log()]
        self.assertEqual(
            kinds,
            [
                "cost.account-registered",
                "cost.analyzed",
                "cost.recommended",
                "cost.budget-set",
            ],
        )
        for event in self.mgr.audit_log():
            self.assertEqual(event["schema"], AUDIT_SCHEMA)

    def test_audit_banned_keys(self):
        event = cost_optimization_audit_event(
            "cost.analyzed", 1, account_id="prod", analysis_id="ana-1"
        )
        self.assertNotIn("breakdown", event["detail"])
        for banned in ("breakdown", "amounts", "budget_cents",
                       "estimated_savings_cents", "total_cents", "note"):
            with self.assertRaises(CostOptimizationError):
                cost_optimization_audit_event(
                    "cost.analyzed", 2, **{banned: "x"}
                )

    def test_audit_bad_kind(self):
        with self.assertRaises(CostOptimizationError):
            cost_optimization_audit_event("cost.nope", 1)

    def test_rejected_rows_are_audited(self):
        self.mgr.register_account("prod", seq=1)
        with self.assertRaises(DuplicateAccountError):
            self.mgr.register_account("prod", seq=2)
        kinds = [event["kind"] for event in self.mgr.audit_log()]
        self.assertIn("cost.rejected", kinds)


class TestViews(unittest.TestCase):
    def setUp(self):
        self.mgr = CostOptimization()

    def test_stats(self):
        self.mgr.register_account("a", seq=1)
        self.mgr.register_account("b", seq=2)
        self.mgr.analyze("a", {"compute": 10}, seq=3)
        self.mgr.recommend("a", "spot_migration", seq=4)
        self.mgr.track("a", seq=5, budget_cents=100)
        stats = self.mgr.stats()
        self.assertEqual(stats["accounts"], 2)
        self.assertEqual(stats["analyses"], 1)
        self.assertEqual(stats["recommendations"], 1)
        self.assertEqual(stats["budgets"], 1)

    def test_cross_instance_digest_determinism(self):
        first = CostOptimization()
        second = CostOptimization()
        first.register_account("prod", seq=1)
        second.register_account("prod", seq=1)
        first.analyze("prod", {"compute": 100, "storage": 50}, seq=2)
        second.analyze("prod", {"compute": 100, "storage": 50}, seq=2)
        self.assertEqual(
            first.analyses_for("prod")[0].digest,
            second.analyses_for("prod")[0].digest,
        )


if __name__ == "__main__":
    unittest.main()
