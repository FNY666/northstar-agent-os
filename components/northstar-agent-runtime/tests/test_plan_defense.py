"""Tests for plan_defense: stale-plan, plan-injection, scope-drift."""
from __future__ import annotations

import unittest

import plan_defense as pd
from plan_defense import (
    ISSUE_PLAN_INJECTION,
    ISSUE_SCOPE_DRIFT,
    ISSUE_STALE_PLAN,
    SCOPE_DRIFT_THRESHOLD,
    STALE_PLAN_THRESHOLD,
    DefenseReport,
    MalformedPlan,
    PlanDefense,
    PlanDefenseError,
)


def make_plan(*ids: str, descs: dict | None = None) -> dict:
    descs = descs or {}
    return {
        "subgoals": [
            {"id": sid, "description": descs.get(sid, f"do {sid} work")}
            for sid in ids
        ]
    }


class StalePlanTests(unittest.TestCase):
    def test_fresh_plan_not_stale(self):
        plan = make_plan("a")
        self.assertFalse(pd.detect_stale_plan(plan, 50, 10))

    def test_exactly_at_threshold_not_stale(self):
        plan = make_plan("a")
        self.assertFalse(
            pd.detect_stale_plan(plan, STALE_PLAN_THRESHOLD, 0)
        )

    def test_one_past_threshold_is_stale(self):
        plan = make_plan("a")
        self.assertTrue(
            pd.detect_stale_plan(plan, STALE_PLAN_THRESHOLD + 1, 0)
        )

    def test_future_plan_is_stale_fail_closed(self):
        plan = make_plan("a")
        self.assertTrue(pd.detect_stale_plan(plan, 10, 50))

    def test_malformed_plan_raises(self):
        with self.assertRaises(MalformedPlan):
            pd.detect_stale_plan({"no": "subgoals"}, 50, 10)

    def test_bool_seq_rejected(self):
        plan = make_plan("a")
        with self.assertRaises(PlanDefenseError):
            pd.detect_stale_plan(plan, True, 0)

    def test_negative_seq_rejected(self):
        plan = make_plan("a")
        with self.assertRaises(PlanDefenseError):
            pd.detect_stale_plan(plan, 50, -1)


class InjectionTests(unittest.TestCase):
    def test_all_trusted_not_injected(self):
        plan = make_plan("a", "b")
        self.assertFalse(pd.detect_plan_injection(plan, {"a", "b"}))

    def test_one_untrusted_is_injected(self):
        plan = make_plan("a", "evil")
        self.assertTrue(pd.detect_plan_injection(plan, {"a", "b"}))

    def test_empty_plan_not_injected(self):
        plan = {"subgoals": []}
        self.assertFalse(pd.detect_plan_injection(plan, {"a"}))

    def test_empty_trusted_set_flags_everything(self):
        plan = make_plan("a")
        self.assertTrue(pd.detect_plan_injection(plan, set()))

    def test_bad_trusted_id_rejected(self):
        plan = make_plan("a")
        with self.assertRaises(PlanDefenseError):
            pd.detect_plan_injection(plan, [""])

    def test_subgoal_without_id_raises(self):
        with self.assertRaises(MalformedPlan):
            pd.detect_plan_injection({"subgoals": [{"description": "x"}]}, {"a"})


class DriftTests(unittest.TestCase):
    def test_high_overlap_not_drift(self):
        subs = [{"description": "fetch user profile data from database"}]
        self.assertFalse(
            pd.detect_scope_drift("fetch user profile data", subs)
        )

    def test_low_overlap_is_drift(self):
        subs = [{"description": "launch rocket to mars colony"}]
        self.assertTrue(
            pd.detect_scope_drift("fetch user profile data", subs)
        )

    def test_empty_goal_is_drift(self):
        subs = [{"description": "do something"}]
        self.assertTrue(pd.detect_scope_drift("", subs))
        self.assertTrue(pd.detect_scope_drift("   ... ", subs))

    def test_empty_subgoals_is_drift(self):
        self.assertTrue(pd.detect_scope_drift("fetch user profile", []))

    def test_non_string_goal_rejected(self):
        with self.assertRaises(PlanDefenseError):
            pd.detect_scope_drift(None, [])

    def test_case_insensitive_overlap(self):
        subs = [{"description": "FETCH USER PROFILE"}]
        self.assertFalse(
            pd.detect_scope_drift("fetch user profile", subs)
        )


class PlanDefenseClassTests(unittest.TestCase):
    def _defense(self) -> PlanDefense:
        return PlanDefense(trusted_subgoal_ids={"a", "b"})

    def test_clean_plan(self):
        d = self._defense()
        plan = make_plan(
            "a", "b",
            descs={"a": "fetch user profile", "b": "summarize user profile"},
        )
        self.assertEqual(
            d.check(plan, "fetch and summarize user profile", 50, 10), "clean"
        )

    def test_stale_issue(self):
        d = self._defense()
        plan = make_plan(
            "a", descs={"a": "fetch user profile"},
        )
        self.assertEqual(
            d.check(plan, "fetch user profile", 500, 10), [ISSUE_STALE_PLAN]
        )

    def test_injection_issue(self):
        d = self._defense()
        plan = make_plan(
            "a", "evil", descs={"a": "fetch user profile", "evil": "fetch user profile too"},
        )
        self.assertEqual(
            d.check(plan, "fetch user profile", 50, 10), [ISSUE_PLAN_INJECTION]
        )

    def test_drift_issue(self):
        d = self._defense()
        plan = make_plan(
            "a", descs={"a": "launch rocket to mars"},
        )
        self.assertEqual(
            d.check(plan, "fetch user profile", 50, 10), [ISSUE_SCOPE_DRIFT]
        )

    def test_multiple_issues_fixed_order(self):
        d = self._defense()
        plan = make_plan("evil", descs={"evil": "launch rocket"})
        self.assertEqual(
            d.check(plan, "fetch user profile", 500, 10),
            [ISSUE_STALE_PLAN, ISSUE_PLAN_INJECTION, ISSUE_SCOPE_DRIFT],
        )

    def test_malformed_plan_reports_all_issues(self):
        d = self._defense()
        self.assertEqual(
            d.check({"bad": 1}, "goal", 50, 10),
            [ISSUE_STALE_PLAN, ISSUE_PLAN_INJECTION, ISSUE_SCOPE_DRIFT],
        )

    def test_no_trusted_set_reports_injection(self):
        d = PlanDefense()
        plan = make_plan("a", descs={"a": "fetch user profile"})
        result = d.check(plan, "fetch user profile", 50, 10)
        self.assertIn(ISSUE_PLAN_INJECTION, result)

    def test_custom_thresholds(self):
        d = PlanDefense(trusted_subgoal_ids={"a"}, stale_threshold=10,
                        drift_threshold=0.9)
        plan = make_plan("a", descs={"a": "fetch user profile"})
        # age 11 > 10 -> stale
        self.assertIn(ISSUE_STALE_PLAN, d.check(plan, "fetch user profile", 11, 0))

    def test_bad_thresholds_rejected(self):
        with self.assertRaises(PlanDefenseError):
            PlanDefense(stale_threshold=-1)
        with self.assertRaises(PlanDefenseError):
            PlanDefense(drift_threshold=0)
        with self.assertRaises(PlanDefenseError):
            PlanDefense(drift_threshold=1.5)

    def test_report_shape(self):
        d = self._defense()
        plan = make_plan("a", descs={"a": "fetch user profile"})
        rep = d.check_report(plan, "fetch user profile", 50, 10)
        self.assertIsInstance(rep, DefenseReport)
        self.assertTrue(rep.clean)
        self.assertEqual(rep.issues, ())
        d2 = d.as_dict if hasattr(d, "as_dict") else None
        self.assertEqual(
            rep.as_dict()["defense_version"], pd.PLAN_DEFENSE_VERSION
        )

    def test_report_dirty(self):
        d = self._defense()
        plan = make_plan("a", descs={"a": "launch rocket"})
        rep = d.check_report(plan, "fetch user profile", 50, 10)
        self.assertFalse(rep.clean)
        self.assertEqual(rep.issues, (ISSUE_SCOPE_DRIFT,))

    def test_trusted_ids_property(self):
        d = self._defense()
        self.assertEqual(d.trusted_subgoal_ids, frozenset({"a", "b"}))

    def test_main_runs(self):
        pd.main()


if __name__ == "__main__":
    unittest.main()
