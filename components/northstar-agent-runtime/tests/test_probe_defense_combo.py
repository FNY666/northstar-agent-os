"""Tests for probe_defense_combo: flywheel probes feeding plan defense."""

import importlib.util
import sys
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_probe_flywheel = _load("probe_flywheel", BASE / "probe_flywheel.py")
_plan_defense = _load("plan_defense", BASE / "plan_defense.py")
pdc = _load("probe_defense_combo", BASE / "probe_defense_combo.py")


def _bundle(action, error, seq):
    return {"failed_action": action, "error": error, "created_seq": seq}


def _loop_with_rule(action="db.delete", error="permission-denied"):
    loop = pdc.ProbeDefenseLoop(trusted_subgoal_ids={"a"})
    for seq in range(1, _probe_flywheel.PROBE_THRESHOLD + 1):
        loop.record_failure(_bundle(action, error, seq))
    return loop


CLEAN_PLAN = {
    "subgoals": [
        {"id": "a", "description": "fetch user profile data"},
    ]
}


class TestVersionPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(pdc.PROBE_DEFENSE_COMBO_VERSION, "probe-defense-combo.v1")

    def test_schema_pin(self):
        self.assertEqual(pdc.SCHEMA_PIN, "northstar.probe-defense-combo.v1")

    def test_issue_vocab(self):
        self.assertEqual(pdc.ISSUE_PROBE_BLOCKED, "probe-blocked")


class TestRuleCreation(unittest.TestCase):
    def test_below_threshold_no_rules(self):
        loop = pdc.ProbeDefenseLoop()
        rep = loop.record_failure(_bundle("db.delete", "permission-denied", 1))
        self.assertEqual(rep.new_rules, ())
        self.assertEqual(rep.total_rules, 0)
        self.assertEqual(loop.rules, ())

    def test_threshold_creates_one_rule(self):
        loop = pdc.ProbeDefenseLoop()
        rep = None
        for seq in range(1, _probe_flywheel.PROBE_THRESHOLD + 1):
            rep = loop.record_failure(_bundle("db.delete", "permission-denied", seq))
        self.assertEqual(len(rep.new_rules), 1)
        self.assertEqual(rep.total_rules, 1)
        rule = loop.rules[0]
        self.assertEqual(rule.action_type, "db.delete")
        self.assertEqual(rule.error_type, "permission-denied")
        self.assertTrue(rule.rule_id.startswith("failure-flywheel-"))
        self.assertEqual(rule.probe_name, rule.rule_id)
        self.assertEqual(rule.action_tokens, frozenset({"db", "delete"}))
        self.assertEqual(rule.created_seq, _probe_flywheel.PROBE_THRESHOLD)

    def test_no_duplicate_rules_on_further_failures(self):
        loop = _loop_with_rule()
        rep = loop.record_failure(_bundle("db.delete", "permission-denied", 99))
        self.assertEqual(rep.new_rules, ())
        self.assertEqual(rep.total_rules, 1)
        self.assertEqual(len(loop.rules), 1)

    def test_second_pattern_second_rule(self):
        loop = _loop_with_rule()
        for seq in range(10, 10 + _probe_flywheel.PROBE_THRESHOLD):
            loop.record_failure(_bundle("s3.upload", "timeout", seq))
        self.assertEqual(len(loop.rules), 2)
        # creation order is deterministic: db.delete first, s3.upload second
        self.assertEqual(loop.rules[0].action_type, "db.delete")
        self.assertEqual(loop.rules[1].action_type, "s3.upload")

    def test_tokenless_action_fails_closed(self):
        loop = pdc.ProbeDefenseLoop()
        with self.assertRaises(ValueError):
            for seq in range(1, _probe_flywheel.PROBE_THRESHOLD + 1):
                loop.record_failure(_bundle("!!!", "boom", seq))

    def test_ingestion_report_shape(self):
        loop = pdc.ProbeDefenseLoop()
        rep = loop.record_failure(_bundle("x.y", "e", 5))
        d = rep.as_dict()
        self.assertEqual(d["schema"], pdc.SCHEMA_PIN)
        self.assertEqual(d["combo_version"], pdc.PROBE_DEFENSE_COMBO_VERSION)
        self.assertEqual(d["total_rules"], 0)
        self.assertIn("pattern", d)


class TestRuleMatching(unittest.TestCase):
    def test_match_on_subgoal_id(self):
        loop = _loop_with_rule()
        rule = loop.rules[0]
        self.assertEqual(
            rule.matches_subgoal("db-delete-rows", "something else"),
            ("db", "delete"),
        )

    def test_match_on_description(self):
        loop = _loop_with_rule()
        rule = loop.rules[0]
        matched = rule.matches_subgoal("step-9", "please delete the db snapshot")
        self.assertIn("db", matched)
        self.assertIn("delete", matched)

    def test_no_match(self):
        loop = _loop_with_rule()
        rule = loop.rules[0]
        self.assertEqual(rule.matches_subgoal("send-newsletter", "email users"), ())

    def test_rule_as_dict(self):
        loop = _loop_with_rule()
        d = loop.rules[0].as_dict()
        self.assertEqual(d["schema"], pdc.SCHEMA_PIN)
        self.assertEqual(d["action_tokens"], ["db", "delete"])

    def test_rule_validation(self):
        with self.assertRaises(ValueError):
            pdc.DefenseRule(
                rule_id="r", action_type="a", error_type="e",
                probe_name="p", action_tokens=frozenset(),
            )
        with self.assertRaises(ValueError):
            pdc.DefenseRule(
                rule_id="", action_type="a", error_type="e",
                probe_name="p", action_tokens=frozenset({"a"}),
            )


class TestCheck(unittest.TestCase):
    def test_clean_plan_is_clean(self):
        loop = _loop_with_rule()
        self.assertEqual(loop.check(CLEAN_PLAN, "fetch user profile", 50, 10), "clean")

    def test_matching_subgoal_flagged(self):
        loop = pdc.ProbeDefenseLoop(trusted_subgoal_ids={"a", "db-delete-rows"})
        for seq in range(1, _probe_flywheel.PROBE_THRESHOLD + 1):
            loop.record_failure(_bundle("db.delete", "permission-denied", seq))
        plan = {
            "subgoals": [
                {"id": "a", "description": "fetch user profile data"},
                {"id": "db-delete-rows", "description": "delete stale rows from db"},
            ]
        }
        verdict = loop.check(plan, "fetch user profile", 50, 10)
        self.assertEqual(verdict, [pdc.ISSUE_PROBE_BLOCKED])

    def test_base_issues_still_surface(self):
        loop = pdc.ProbeDefenseLoop(trusted_subgoal_ids={"a"})
        for seq in range(1, _probe_flywheel.PROBE_THRESHOLD + 1):
            loop.record_failure(_bundle("db.delete", "permission-denied", seq))
        plan = {
            "subgoals": [
                {"id": "a", "description": "fetch user profile data"},
                {"id": "db-delete-rows", "description": "delete stale rows"},
            ]
        }
        verdict = loop.check(plan, "fetch user profile", 50, 10)
        self.assertIn(_plan_defense.ISSUE_PLAN_INJECTION, verdict)
        self.assertIn(pdc.ISSUE_PROBE_BLOCKED, verdict)
        # base issues keep their fixed order, probe-blocked last
        self.assertLess(
            verdict.index(_plan_defense.ISSUE_PLAN_INJECTION),
            verdict.index(pdc.ISSUE_PROBE_BLOCKED),
        )

    def test_stale_plan_with_probe(self):
        loop = _loop_with_rule()
        verdict = loop.check(CLEAN_PLAN, "fetch user profile", 5000, 10)
        self.assertIn(_plan_defense.ISSUE_STALE_PLAN, verdict)

    def test_malformed_plan_no_crash(self):
        loop = _loop_with_rule()
        verdict = loop.check({"nope": True}, "goal", 50, 10)
        self.assertIn(_plan_defense.ISSUE_STALE_PLAN, verdict)
        self.assertIn(_plan_defense.ISSUE_PLAN_INJECTION, verdict)
        self.assertIn(_plan_defense.ISSUE_SCOPE_DRIFT, verdict)
        self.assertNotIn(pdc.ISSUE_PROBE_BLOCKED, verdict)

    def test_check_report_shape(self):
        loop = _loop_with_rule()
        report = loop.check_report(CLEAN_PLAN, "fetch user profile", 50, 10)
        self.assertTrue(report.clean)
        self.assertEqual(report.issues, ())
        self.assertEqual(report.rule_hits, ())
        d = report.as_dict()
        self.assertEqual(d["schema"], pdc.SCHEMA_PIN)
        self.assertTrue(d["clean"])

    def test_rule_hit_detail(self):
        loop = pdc.ProbeDefenseLoop(trusted_subgoal_ids={"db-delete-rows"})
        for seq in range(1, _probe_flywheel.PROBE_THRESHOLD + 1):
            loop.record_failure(_bundle("db.delete", "permission-denied", seq))
        plan = {"subgoals": [{"id": "db-delete-rows", "description": "db delete rows"}]}
        report = loop.check_report(plan, "db delete rows", 50, 10)
        self.assertFalse(report.clean)
        self.assertEqual(len(report.rule_hits), 1)
        hit = report.rule_hits[0]
        self.assertEqual(hit.subgoal_id, "db-delete-rows")
        self.assertEqual(hit.rule_id, loop.rules[0].rule_id)
        self.assertIn("delete", hit.matched_tokens)


class TestRemediation(unittest.TestCase):
    def test_remediate_lifts_rule(self):
        loop = pdc.ProbeDefenseLoop(trusted_subgoal_ids={"db-delete-rows"})
        for seq in range(1, _probe_flywheel.PROBE_THRESHOLD + 1):
            loop.record_failure(_bundle("db.delete", "permission-denied", seq))
        plan = {
            "subgoals": [{"id": "db-delete-rows", "description": "delete rows"}]
        }
        self.assertNotEqual(
            loop.check(plan, "db delete rows", 50, 10), "clean"
        )
        removed = loop.remediate(loop.rules[0].rule_id)
        self.assertEqual(removed.action_type, "db.delete")
        self.assertEqual(loop.rules, ())
        self.assertEqual(loop.check(plan, "db delete rows", 50, 10), "clean")

    def test_remediate_unknown_raises(self):
        loop = _loop_with_rule()
        with self.assertRaises(KeyError):
            loop.remediate("no-such-rule")


class TestTrustedSet(unittest.TestCase):
    def test_set_trusted_subgoal_ids(self):
        loop = pdc.ProbeDefenseLoop()
        plan = {"subgoals": [{"id": "zz", "description": "mystery"}]}
        self.assertIn(
            _plan_defense.ISSUE_PLAN_INJECTION,
            loop.check(plan, "mystery", 50, 10),
        )
        loop.set_trusted_subgoal_ids({"zz"})
        self.assertEqual(loop.check(plan, "mystery", 50, 10), "clean")

    def test_constructor_validation_passthrough(self):
        with self.assertRaises(Exception):
            pdc.ProbeDefenseLoop(trusted_subgoal_ids={""})


class TestFailClosed(unittest.TestCase):
    def test_malformed_bundle_raises(self):
        loop = pdc.ProbeDefenseLoop()
        with self.assertRaises(ValueError):
            loop.record_failure({"bogus": 1})
        with self.assertRaises(ValueError):
            loop.record_failure(None)

    def test_bulk_ingest(self):
        loop = pdc.ProbeDefenseLoop()
        reports = loop.record_failures(
            _bundle("a.b", "e", seq)
            for seq in range(1, _probe_flywheel.PROBE_THRESHOLD + 1)
        )
        self.assertEqual(len(reports), _probe_flywheel.PROBE_THRESHOLD)
        self.assertEqual(reports[-1].total_rules, 1)


class TestMain(unittest.TestCase):
    def test_main_runs(self):
        pdc.main()


if __name__ == "__main__":
    unittest.main()
