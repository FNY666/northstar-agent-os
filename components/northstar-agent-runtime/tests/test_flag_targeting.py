"""Tests for flag_targeting: 15 cases."""

import ast
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from flag_targeting import (
    BUCKETS,
    SCHEMA_PIN,
    BadPredicateError,
    BadStageError,
    BadVariationError,
    DuplicateFlagError,
    DuplicateRuleError,
    FlagTargeting,
    SeqOrderError,
    UnknownFlagError,
    UnknownRuleError,
    flag_targeting_audit_event,
    main,
)


def make_flag(ft=None, seq=1):
    ft = ft or FlagTargeting()
    ft.define("f", ["control", "treatment"], seq=seq, description="d")
    return ft


class TestFlagTargeting(unittest.TestCase):
    def test_01_pins(self):
        self.assertEqual(SCHEMA_PIN, "northstar.flag-targeting.v1")
        self.assertEqual(BUCKETS, 10_000)

    def test_02_define_roundtrip_and_verify(self):
        ft = FlagTargeting()
        rec = ft.define("f", ["control", "treatment"], seq=1, description="d")
        self.assertTrue(rec.digest.startswith("sha256:"))
        self.assertTrue(rec.verify())
        self.assertEqual(ft.flag("f").digest, rec.digest)

    def test_03_duplicate_flag(self):
        ft = make_flag()
        with self.assertRaises(DuplicateFlagError):
            ft.define("f", ["a", "b"], seq=2)

    def test_04_bad_variations(self):
        ft = FlagTargeting()
        with self.assertRaises(BadVariationError):
            ft.define("x", ["only"], seq=1)  # < 2
        with self.assertRaises(BadVariationError):
            ft.define("y", ["a", "a"], seq=1)  # dup
        with self.assertRaises(BadVariationError):
            ft.define("z", ["a", "b"], seq=1, default="c")  # default not in set

    def test_05_add_rule_and_predicate_digest(self):
        ft = make_flag()
        rule = ft.add_rule(
            "f", "r1",
            {"attr": "country", "op": "eq", "value": "DE"},
            "treatment", seq=2, priority=5,
        )
        self.assertTrue(rule.verify("f"))
        with self.assertRaises(DuplicateRuleError):
            ft.add_rule("f", "r1",
                        {"attr": "country", "op": "eq", "value": "DE"},
                        "treatment", seq=3)

    def test_06_bad_predicate_refused(self):
        ft = make_flag()
        with self.assertRaises(BadPredicateError):
            ft.add_rule("f", "r1",
                        {"attr": "c", "op": "fuzzy", "value": "DE"},
                        "treatment", seq=2)  # unknown op
        with self.assertRaises(BadPredicateError):
            ft.add_rule("f", "r2", {"any": []}, "treatment", seq=2)  # empty
        with self.assertRaises(BadPredicateError):
            ft.add_rule("f", "r3",
                        {"attr": "age", "op": "gt", "value": "old"},
                        "treatment", seq=2)  # comparison needs number
        with self.assertRaises(BadPredicateError):
            ft.add_rule("f", "r4",
                        {"attr": "v", "op": "semver-gt", "value": "x"},
                        "treatment", seq=2)  # bad semver

    def test_07_rule_beats_rollout_and_predicate_asts(self):
        ft = make_flag()
        ft.add_rule(
            "f", "semver-rule",
            {"all": [
                {"attr": "version", "op": "semver-gt", "value": "2.0.0"},
                {"not": {"attr": "internal", "op": "eq", "value": True}},
            ]},
            "treatment", seq=2,
        )
        ft.rollout("f", [{"percent": 100}], seq=3)
        hit = ft.evaluate("f", "u1", {"version": "2.5.0", "internal": False}, seq=4)
        self.assertEqual(hit.variation, "treatment")
        self.assertEqual(hit.reason, "rule")
        self.assertEqual(hit.rule_id, "semver-rule")
        self.assertTrue(hit.verify(["control", "treatment"]))
        miss = ft.evaluate("f", "u1", {"version": "1.0.0"}, seq=5)
        self.assertEqual(miss.reason, "rollout")
        no_attr = ft.evaluate("f", "u2", {}, seq=6)
        self.assertEqual(no_attr.reason, "rollout")

    def test_08_staged_rollout_promote(self):
        ft = make_flag()
        ft.rollout("f", [{"percent": 0}, {"percent": 100}], seq=2)
        self.assertEqual(ft.stage_index("f"), 0)
        before = ft.evaluate("f", "u9", {}, seq=3)
        self.assertEqual(before.reason, "default")  # 0% -> default
        promo = ft.promote("f", seq=4)
        self.assertEqual(promo.stage_index, 1)
        self.assertTrue(promo.verify())
        after = ft.evaluate("f", "u9", {}, seq=5)
        self.assertEqual(after.reason, "rollout")
        self.assertEqual(after.stage_index, 1)
        with self.assertRaises(BadStageError):
            ft.promote("f", seq=6)  # already final

    def test_09_weighted_variations_deterministic(self):
        ft = FlagTargeting()
        ft.define("ab", ["a", "b", "c"], seq=1)
        ft.rollout("ab", [{"percent": 100,
                           "weights": {"a": 50.0, "b": 30.0, "c": 20.0}}], seq=2)
        first = {}
        for n in range(200):
            r = ft.evaluate("ab", f"s{n}", {}, seq=3)
            self.assertIn(r.variation, ("a", "b", "c"))
            again = ft.evaluate("ab", f"s{n}", {}, seq=4)
            self.assertEqual(again.variation, r.variation)
            first[r.variation] = first.get(r.variation, 0) + 1
        # Weights are roughly honored (not exact, just sane spread).
        self.assertTrue(all(first.get(v, 0) > 0 for v in ("a", "b", "c")))

    def test_10_kill_switch(self):
        ft = make_flag()
        ft.add_rule("f", "r1",
                    {"attr": "country", "op": "eq", "value": "DE"},
                    "treatment", seq=2)
        ft.disable("f", seq=3)
        rep = ft.evaluate("f", "u1", {"country": "DE"}, seq=4)
        self.assertEqual(rep.variation, "control")
        self.assertEqual(rep.reason, "default")
        ft.enable("f", seq=5)
        rep2 = ft.evaluate("f", "u1", {"country": "DE"}, seq=6)
        self.assertEqual(rep2.reason, "rule")

    def test_11_seq_ordering(self):
        ft = make_flag()
        with self.assertRaises(SeqOrderError):
            ft.disable("f", seq=1)  # rewind
        with self.assertRaises(TypeError):
            ft.disable("f", seq=True)  # bool
        with self.assertRaises(ValueError):
            ft.disable("f", seq=-1)  # negative
        # Failed mutation consumed seq 1 already -> seq 2 must be > last.
        rep = ft.disable("f", seq=2)
        self.assertFalse(rep.enabled)

    def test_12_unknown_flag_and_rule(self):
        ft = FlagTargeting()
        with self.assertRaises(UnknownFlagError):
            ft.evaluate("nope", "u", {}, seq=1)
        ft = make_flag()
        with self.assertRaises(UnknownRuleError):
            ft.remove_rule("f", "nope", seq=2)
        with self.assertRaises(BadStageError):
            ft.promote("f", seq=2)  # no plan

    def test_13_audit_shapes_and_bad_kind(self):
        ft = make_flag()
        ft.add_rule("f", "r1",
                    {"attr": "country", "op": "eq", "value": "DE"},
                    "treatment", seq=2)
        kinds = {e["kind"] for e in ft.audit_log()}
        self.assertIn("flag-targeting.flag-defined", kinds)
        self.assertIn("flag-targeting.rule-added", kinds)
        for e in ft.audit_log():
            self.assertEqual(e["schema"], "audit.ndjson/1")
            self.assertEqual(e["module"], "flag-targeting.v1")
        with self.assertRaises(Exception):
            flag_targeting_audit_event("nope", 1)

    def test_14_stdlib_only_ast(self):
        src = os.path.join(os.path.dirname(__file__), "..", "flag_targeting.py")
        tree = ast.parse(open(src).read())
        allowed = {"hashlib", "threading", "dataclasses", "typing", "__future__"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], allowed, a.name)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed, node.module)

    def test_15_main_self_check(self):
        main()


if __name__ == "__main__":
    unittest.main()
