"""Tests for flag_service.py: targeting, rules, percentage rollouts."""

import ast
import threading
import unittest
from pathlib import Path

import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from flag_service import (  # noqa: E402
    BUCKETS,
    FLAG_SERVICE_VERSION,
    SCHEMA_PIN,
    DuplicateFlagError,
    DuplicateRuleError,
    EvaluationReport,
    FlagRecord,
    FlagService,
    FlagServiceError,
    RolloutRecord,
    RuleRecord,
    UnknownFlagError,
    UnknownRuleError,
    flag_service_audit_event,
    main,
)


class TestPins(unittest.TestCase):
    def test_version_and_schema(self):
        self.assertEqual(FLAG_SERVICE_VERSION, "flag-service.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.flag-service.v1")
        self.assertEqual(BUCKETS, 10_000)


class TestCreate(unittest.TestCase):
    def setUp(self):
        self.svc = FlagService()

    def test_create_shape(self):
        rec = self.svc.create("f1", seq=1, description="d", default_variation=False)
        self.assertIsInstance(rec, FlagRecord)
        self.assertEqual(rec.key, "f1")
        self.assertEqual(rec.description, "d")
        self.assertTrue(rec.enabled)
        self.assertEqual(rec.rollout_pct, 0.0)
        self.assertEqual(rec.rules, ())
        self.assertTrue(rec.digest.startswith("sha256:"))

    def test_create_duplicate(self):
        self.svc.create("f1", seq=1)
        with self.assertRaises(DuplicateFlagError):
            self.svc.create("f1", seq=2)

    def test_create_bad_key(self):
        with self.assertRaises(TypeError):
            self.svc.create(123, seq=1)
        with self.assertRaises(ValueError):
            self.svc.create("", seq=1)

    def test_create_bad_seq(self):
        with self.assertRaises(TypeError):
            self.svc.create("f", seq=True)
        with self.assertRaises(ValueError):
            self.svc.create("f", seq=-1)

    def test_create_default_variations(self):
        for dv in (True, 0, "blue", None):
            rec = self.svc.create(f"f-{dv!r}", seq=1, default_variation=dv)
            self.assertEqual(rec.default_variation, dv)
        with self.assertRaises(ValueError):
            self.svc.create("f-nan", seq=1, default_variation=float("nan"))

    def test_digest_determinism(self):
        a = FlagService()
        b = FlagService()
        a.create("f", seq=1, default_variation=1)
        b.create("f", seq=1, default_variation=1)
        self.assertEqual(a.flag("f").digest, b.flag("f").digest)
        a.create("g", seq=2)
        self.assertNotEqual(a.flag("f").digest, a.flag("g").digest)

    def test_keys_sorted(self):
        self.svc.create("z", seq=1)
        self.svc.create("a", seq=2)
        self.assertEqual(self.svc.keys(), ("a", "z"))

    def test_remove(self):
        self.svc.create("f", seq=1)
        self.svc.remove("f", seq=2)
        self.assertEqual(self.svc.keys(), ())
        with self.assertRaises(UnknownFlagError):
            self.svc.evaluate("f", "s", seq=3)
        with self.assertRaises(UnknownFlagError):
            self.svc.remove("f", seq=4)


class TestRules(unittest.TestCase):
    def setUp(self):
        self.svc = FlagService()
        self.svc.create("f", seq=1, default_variation=False)

    def test_add_rule_shape(self):
        r = self.svc.add_rule("f", "staff", {"email": "a@co"}, "staff-on", seq=2)
        self.assertIsInstance(r, RuleRecord)
        self.assertEqual(r.rule_id, "staff")
        self.assertEqual(dict(r.predicate), {"email": "a@co"})
        self.assertTrue(r.digest.startswith("sha256:"))

    def test_add_rule_duplicate(self):
        self.svc.add_rule("f", "r1", {"a": 1}, True, seq=2)
        with self.assertRaises(DuplicateRuleError):
            self.svc.add_rule("f", "r1", {"a": 2}, False, seq=3)

    def test_add_rule_bad_predicate(self):
        with self.assertRaises(TypeError):
            self.svc.add_rule("f", "r", "not-a-mapping", True, seq=2)
        with self.assertRaises(ValueError):
            self.svc.add_rule("f", "r", {}, True, seq=2)
        with self.assertRaises(TypeError):
            self.svc.add_rule("f", "r", {"a": object()}, True, seq=2)

    def test_add_rule_predicate_value_types(self):
        for v in (True, 3, 2.5, "x"):
            self.svc.add_rule("f", f"r-{v!r}", {"k": v}, True, seq=2)
        with self.assertRaises(TypeError):
            self.svc.add_rule("f", "r-list", {"k": [1, 2]}, True, seq=2)
        with self.assertRaises(TypeError):
            self.svc.add_rule("f", "r-none", {"k": None}, True, seq=2)

    def test_remove_rule(self):
        self.svc.add_rule("f", "r1", {"a": 1}, True, seq=2)
        self.svc.remove_rule("f", "r1", seq=3)
        self.assertEqual(self.svc.flag("f").rules, ())
        with self.assertRaises(UnknownRuleError):
            self.svc.remove_rule("f", "r1", seq=4)

    def test_add_rule_unknown_flag(self):
        with self.assertRaises(UnknownFlagError):
            self.svc.add_rule("nope", "r", {"a": 1}, True, seq=2)


class TestEvaluate(unittest.TestCase):
    def setUp(self):
        self.svc = FlagService()
        self.svc.create("f", seq=1, default_variation=False)

    def test_default_when_nothing_set(self):
        rep = self.svc.evaluate("f", "alice", seq=2)
        self.assertIsInstance(rep, EvaluationReport)
        self.assertEqual(rep.variation, False)
        self.assertEqual(rep.reason, "default")
        self.assertIsNone(rep.rule_id)
        self.assertIsNone(rep.bucket)
        self.assertTrue(rep.flag_digest.startswith("sha256:"))

    def test_rule_match(self):
        self.svc.add_rule("f", "staff", {"email": "a@co"}, "staff-on", seq=2)
        rep = self.svc.evaluate("f", "alice", seq=3, attributes={"email": "a@co"})
        self.assertEqual(rep.variation, "staff-on")
        self.assertEqual(rep.reason, "rule")
        self.assertEqual(rep.rule_id, "staff")

    def test_rule_no_match_falls_through(self):
        self.svc.add_rule("f", "staff", {"email": "a@co"}, "staff-on", seq=2)
        rep = self.svc.evaluate("f", "bob", seq=3, attributes={"email": "b@co"})
        self.assertEqual(rep.variation, False)
        self.assertEqual(rep.reason, "default")
        # missing attribute also no match
        rep = self.svc.evaluate("f", "bob", seq=4)
        self.assertEqual(rep.reason, "default")

    def test_rule_order_first_match_wins(self):
        self.svc.add_rule("f", "r1", {"tier": "gold"}, "gold", seq=2)
        self.svc.add_rule("f", "r2", {"tier": "gold"}, "gold2", seq=3)
        rep = self.svc.evaluate("f", "s", seq=4, attributes={"tier": "gold"})
        self.assertEqual(rep.rule_id, "r1")
        self.assertEqual(rep.variation, "gold")

    def test_rollout_full_on(self):
        self.svc.rollout("f", 100.0, seq=2)
        for subj in ("alice", "bob", "carol"):
            rep = self.svc.evaluate("f", subj, seq=3)
            self.assertEqual(rep.variation, "on", subj)
            self.assertEqual(rep.reason, "rollout")
            self.assertIsNotNone(rep.bucket)

    def test_rollout_zero(self):
        self.svc.rollout("f", 0.0, seq=2)
        rep = self.svc.evaluate("f", "alice", seq=3)
        self.assertEqual(rep.variation, False)
        self.assertEqual(rep.reason, "default")

    def test_rollout_deterministic(self):
        self.svc.rollout("f", 50.0, seq=2)
        svc2 = FlagService()
        svc2.create("f", seq=1, default_variation=False)
        svc2.rollout("f", 50.0, seq=2)
        for subj in ("alice", "bob", "carol", "dave", "erin"):
            r1 = self.svc.evaluate("f", subj, seq=3)
            r2 = svc2.evaluate("f", subj, seq=3)
            self.assertEqual(r1.variation, r2.variation, subj)
            self.assertEqual(r1.bucket, r2.bucket, subj)

    def test_rollout_roughly_fifty_percent(self):
        self.svc.rollout("f", 50.0, seq=2)
        ons = sum(
            1
            for i in range(400)
            if self.svc.evaluate("f", f"subject-{i}", seq=3).variation == "on"
        )
        self.assertGreater(ons, 120)
        self.assertLess(ons, 280)

    def test_rollout_bad_pct(self):
        with self.assertRaises(ValueError):
            self.svc.rollout("f", 101.0, seq=2)
        with self.assertRaises(ValueError):
            self.svc.rollout("f", -1.0, seq=2)
        with self.assertRaises(TypeError):
            self.svc.rollout("f", True, seq=2)
        with self.assertRaises(ValueError):
            self.svc.rollout("f", float("nan"), seq=2)
        with self.assertRaises(UnknownFlagError):
            self.svc.rollout("nope", 10.0, seq=2)

    def test_rollout_record(self):
        rec = self.svc.rollout("f", 25.0, seq=2)
        self.assertIsInstance(rec, RolloutRecord)
        self.assertEqual(rec.old_pct, 0.0)
        self.assertEqual(rec.new_pct, 25.0)
        self.assertEqual(self.svc.flag("f").rollout_pct, 25.0)

    def test_disabled_kill_switch(self):
        self.svc.add_rule("f", "staff", {"email": "a@co"}, "staff-on", seq=2)
        self.svc.rollout("f", 100.0, seq=3)
        self.svc.disable("f", seq=4)
        for attrs in (None, {"email": "a@co"}):
            rep = self.svc.evaluate("f", "s", seq=5, attributes=attrs)
            self.assertEqual(rep.variation, False)
            self.assertEqual(rep.reason, "disabled")
        self.svc.enable("f", seq=6)
        rep = self.svc.evaluate("f", "s", seq=7, attributes={"email": "a@co"})
        self.assertEqual(rep.reason, "rule")

    def test_evaluate_unknown_flag(self):
        with self.assertRaises(UnknownFlagError):
            self.svc.evaluate("nope", "s", seq=1)

    def test_evaluate_bad_inputs(self):
        with self.assertRaises(TypeError):
            self.svc.evaluate(1, "s", seq=1)
        with self.assertRaises(ValueError):
            self.svc.evaluate("f", "", seq=1)
        with self.assertRaises(TypeError):
            self.svc.evaluate("f", "s", seq=1, attributes=[("a", 1)])

    def test_flag_digest_changes_with_rollout(self):
        before = self.svc.flag("f").digest
        self.svc.rollout("f", 10.0, seq=2)
        self.assertNotEqual(before, self.svc.flag("f").digest)


class TestAuditAndMain(unittest.TestCase):
    def test_audit_shapes(self):
        for kind in ("created", "removed", "enabled", "disabled", "rule-added",
                     "rule-removed", "rolled-out", "rejected"):
            rec = flag_service_audit_event(kind, seq=1, flag_key="f")
            self.assertEqual(rec["schema"], "audit.ndjson/1")
            self.assertEqual(rec["kind"], f"flag-service.{kind}")
            self.assertEqual(rec["module"], "flag-service.v1")
        with self.assertRaises(FlagServiceError):
            flag_service_audit_event("bogus", seq=1)
        with self.assertRaises(ValueError):
            flag_service_audit_event("created", seq=-1)

    def test_flagrecord_as_dict(self):
        svc = FlagService()
        rec = svc.create("f", seq=1, default_variation="blue")
        d = rec.as_dict()
        self.assertEqual(d["key"], "f")
        self.assertEqual(d["default_variation"], "blue")
        self.assertEqual(d["version"], "flag-service.v1")
        self.assertEqual(d["schema"], "northstar.flag-service.v1")

    def test_stdlib_only(self):
        src = Path(__file__).resolve().parent.parent.joinpath("flag_service.py").read_text()
        tree = ast.parse(src)
        allowed = {
            "hashlib", "threading", "dataclasses", "typing", "__future__",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], allowed, a.name)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn(node.module.split(".")[0], allowed, node.module)

    def test_thread_safety(self):
        svc = FlagService()
        for i in range(10):
            svc.create(f"f{i}", seq=i)
        def worker(i):
            svc.evaluate(f"f{i % 10}", f"subject-{i}", seq=100 + i)
            svc.rollout(f"f{i % 10}", (i % 101) * 1.0, seq=200 + i)
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(40)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

    def test_main(self):
        main()


if __name__ == "__main__":
    unittest.main()
