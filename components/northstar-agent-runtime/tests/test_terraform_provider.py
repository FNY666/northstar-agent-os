"""Tests for terraform_provider: declare/plan/apply/destroy bookkeeping."""

import unittest

from terraform_provider import (
    SCHEMA_PIN,
    TERRAFORM_PROVIDER_VERSION,
    ApplyResult,
    Change,
    DestroyResult,
    DuplicateDeclarationError,
    EmptyStateError,
    Plan,
    PlanReplayError,
    ResourceDeclaration,
    TerraformError,
    TerraformProvider,
    UnknownAddressError,
    terraform_provider_audit_event,
)


def fresh() -> TerraformProvider:
    return TerraformProvider()


class VersionPinTest(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(TERRAFORM_PROVIDER_VERSION, "terraform-provider.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.terraform-provider.v1")


class DeclareTest(unittest.TestCase):
    def test_declare_happy_path(self):
        p = fresh()
        decl = p.declare("aws_instance.web", "aws_instance", {"ami": "x"}, seq=0)
        self.assertIsInstance(decl, ResourceDeclaration)
        self.assertEqual(decl.address, "aws_instance.web")
        self.assertTrue(decl.digest.startswith("sha256:"))

    def test_declare_idempotent_same_config(self):
        p = fresh()
        a = p.declare("r.a", "t", {"x": 1}, seq=0)
        b = p.declare("r.a", "t", {"x": 1}, seq=5)
        self.assertEqual(a.digest, b.digest)

    def test_declare_conflict_refused(self):
        p = fresh()
        p.declare("r.a", "t", {"x": 1}, seq=0)
        with self.assertRaises(DuplicateDeclarationError):
            p.declare("r.a", "t", {"x": 2}, seq=1)

    def test_declare_bad_address(self):
        p = fresh()
        with self.assertRaises(TerraformError):
            p.declare("", "t", {}, seq=0)

    def test_declare_bad_seq(self):
        p = fresh()
        with self.assertRaises(TerraformError):
            p.declare("r.a", "t", {}, seq=-1)

    def test_undeclare_unknown(self):
        p = fresh()
        with self.assertRaises(UnknownAddressError):
            p.undeclare("r.ghost", seq=0)


class PlanTest(unittest.TestCase):
    def test_plan_create(self):
        p = fresh()
        p.declare("r.a", "t", {"ami": "1"}, seq=0)
        plan = p.plan(seq=1)
        self.assertIsInstance(plan, Plan)
        self.assertEqual(len(plan.changes), 1)
        self.assertEqual(plan.changes[0].action, "create")
        self.assertIsNone(plan.changes[0].old_attrs)

    def test_plan_empty_when_converged(self):
        p = fresh()
        p.declare("r.a", "t", {"ami": "1"}, seq=0)
        p.apply(p.plan(seq=1), seq=2)
        plan = p.plan(seq=3)
        self.assertEqual(len(plan.changes), 0)

    def test_plan_drift_is_update(self):
        p = fresh()
        p.declare("r.a", "t", {"ami": "1"}, seq=0)
        p.apply(p.plan(seq=1), seq=2)
        p.refresh("r.a", {"ami": "2"}, seq=3)
        plan = p.plan(seq=4)
        self.assertEqual(plan.changes[0].action, "update")

    def test_plan_unmanaged_state_is_delete(self):
        p = fresh()
        p.refresh("r.rogue", {"x": 1}, seq=0)
        plan = p.plan(seq=1)
        self.assertEqual(plan.changes[0].action, "delete")
        self.assertIsNone(plan.changes[0].new_attrs)

    def test_plan_is_pure(self):
        p = fresh()
        p.declare("r.a", "t", {"x": 1}, seq=0)
        before = p.observed()
        p.plan(seq=1)
        self.assertEqual(p.observed(), before)

    def test_plan_sorted_by_address(self):
        p = fresh()
        p.declare("r.z", "t", {"x": 1}, seq=0)
        p.declare("r.a", "t", {"x": 1}, seq=0)
        plan = p.plan(seq=1)
        addrs = [c.address for c in plan.changes]
        self.assertEqual(addrs, sorted(addrs))


class ApplyTest(unittest.TestCase):
    def test_apply_create_converges_state(self):
        p = fresh()
        p.declare("r.a", "t", {"x": 1}, seq=0)
        result = p.apply(p.plan(seq=1), seq=2)
        self.assertIsInstance(result, ApplyResult)
        self.assertEqual(result.applied, ("r.a",))
        self.assertEqual(p.observed(), ("r.a",))

    def test_apply_single_use(self):
        p = fresh()
        p.declare("r.a", "t", {"x": 1}, seq=0)
        plan = p.plan(seq=1)
        p.apply(plan, seq=2)
        with self.assertRaises(PlanReplayError):
            p.apply(plan, seq=3)

    def test_apply_uses_applier_report(self):
        p = fresh()
        p.declare("r.a", "t", {"x": 1}, seq=0)
        seen = []

        def applier(address, action, attrs):
            seen.append((address, action))
            return {"x": 1, "cloud_id": "i-123"}

        p.apply(p.plan(seq=1), seq=2, applier=applier)
        self.assertEqual(seen, [("r.a", "create")])

    def test_apply_empty_plan(self):
        p = fresh()
        plan = p.plan(seq=0)
        result = p.apply(plan, seq=1)
        self.assertEqual(result.applied, ())

    def test_apply_bad_plan_type(self):
        p = fresh()
        with self.assertRaises(TerraformError):
            p.apply("not-a-plan", seq=0)


class DestroyTest(unittest.TestCase):
    def test_destroy_removes_state(self):
        p = fresh()
        p.declare("r.a", "t", {"x": 1}, seq=0)
        p.declare("r.b", "t", {"x": 2}, seq=0)
        p.apply(p.plan(seq=1), seq=2)
        result = p.destroy(seq=3)
        self.assertIsInstance(result, DestroyResult)
        self.assertEqual(result.destroyed, ("r.a", "r.b"))
        self.assertEqual(p.observed(), ())

    def test_destroy_empty_refused(self):
        p = fresh()
        with self.assertRaises(EmptyStateError):
            p.destroy(seq=0)

    def test_destroy_calls_applier(self):
        p = fresh()
        p.declare("r.a", "t", {"x": 1}, seq=0)
        p.apply(p.plan(seq=1), seq=2)
        calls = []
        p.destroy(seq=3, applier=lambda a, ac, at: calls.append((a, ac)))
        self.assertEqual(calls, [("r.a", "delete")])


class AuditTest(unittest.TestCase):
    def test_audit_shape(self):
        rec = terraform_provider_audit_event("planned", seq=7)
        self.assertEqual(rec["module"], "terraform_provider")
        self.assertEqual(rec["module_version"], "terraform-provider.v1")
        self.assertEqual(rec["schema"], "northstar.terraform-provider.v1")
        self.assertEqual(rec["kind"], "planned")

    def test_audit_unknown_kind(self):
        with self.assertRaises(TerraformError):
            terraform_provider_audit_event("bogus", seq=0)


class AttrValidationTest(unittest.TestCase):
    def test_nan_refused(self):
        p = fresh()
        with self.assertRaises(TerraformError):
            p.declare("r.a", "t", {"x": float("nan")}, seq=0)

    def test_bool_vs_int_distinct(self):
        p = fresh()
        p.declare("r.a", "t", {"x": True}, seq=0)
        plan = p.plan(seq=1)
        p.apply(plan, seq=2)
        p.refresh("r.a", {"x": 1}, seq=3)
        plan2 = p.plan(seq=4)
        self.assertEqual(plan2.changes[0].action, "update")

    def test_deep_nesting_refused(self):
        p = fresh()
        deep: object = {"v": 1}
        for _ in range(20):
            deep = {"v": deep}
        with self.assertRaises(TerraformError):
            p.declare("r.a", "t", deep, seq=0)

    def test_main_self_check(self):
        import terraform_provider as m

        m.main()


if __name__ == "__main__":
    unittest.main()
