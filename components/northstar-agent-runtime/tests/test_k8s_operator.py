"""Tests for the k8s_operator module."""

import threading
import unittest

from k8s_operator import (
    K8S_OPERATOR_VERSION,
    SCHEMA_PIN,
    DuplicateCRDError,
    DuplicateResourceError,
    K8sOperator,
    K8sOperatorError,
    UnknownCRDError,
    UnknownResourceError,
    k8s_operator_audit_event,
)


def _op():
    op = K8sOperator()
    op.register_crd("example.com", "v1", "Widget", {"type": "object"}, 0)
    return op


class TestPins(unittest.TestCase):
    def test_version_and_schema(self):
        self.assertEqual(K8S_OPERATOR_VERSION, "k8s-operator.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.k8s-operator.v1")
        rec = _op().register_crd("x.io", "v1", "Thing", {}, 1)
        self.assertEqual(rec.schema, SCHEMA_PIN)
        self.assertEqual(rec.record_version, K8S_OPERATOR_VERSION)


class TestCRDRegistry(unittest.TestCase):
    def test_register_happy_path(self):
        op = K8sOperator()
        rec = op.register_crd("example.com", "v1", "Widget", {"type": "object"}, 1)
        self.assertEqual(rec.crd_name, "widgets.example.com")
        self.assertTrue(rec.schema_digest.startswith("sha256:"))
        self.assertIn("example.com/v1/Widget", op.crds())

    def test_schema_digest_determinism(self):
        op = K8sOperator()
        a = op.register_crd("a.io", "v1", "Foo", {"x": 1}, 1)
        op2 = K8sOperator()
        b = op2.register_crd("a.io", "v1", "Foo", {"x": 1}, 1)
        self.assertEqual(a.schema_digest, b.schema_digest)

    def test_duplicate_crd(self):
        op = _op()
        with self.assertRaises(DuplicateCRDError):
            op.register_crd("example.com", "v1", "Widget", {}, 2)

    def test_bad_crd_inputs(self):
        op = K8sOperator()
        with self.assertRaises(K8sOperatorError):
            op.register_crd("", "v1", "Widget", {}, 1)
        with self.assertRaises(K8sOperatorError):
            op.register_crd("example.com", "", "Widget", {}, 1)
        with self.assertRaises(K8sOperatorError):
            op.register_crd("example.com", "v1", "widget", {}, 1)  # lowercase kind
        with self.assertRaises(K8sOperatorError):
            op.register_crd("example.com", "v1", "Widget", float("nan"), 1)
        with self.assertRaises(K8sOperatorError):
            op.register_crd("example.com", "v1", "Widget", {}, -1)  # bad seq
        with self.assertRaises(K8sOperatorError):
            op.register_crd("example.com", "v1", "Widget", {}, True)  # bool seq


class TestApply(unittest.TestCase):
    def test_apply_happy_path(self):
        op = _op()
        rec = op.apply("w1", "Widget", {"replicas": 2}, 1)
        self.assertEqual(rec.phase, "Pending")
        self.assertEqual(rec.generation, 1)
        self.assertTrue(rec.spec_digest.startswith("sha256:"))
        self.assertEqual(rec.audit_seq, 1)

    def test_apply_unknown_kind(self):
        op = _op()
        with self.assertRaises(UnknownCRDError):
            op.apply("w1", "Gadget", {}, 1)

    def test_apply_duplicate(self):
        op = _op()
        op.apply("w1", "Widget", {}, 1)
        with self.assertRaises(DuplicateResourceError):
            op.apply("w1", "Widget", {}, 2)

    def test_apply_bad_inputs(self):
        op = _op()
        with self.assertRaises(K8sOperatorError):
            op.apply("", "Widget", {}, 1)
        with self.assertRaises(K8sOperatorError):
            op.apply("Bad_Name", "Widget", {}, 1)
        with self.assertRaises(K8sOperatorError):
            op.apply("w1", "Widget", {"v": float("nan")}, 1)
        with self.assertRaises(K8sOperatorError):
            op.apply("w1", "Widget", {}, -1)

    def test_update_spec_bumps_generation(self):
        op = _op()
        op.apply("w1", "Widget", {"replicas": 2}, 1)
        op.report_observed("w1", {"replicas": 2}, 2)
        op.reconcile(3)
        self.assertTrue(op.status("w1").in_sync)
        rec = op.update_spec("w1", {"replicas": 3}, 4)
        self.assertEqual(rec.generation, 2)
        self.assertEqual(rec.phase, "Progressing")
        self.assertFalse(op.status("w1").in_sync)

    def test_update_spec_identical_is_noop(self):
        op = _op()
        op.apply("w1", "Widget", {"replicas": 2}, 1)
        rec = op.update_spec("w1", {"replicas": 2}, 2)
        self.assertEqual(rec.generation, 1)

    def test_update_spec_unknown_resource(self):
        op = _op()
        with self.assertRaises(UnknownResourceError):
            op.update_spec("nope", {}, 1)


class TestReconcile(unittest.TestCase):
    def test_create_then_converge(self):
        op = _op()
        op.apply("w1", "Widget", {"replicas": 2}, 1)
        report = op.reconcile(2)
        self.assertEqual(report.actions[0].action, "create")
        self.assertTrue(report.requeue)
        self.assertEqual(op.status("w1").phase, "Progressing")
        op.report_observed("w1", {"replicas": 2}, 3)
        report = op.reconcile(4)
        self.assertEqual(report.actions[0].action, "noop")
        st = op.status("w1")
        self.assertEqual(st.phase, "Ready")
        self.assertTrue(st.in_sync)
        self.assertEqual(st.observed_generation, st.generation)
        self.assertFalse(report.requeue)

    def test_drift_emits_update(self):
        op = _op()
        op.apply("w1", "Widget", {"replicas": 2}, 1)
        op.report_observed("w1", {"replicas": 9}, 2)  # host drifted
        report = op.reconcile(3)
        self.assertEqual(report.actions[0].action, "update")
        self.assertIn("differs", report.actions[0].reason)

    def test_level_triggered_repeated_passes(self):
        op = _op()
        op.apply("w1", "Widget", {"replicas": 2}, 1)
        op.reconcile(2)
        r2 = op.reconcile(3)
        # No observed yet: still create, pass counter moved on.
        self.assertEqual(r2.actions[0].action, "create")
        self.assertEqual(op.reconcile_passes(), 2)

    def test_report_digest_deterministic(self):
        op = _op()
        op.apply("w1", "Widget", {"replicas": 2}, 1)
        self.assertEqual(op.reconcile(2).digest, op.reconcile(3).digest)

    def test_reconcile_empty(self):
        op = _op()
        report = op.reconcile(1)
        self.assertEqual(report.actions, ())
        self.assertFalse(report.requeue)

    def test_reconcile_bad_seq(self):
        op = _op()
        with self.assertRaises(K8sOperatorError):
            op.reconcile(-1)
        with self.assertRaises(K8sOperatorError):
            op.reconcile(True)

    def test_delete_lifecycle(self):
        op = _op()
        op.apply("w1", "Widget", {"replicas": 2}, 1)
        op.report_observed("w1", {"replicas": 2}, 2)
        op.reconcile(3)
        rec = op.delete("w1", 4)
        self.assertEqual(rec.phase, "Terminating")
        report = op.reconcile(5)
        self.assertEqual(report.actions[0].action, "delete")
        # Still managed until the host confirms the object is gone.
        self.assertIn("w1", op.names())
        obs = op.report_observed("w1", None, 6)
        self.assertIsNone(obs.observed_digest)
        op.reconcile(7)
        self.assertNotIn("w1", op.names())
        with self.assertRaises(UnknownResourceError):
            op.status("w1")

    def test_delete_unknown(self):
        op = _op()
        with self.assertRaises(UnknownResourceError):
            op.delete("nope", 1)

    def test_observed_unknown_resource(self):
        op = _op()
        with self.assertRaises(UnknownResourceError):
            op.report_observed("nope", {}, 1)


class TestAudit(unittest.TestCase):
    def test_shapes(self):
        for kind in ("crd-registered", "applied", "observed",
                     "reconciled", "deleted", "rejected"):
            ev = k8s_operator_audit_event(kind, 1, "w1", {"k": "v"})
            self.assertEqual(ev["event"], "k8s-operator")
            self.assertEqual(ev["kind"], kind)
            self.assertEqual(ev["name"], "w1")
            self.assertEqual(ev["schema"], SCHEMA_PIN)

    def test_rejections(self):
        with self.assertRaises(K8sOperatorError):
            k8s_operator_audit_event("bogus", 1)
        with self.assertRaises(K8sOperatorError):
            k8s_operator_audit_event("applied", -1)
        with self.assertRaises(K8sOperatorError):
            k8s_operator_audit_event("applied", 1, "Bad Name")


class TestThreadSafety(unittest.TestCase):
    def test_concurrent_apply_reconcile(self):
        op = K8sOperator()
        op.register_crd("example.com", "v1", "Widget", {}, 0)
        errors = []

        def worker(i):
            try:
                op.apply(f"w{i}", "Widget", {"i": i}, i + 1)
                op.reconcile(100 + i)
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        self.assertEqual(len(op.names()), 8)


class TestMain(unittest.TestCase):
    def test_main(self):
        import k8s_operator

        k8s_operator.main()  # must not raise


if __name__ == "__main__":
    unittest.main()
