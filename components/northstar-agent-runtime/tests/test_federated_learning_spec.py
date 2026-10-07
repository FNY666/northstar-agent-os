"""Tests for the federated_learning evaluate() spec API (additive)."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from federated_learning import (
    SCHEMA_PIN,
    FEDERATED_LEARNING_VERSION,
    AggregationError,
    ClientMetric,
    EvaluationReport,
    FederatedLearning,
    federated_learning_audit_event,
)


def _metric(client_id="a", round=1, num_examples=1,
            metrics=None):
    if metrics is None:
        metrics = {"accuracy": 1.0}
    return ClientMetric(client_id, round, num_examples, metrics)


class TestSpecApiPresence(unittest.TestCase):
    def test_evaluate_exists(self):
        self.assertTrue(callable(FederatedLearning.evaluate))

    def test_version_pins(self):
        self.assertEqual(FEDERATED_LEARNING_VERSION, "federated-learning.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.federated-learning.v1")


class TestClientMetric(unittest.TestCase):
    def test_roundtrip(self):
        m = _metric("a", 1, 4, {"accuracy": 0.9, "loss": 0.2})
        self.assertEqual(m.client_id, "a")
        self.assertEqual(m.round, 1)
        self.assertEqual(m.num_examples, 4)
        self.assertEqual(m.metrics, (("accuracy", 0.9), ("loss", 0.2)))
        self.assertEqual(m.metric_names, ("accuracy", "loss"))
        self.assertTrue(m.digest.startswith("sha256:"))
        self.assertEqual(m.as_dict()["schema"], SCHEMA_PIN)

    def test_metric_names_sorted(self):
        m = _metric(metrics={"loss": 0.1, "accuracy": 0.9, "f1": 0.8})
        self.assertEqual(m.metric_names, ("accuracy", "f1", "loss"))

    def test_digest_deterministic(self):
        self.assertEqual(_metric().digest, _metric().digest)

    def test_bad_inputs(self):
        for bad in ((), [], "x", {"accuracy": 1.0}):
            if isinstance(bad, dict):
                continue
            with self.assertRaises(TypeError):
                ClientMetric("a", 1, 1, bad)
        with self.assertRaises(ValueError):
            ClientMetric("a", 1, 1, {})
        with self.assertRaises(ValueError):
            ClientMetric("", 1, 1, {"accuracy": 1.0})
        with self.assertRaises(ValueError):
            ClientMetric("a", 1, 0, {"accuracy": 1.0})
        for bad_value in (True, float("nan"), float("inf"), 2 ** 54, "high"):
            with self.assertRaises((TypeError, ValueError)):
                ClientMetric("a", 1, 1, {"accuracy": bad_value})


class TestEvaluate(unittest.TestCase):
    def test_weighted_math(self):
        fl = FederatedLearning()
        r = fl.evaluate([_metric("a", 1, 1, {"accuracy": 0.5}),
                         _metric("b", 1, 3, {"accuracy": 1.0})], 0)
        self.assertIsInstance(r, EvaluationReport)
        self.assertEqual(r.round, 1)
        self.assertEqual(r.clients, ("a", "b"))
        self.assertEqual(r.total_examples, 4)
        self.assertEqual(r.metric_names, ("accuracy",))
        self.assertEqual(r.weighted_metrics, (0.875,))
        self.assertEqual(r.metric("accuracy"), 0.875)

    def test_multi_metric(self):
        fl = FederatedLearning()
        r = fl.evaluate([_metric("a", 0, 1, {"acc": 0.0, "loss": 10.0}),
                         _metric("b", 0, 1, {"acc": 1.0, "loss": 0.0})], 0)
        self.assertEqual(r.metric_names, ("acc", "loss"))
        self.assertEqual(r.weighted_metrics, (0.5, 5.0))

    def test_model_round_pinned(self):
        fl = FederatedLearning()
        self.assertIsNone(fl.evaluate([_metric()], 0).model_round)
        fl.broadcast([1.0], 1)
        r = fl.evaluate([_metric()], 2)
        self.assertEqual(r.model_round, 0)
        self.assertEqual(fl.next_round(), 1)  # evaluate advances nothing

    def test_unknown_metric_keyerror(self):
        fl = FederatedLearning()
        r = fl.evaluate([_metric()], 0)
        with self.assertRaises(KeyError):
            r.metric("nope")

    def test_refusals(self):
        fl = FederatedLearning()
        with self.assertRaises(AggregationError):
            fl.evaluate([], 0)
        a = _metric("a")
        with self.assertRaises(AggregationError):
            fl.evaluate([a, a], 0)
        b = _metric("b", round=2)
        with self.assertRaises(AggregationError):
            fl.evaluate([a, b], 0)
        c = _metric("c", metrics={"accuracy": 1.0, "loss": 0.0})
        with self.assertRaises(AggregationError):
            fl.evaluate([a, c], 0)
        with self.assertRaises(TypeError):
            fl.evaluate(["junk"], 0)

    def test_bad_seq(self):
        fl = FederatedLearning()
        with self.assertRaises(TypeError):
            fl.evaluate([_metric()], True)
        with self.assertRaises(ValueError):
            fl.evaluate([_metric()], -1)

    def test_report_digest_and_dict(self):
        fl = FederatedLearning()
        r = fl.evaluate([_metric("a"), _metric("b")], 0)
        self.assertTrue(r.digest.startswith("sha256:"))
        d = r.as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertEqual(d["digest"], r.digest)
        self.assertIsNone(d["model_round"])
        r2 = fl.evaluate([_metric("b"), _metric("a")], 1)
        self.assertEqual(r.digest, r2.digest)  # input order irrelevant

    def test_audit_evaluation_recorded(self):
        fl = FederatedLearning()
        r = fl.evaluate([_metric("a", 1, 2, {"accuracy": 0.75})], 0)
        ev = federated_learning_audit_event("evaluation-recorded", 1,
                                            evaluation=r)
        self.assertEqual(ev["schema"], "audit.ndjson/1")
        self.assertEqual(ev["kind"], "evaluation-recorded")
        self.assertEqual(ev["eval_round"], 1)
        self.assertEqual(ev["eval_clients"], ["a"])
        self.assertEqual(ev["eval_metrics"], {"accuracy": 0.75})
        self.assertEqual(ev["eval_digest"], r.digest)
        with self.assertRaises(TypeError):
            federated_learning_audit_event("evaluation-recorded", 2,
                                           evaluation="x")


class TestExistingBehaviorUntouched(unittest.TestCase):
    def test_aggregate_still_works(self):
        from federated_learning import ClientUpdate
        fl = FederatedLearning()
        r = fl.aggregate([ClientUpdate("a", 1, 1, [1.0]),
                          ClientUpdate("b", 1, 1, [3.0])], 0)
        self.assertEqual(r.params, (2.0,))


if __name__ == "__main__":
    unittest.main()
