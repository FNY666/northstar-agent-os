"""Tests for federated_learning: FedAvg aggregation state machine."""

import math
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from federated_learning import (
    SCHEMA_PIN,
    FEDERATED_LEARNING_VERSION,
    AggregationError,
    AggregationResult,
    ClientUpdate,
    FederatedLearning,
    FederatedLearningError,
    GlobalModel,
    federated_learning_audit_event,
)


def _update(client_id="a", round=1, num_examples=1, params=(1.0, 2.0)):
    return ClientUpdate(client_id, round, num_examples, params)


class TestVersionPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(FEDERATED_LEARNING_VERSION, "federated-learning.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.federated-learning.v1")


class TestClientUpdateValidation(unittest.TestCase):
    def test_happy_path(self):
        u = _update()
        self.assertEqual(u.client_id, "a")
        self.assertEqual(u.round, 1)
        self.assertEqual(u.num_examples, 1)
        self.assertEqual(u.params, (1.0, 2.0))
        self.assertTrue(u.digest.startswith("sha256:"))
        self.assertEqual(len(u.digest), 71)

    def test_digest_deterministic(self):
        self.assertEqual(_update().digest, _update().digest)

    def test_digest_content_sensitive(self):
        self.assertNotEqual(_update(params=(1.0, 2.0)).digest,
                            _update(params=(1.0, 3.0)).digest)
        self.assertNotEqual(_update(client_id="a").digest,
                            _update(client_id="b").digest)

    def test_frozen(self):
        u = _update()
        with self.assertRaises(Exception):
            u.num_examples = 5  # type: ignore[attr-defined]

    def test_empty_client_id(self):
        with self.assertRaises(ValueError):
            _update(client_id="")

    def test_non_str_client_id(self):
        with self.assertRaises(TypeError):
            _update(client_id=7)

    def test_negative_round(self):
        with self.assertRaises(ValueError):
            _update(round=-1)

    def test_bool_round(self):
        with self.assertRaises(TypeError):
            _update(round=True)

    def test_zero_num_examples(self):
        with self.assertRaises(ValueError):
            _update(num_examples=0)

    def test_bool_num_examples(self):
        with self.assertRaises(TypeError):
            _update(num_examples=True)

    def test_empty_params(self):
        with self.assertRaises(ValueError):
            _update(params=())

    def test_str_params_rejected(self):
        with self.assertRaises(TypeError):
            _update(params="1.0, 2.0")

    def test_nan_inf_params_rejected(self):
        for bad in ((float("nan"),), (float("inf"),), (float("-inf"),)):
            with self.assertRaises(ValueError):
                _update(params=bad)

    def test_bool_param_rejected(self):
        with self.assertRaises(TypeError):
            _update(params=(True, 1.0))

    def test_huge_int_param_rejected(self):
        with self.assertRaises(ValueError):
            _update(params=(2 ** 54,))

    def test_as_dict_shape(self):
        d = _update().as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertEqual(d["client_id"], "a")
        self.assertEqual(d["params"], [1.0, 2.0])
        self.assertEqual(d["digest"], _update().digest)


class TestGlobalModel(unittest.TestCase):
    def test_round_numbering(self):
        fl = FederatedLearning()
        m0 = fl.broadcast([0.0, 0.0], 0)
        m1 = fl.broadcast([1.0, 1.0], 1)
        self.assertEqual(m0.round, 0)
        self.assertEqual(m1.round, 1)
        self.assertEqual(fl.next_round(), 2)
        self.assertIs(fl.current_model(), m1)

    def test_broadcast_validation(self):
        fl = FederatedLearning()
        for bad_params in ((), "x", (float("nan"),), (True,), (2 ** 54,)):
            with self.assertRaises((ValueError, TypeError)):
                fl.broadcast(bad_params, 0)

    def test_bad_seq(self):
        fl = FederatedLearning()
        with self.assertRaises(TypeError):
            fl.broadcast([1.0], True)
        with self.assertRaises(ValueError):
            fl.broadcast([1.0], -1)


class TestAggregate(unittest.TestCase):
    def test_fedavg_weighted_math(self):
        fl = FederatedLearning()
        a = _update("a", 1, 1, (1.0, 2.0))
        b = _update("b", 1, 3, (3.0, 4.0))
        r = fl.aggregate([a, b], 0)
        self.assertEqual(r.round, 1)
        self.assertEqual(r.clients, ("a", "b"))
        self.assertEqual(r.total_examples, 4)
        self.assertEqual(r.weights, (0.25, 0.75))
        self.assertEqual(r.params, (2.5, 3.5))

    def test_equal_weights_is_mean(self):
        fl = FederatedLearning()
        a = _update("a", 0, 1, (0.0, 10.0))
        b = _update("b", 0, 1, (10.0, 0.0))
        r = fl.aggregate([b, a], 0)  # input order irrelevant
        self.assertEqual(r.clients, ("a", "b"))
        self.assertEqual(r.params, (5.0, 5.0))

    def test_single_client_identity(self):
        fl = FederatedLearning()
        a = _update("solo", 2, 7, (3.5, -1.25))
        r = fl.aggregate([a], 0)
        self.assertEqual(r.clients, ("solo",))
        self.assertEqual(r.total_examples, 7)
        self.assertEqual(r.weights, (1.0,))
        self.assertEqual(r.params, (3.5, -1.25))

    def test_empty_set_refused(self):
        fl = FederatedLearning()
        with self.assertRaises(AggregationError):
            fl.aggregate([], 0)

    def test_duplicate_client_refused(self):
        fl = FederatedLearning()
        a = _update("a")
        with self.assertRaises(AggregationError):
            fl.aggregate([a, a], 0)

    def test_mixed_round_refused(self):
        fl = FederatedLearning()
        a = _update("a", round=1)
        b = _update("b", round=2)
        with self.assertRaises(AggregationError):
            fl.aggregate([a, b], 0)

    def test_dimension_mismatch_refused(self):
        fl = FederatedLearning()
        a = _update("a", params=(1.0, 2.0))
        b = _update("b", params=(1.0, 2.0, 3.0))
        with self.assertRaises(AggregationError):
            fl.aggregate([a, b], 0)

    def test_non_update_rejected(self):
        fl = FederatedLearning()
        with self.assertRaises(TypeError):
            fl.aggregate(["not-an-update"], 0)
        with self.assertRaises(TypeError):
            fl.aggregate("junk", 0)

    def test_aggregation_result_digest(self):
        fl = FederatedLearning()
        r = fl.aggregate([_update("a"), _update("b")], 0)
        self.assertTrue(r.digest.startswith("sha256:"))
        d = r.as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertEqual(d["digest"], r.digest)


class TestRound(unittest.TestCase):
    def test_round_advances_model(self):
        fl = FederatedLearning()
        fl.broadcast([0.0, 0.0], 0)
        m = fl.round([_update("a", 1, 1, (2.0, 2.0)),
                      _update("b", 1, 1, (4.0, 4.0))], 1)
        self.assertEqual(m.round, 1)
        self.assertEqual(m.params, (3.0, 3.0))
        self.assertIs(fl.current_model(), m)

    def test_round_refuses_bad_batch(self):
        fl = FederatedLearning()
        with self.assertRaises(AggregationError):
            fl.round([], 0)
        self.assertIsNone(fl.current_model())


class TestAuditEvents(unittest.TestCase):
    def test_event_shapes(self):
        fl = FederatedLearning()
        m = fl.broadcast([1.0], 0)
        ev = federated_learning_audit_event("model-broadcast", 1,
                                            global_model=m)
        self.assertEqual(ev["schema"], "audit.ndjson/1")
        self.assertEqual(ev["kind"], "model-broadcast")
        self.assertEqual(ev["model_round"], 0)
        self.assertEqual(ev["model_digest"], m.digest)

        r = fl.aggregate([_update("a")], 2)
        ev2 = federated_learning_audit_event("updates-aggregated", 3,
                                             result=r)
        self.assertEqual(ev2["agg_round"], 1)
        self.assertEqual(ev2["agg_clients"], ["a"])
        self.assertEqual(ev2["agg_digest"], r.digest)

    def test_bad_kind_and_seq(self):
        with self.assertRaises(ValueError):
            federated_learning_audit_event("bogus", 0)
        with self.assertRaises(TypeError):
            federated_learning_audit_event("rejected", True)
        with self.assertRaises(ValueError):
            federated_learning_audit_event("rejected", -1)

    def test_bad_record_types(self):
        with self.assertRaises(TypeError):
            federated_learning_audit_event("model-broadcast", 0,
                                           global_model="x")
        with self.assertRaises(TypeError):
            federated_learning_audit_event("updates-aggregated", 0,
                                           result="x")


class TestMain(unittest.TestCase):
    def test_main_self_check(self):
        import federated_learning as mod
        mod.main()


if __name__ == "__main__":
    unittest.main()
