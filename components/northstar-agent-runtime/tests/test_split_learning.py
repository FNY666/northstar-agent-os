"""Tests for split_learning.py (SplitNN interface, simulated)."""

import unittest

from split_learning import (
    BackwardPass,
    ForwardPass,
    SCHEMA_PIN,
    SmashedData,
    SPLIT_LEARNING_VERSION,
    SplitLearning,
    SplitLearningError,
    split_learning_audit_event,
)


def _net(cut=2):
    return SplitLearning(n_layers=4, dims=[4, 8, 8, 4, 2], cut=cut)


class VersionPinTests(unittest.TestCase):
    def test_version_and_schema(self):
        self.assertEqual(SPLIT_LEARNING_VERSION, "split-learning.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.split-learning.v1")


class ConstructorTests(unittest.TestCase):
    def test_cut_bounds(self):
        self.assertEqual(_net(cut=1).cut_layer, 1)
        self.assertEqual(_net(cut=3).cut_layer, 3)
        with self.assertRaises(SplitLearningError):
            _net(cut=0)
        with self.assertRaises(SplitLearningError):
            _net(cut=4)

    def test_bad_n_layers(self):
        with self.assertRaises(SplitLearningError):
            SplitLearning(n_layers=1, dims=[2, 2], cut=1)

    def test_dims_must_match(self):
        with self.assertRaises(SplitLearningError):
            SplitLearning(n_layers=4, dims=[4, 8], cut=2)

    def test_dim_guardrail(self):
        with self.assertRaises((TypeError, ValueError)):
            SplitLearning(n_layers=2, dims=[True, 2, 2], cut=1)
        with self.assertRaises(ValueError):
            SplitLearning(n_layers=2, dims=[0, 2, 2], cut=1)

    def test_seed_must_be_bytes(self):
        with self.assertRaises(TypeError):
            SplitLearning(n_layers=2, dims=[2, 2, 2], cut=1, seed="x")

    def test_layer_counts(self):
        sl = _net(cut=2)
        self.assertEqual(sl.client_layer_count(), 2)
        self.assertEqual(sl.server_layer_count(), 2)
        self.assertEqual(sl.n_layers, 4)


class ForwardTests(unittest.TestCase):
    def test_forward_shape(self):
        fwd = _net().forward([0.5, -0.5, 0.25, 1.0], seq=1)
        self.assertIsInstance(fwd, ForwardPass)
        self.assertEqual(len(fwd.output), 2)
        self.assertTrue(fwd.output_pin.startswith("sha256:"))
        self.assertEqual(fwd.version, SPLIT_LEARNING_VERSION)

    def test_forward_deterministic(self):
        sl = _net()
        a = sl.forward([1.0, 2.0, 3.0, 4.0], seq=1)
        b = sl.forward([1.0, 2.0, 3.0, 4.0], seq=2)
        self.assertEqual(a.output, b.output)
        self.assertEqual(a.smashed_pin, b.smashed_pin)

    def test_input_dim_mismatch(self):
        with self.assertRaises(ValueError):
            _net().forward([1.0, 2.0], seq=1)

    def test_non_finite_rejected(self):
        with self.assertRaises(ValueError):
            _net().forward([float("nan"), 0, 0, 0], seq=1)
        with self.assertRaises(ValueError):
            _net().forward([float("inf"), 0, 0, 0], seq=1)

    def test_bool_input_rejected(self):
        with self.assertRaises(TypeError):
            _net().forward([True, 0, 0, 0], seq=1)

    def test_bool_seq_rejected(self):
        with self.assertRaises(TypeError):
            _net().forward([0, 0, 0, 0], seq=True)

    def test_smashed_data_matches(self):
        sl = _net()
        fwd = sl.forward([0.1, 0.2, 0.3, 0.4], seq=1)
        smash = sl.smashed_data(seq=2)
        self.assertIsInstance(smash, SmashedData)
        self.assertEqual(smash.activation_pin, fwd.smashed_pin)
        self.assertEqual(len(smash.activation), 8)

    def test_smashed_before_forward(self):
        with self.assertRaises(SplitLearningError):
            _net().smashed_data(seq=1)


class BackwardTests(unittest.TestCase):
    def test_backward_shape(self):
        sl = _net()
        sl.forward([0.1, 0.2, 0.3, 0.4], seq=1)
        bwd = sl.backward([1.0, -1.0], seq=2)
        self.assertIsInstance(bwd, BackwardPass)
        self.assertEqual(bwd.cut, 2)
        self.assertEqual(len(bwd.cut_gradient), 8)
        self.assertTrue(bwd.cut_gradient_pin.startswith("sha256:"))

    def test_backward_deterministic(self):
        sl = _net()
        sl.forward([0.1, 0.2, 0.3, 0.4], seq=1)
        a = sl.backward([1.0, 1.0], seq=2)
        b = sl.backward([1.0, 1.0], seq=3)
        self.assertEqual(a.cut_gradient, b.cut_gradient)

    def test_backward_before_forward(self):
        with self.assertRaises(SplitLearningError):
            _net().backward([1.0, 1.0], seq=1)

    def test_loss_grad_dim_mismatch(self):
        sl = _net()
        sl.forward([0.1, 0.2, 0.3, 0.4], seq=1)
        with self.assertRaises(ValueError):
            sl.backward([1.0], seq=2)

    def test_client_gradient_finish(self):
        sl = _net()
        sl.forward([0.1, 0.2, 0.3, 0.4], seq=1)
        bwd = sl.backward([1.0, -1.0], seq=2)
        pin = sl.apply_client_gradients(bwd, seq=3)
        self.assertTrue(pin.startswith("sha256:"))

    def test_wrong_cut_refused(self):
        sl = _net(cut=2)
        sl.forward([0.1, 0.2, 0.3, 0.4], seq=1)
        other = _net(cut=1)
        other.forward([0.1, 0.2, 0.3, 0.4], seq=1)
        bwd = other.backward([1.0, 1.0], seq=2)
        with self.assertRaises(SplitLearningError):
            sl.apply_client_gradients(bwd, seq=3)

    def test_stale_gradient_refused(self):
        sl = _net()
        sl.forward([0.1, 0.2, 0.3, 0.4], seq=5)
        bwd = BackwardPass(
            version=SPLIT_LEARNING_VERSION,
            schema=SCHEMA_PIN,
            cut=2,
            cut_gradient=tuple([0.0] * 8),
            cut_gradient_pin="sha256:x",
            loss_gradient_pin="sha256:y",
            seq=1,
        )
        with self.assertRaises(SplitLearningError):
            sl.apply_client_gradients(bwd, seq=6)

    def test_bad_gradient_type(self):
        sl = _net()
        sl.forward([0.1, 0.2, 0.3, 0.4], seq=1)
        with self.assertRaises(TypeError):
            sl.apply_client_gradients("nope", seq=2)


class CutMoveTests(unittest.TestCase):
    def test_move_cut(self):
        sl = _net(cut=2)
        sl.forward([0.1, 0.2, 0.3, 0.4], seq=1)
        sl.move_cut(3, seq=2)
        self.assertEqual(sl.cut_layer, 3)
        self.assertEqual(sl.client_layer_count(), 3)
        self.assertEqual(sl.server_layer_count(), 1)

    def test_move_cut_clears_cache(self):
        sl = _net(cut=2)
        sl.forward([0.1, 0.2, 0.3, 0.4], seq=1)
        sl.move_cut(1, seq=2)
        with self.assertRaises(SplitLearningError):
            sl.smashed_data(seq=3)

    def test_move_cut_bounds(self):
        sl = _net()
        with self.assertRaises(SplitLearningError):
            sl.move_cut(0, seq=1)
        with self.assertRaises(SplitLearningError):
            sl.move_cut(4, seq=1)
        with self.assertRaises(TypeError):
            sl.move_cut("2", seq=1)


class RecordTests(unittest.TestCase):
    def test_records_frozen(self):
        sl = _net()
        fwd = sl.forward([0.1, 0.2, 0.3, 0.4], seq=1)
        with self.assertRaises(Exception):
            fwd.seq = 99  # type: ignore

    def test_weights_digest(self):
        d = _net().weights_digest()
        self.assertTrue(d.startswith("sha256:"))
        self.assertEqual(d, _net().weights_digest())

    def test_as_dict_shapes(self):
        sl = _net()
        fwd = sl.forward([0.1, 0.2, 0.3, 0.4], seq=1)
        d = fwd.as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertEqual(d["cut"], 2)
        smash = sl.smashed_data(seq=2)
        self.assertEqual(smash.as_dict()["cut"], 2)
        bwd = sl.backward([1.0, 1.0], seq=3)
        self.assertIn("cut_gradient", bwd.as_dict())


class AuditEventTests(unittest.TestCase):
    def test_event_shape(self):
        ev = split_learning_audit_event("forwarded", 7, "sha256:abc")
        self.assertEqual(ev["format"], "audit.ndjson/1")
        self.assertEqual(ev["module"], SPLIT_LEARNING_VERSION)
        self.assertEqual(ev["kind"], "split-learning-forwarded")
        self.assertEqual(ev["smashed_pin"], "sha256:abc")

    def test_bad_kind(self):
        with self.assertRaises(ValueError):
            split_learning_audit_event("nope", 1)

    def test_bad_seq(self):
        with self.assertRaises(TypeError):
            split_learning_audit_event("forwarded", True)
        with self.assertRaises(ValueError):
            split_learning_audit_event("forwarded", -1)


class MainSelfCheck(unittest.TestCase):
    def test_main(self):
        import split_learning as m

        m.main()


if __name__ == "__main__":
    unittest.main()
