"""Tests for secure_inference: private inference interface."""
import math
import unittest
from dataclasses import FrozenInstanceError

from secure_inference import (
    SCHEMA_PIN,
    SECURE_INFERENCE_VERSION,
    ModelCommitment,
    Prediction,
    SealedInput,
    SecureInference,
    SecureInferenceError,
    SealedInputError,
    StaleModelError,
    UnknownModelError,
    secure_inference_audit_event,
)

_SECRET = b"northstar-test-session-secret-16"


def _server() -> SecureInference:
    si = SecureInference(_SECRET)
    si.register_model("logreg", "logistic-regression.v1", (0.5, -0.25, 0.1), 0)
    return si


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(SECURE_INFERENCE_VERSION, "secure-inference.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.secure-inference.v1")


class TestRegistration(unittest.TestCase):
    def test_register_logistic(self):
        si = SecureInference(_SECRET)
        c = si.register_model("m1", "logistic-regression.v1", (1.0, 0.0), 3)
        self.assertEqual(c.input_dim, 1)
        self.assertEqual(c.n_classes, 2)
        self.assertEqual(c.registered_seq, 3)
        self.assertTrue(c.params_digest.startswith("sha256:"))

    def test_register_mlp(self):
        si = SecureInference(_SECRET)
        weights = (2.0, 2.0, 1.0, -1.0, 0.5, -0.5, 1.0, 0.0, 0.0, 1.0, 0.1, -0.1)
        c = si.register_model("mlp", "tiny-mlp.v1", weights, 0)
        self.assertEqual(c.input_dim, 1)
        self.assertEqual(c.n_classes, 2)

    def test_digest_deterministic(self):
        a = _server()
        b = _server()
        self.assertEqual(
            a.model_commitment("logreg").params_digest,
            b.model_commitment("logreg").params_digest,
        )

    def test_digest_changes_with_weights(self):
        a = _server()
        si2 = SecureInference(_SECRET)
        si2.register_model("logreg", "logistic-regression.v1", (0.5, -0.25, 0.2), 0)
        self.assertNotEqual(
            a.model_commitment("logreg").params_digest,
            si2.model_commitment("logreg").params_digest,
        )

    def test_duplicate_model_refused(self):
        si = _server()
        with self.assertRaises(SecureInferenceError):
            si.register_model("logreg", "logistic-regression.v1", (1.0, 0.0), 1)

    def test_unknown_architecture_refused(self):
        si = SecureInference(_SECRET)
        with self.assertRaises(SecureInferenceError):
            si.register_model("x", "transformer.v9", (1.0, 0.0), 0)

    def test_nan_weight_refused(self):
        si = SecureInference(_SECRET)
        with self.assertRaises(SecureInferenceError):
            si.register_model("x", "logistic-regression.v1", (float("nan"), 0.0), 0)

    def test_inf_weight_refused(self):
        si = SecureInference(_SECRET)
        with self.assertRaises(SecureInferenceError):
            si.register_model("x", "logistic-regression.v1", (float("inf"), 0.0), 0)

    def test_bool_weight_refused(self):
        si = SecureInference(_SECRET)
        with self.assertRaises(SecureInferenceError):
            si.register_model("x", "logistic-regression.v1", (True, 0.0), 0)

    def test_wrong_shape_refused(self):
        si = SecureInference(_SECRET)
        with self.assertRaises(SecureInferenceError):
            si.register_model("x", "logistic-regression.v1", (1.0,), 0)

    def test_empty_id_refused(self):
        si = SecureInference(_SECRET)
        with self.assertRaises(SecureInferenceError):
            si.register_model("", "logistic-regression.v1", (1.0, 0.0), 0)

    def test_bad_seq_refused(self):
        si = SecureInference(_SECRET)
        with self.assertRaises(SecureInferenceError):
            si.register_model("x", "logistic-regression.v1", (1.0, 0.0), -1)

    def test_unknown_model_lookup(self):
        si = _server()
        with self.assertRaises(UnknownModelError):
            si.model_commitment("nope")

    def test_short_secret_refused(self):
        with self.assertRaises(SecureInferenceError):
            SecureInference(b"short")


class TestSealAndPredict(unittest.TestCase):
    def test_logistic_prediction_matches_hand_computation(self):
        si = _server()
        sealed = si.seal_input("logreg", (1.0, 2.0), 1)
        pred = si.predict(sealed, 2)
        z = 0.5 * 1.0 + -0.25 * 2.0 + 0.1
        expected = 1.0 / (1.0 + math.exp(-z))
        self.assertAlmostEqual(pred.scores[1], expected, places=12)
        self.assertAlmostEqual(sum(pred.scores), 1.0, places=12)
        self.assertEqual(pred.predicted_class, 0 if expected < 0.5 else 1)

    def test_mlp_scores_sum_to_one(self):
        si = SecureInference(_SECRET)
        weights = (2.0, 2.0, 1.0, -1.0, 0.5, -0.5, 1.0, 0.0, 0.0, 1.0, 0.1, -0.1)
        si.register_model("mlp", "tiny-mlp.v1", weights, 0)
        pred = si.predict(si.seal_input("mlp", (0.75,), 1), 2)
        self.assertAlmostEqual(sum(pred.scores), 1.0, places=12)
        self.assertIn(pred.predicted_class, (0, 1))
        self.assertTrue(pred.result_digest.startswith("sha256:"))

    def test_prediction_binds_model_digest(self):
        si = _server()
        sealed = si.seal_input("logreg", (1.0, 2.0), 1)
        pred = si.predict(sealed, 2)
        self.assertEqual(pred.model_digest, si.model_commitment("logreg").params_digest)

    def test_tampered_ciphertext_refused(self):
        si = _server()
        sealed = si.seal_input("logreg", (1.0, 2.0), 1)
        bad = SealedInput(
            model_id=sealed.model_id,
            model_digest=sealed.model_digest,
            features_ciphertext=bytes([sealed.features_ciphertext[0] ^ 0xFF])
            + sealed.features_ciphertext[1:],
            nonce=sealed.nonce,
            tag=sealed.tag,
            sealed_seq=sealed.sealed_seq,
        )
        with self.assertRaises(SealedInputError):
            si.predict(bad, 2)

    def test_tampered_tag_refused(self):
        si = _server()
        sealed = si.seal_input("logreg", (1.0, 2.0), 1)
        bad = SealedInput(
            model_id=sealed.model_id,
            model_digest=sealed.model_digest,
            features_ciphertext=sealed.features_ciphertext,
            nonce=sealed.nonce,
            tag=bytes([sealed.tag[0] ^ 0xFF]) + sealed.tag[1:],
            sealed_seq=sealed.sealed_seq,
        )
        with self.assertRaises(SealedInputError):
            si.predict(bad, 2)

    def test_stale_model_binding_refused(self):
        si = _server()
        sealed = si.seal_input("logreg", (1.0, 2.0), 1)
        stale_digest = "sha256:" + "00" * 32
        stale = SealedInput(
            model_id=sealed.model_id,
            model_digest=stale_digest,
            features_ciphertext=sealed.features_ciphertext,
            nonce=sealed.nonce,
            tag=si._tag(sealed.model_id, sealed.nonce, sealed.features_ciphertext),
            sealed_seq=sealed.sealed_seq,
        )
        with self.assertRaises(StaleModelError):
            si.predict(stale, 2)

    def test_wrong_dim_features_refused(self):
        si = _server()
        with self.assertRaises(SecureInferenceError):
            si.seal_input("logreg", (1.0, 2.0, 3.0), 1)

    def test_nonfinite_feature_refused(self):
        si = _server()
        with self.assertRaises(SecureInferenceError):
            si.seal_input("logreg", (float("nan"), 2.0), 1)

    def test_bool_feature_refused(self):
        si = _server()
        with self.assertRaises(SecureInferenceError):
            si.seal_input("logreg", (True, 2.0), 1)

    def test_seal_unknown_model(self):
        si = _server()
        with self.assertRaises(UnknownModelError):
            si.seal_input("nope", (1.0, 2.0), 1)

    def test_predict_wrong_type_refused(self):
        si = _server()
        with self.assertRaises(SealedInputError):
            si.predict("not-a-seal", 1)

    def test_records_frozen(self):
        si = _server()
        sealed = si.seal_input("logreg", (1.0, 2.0), 1)
        with self.assertRaises(FrozenInstanceError):
            sealed.sealed_seq = 99
        pred = si.predict(sealed, 2)
        with self.assertRaises(FrozenInstanceError):
            pred.predicted_class = 9

    def test_deterministic_seal_replay(self):
        a = _server()
        b = _server()
        s1 = a.seal_input("logreg", (1.0, 2.0), 1)
        s2 = b.seal_input("logreg", (1.0, 2.0), 1)
        self.assertEqual(s1.features_ciphertext, s2.features_ciphertext)
        self.assertEqual(s1.tag, s2.tag)


class TestAudit(unittest.TestCase):
    def test_event_shape(self):
        ev = secure_inference_audit_event("predicted", {"model_id": "m"}, 5)
        self.assertEqual(ev["schema"], SCHEMA_PIN)
        self.assertEqual(ev["kind"], "secure-inference.predicted")
        self.assertEqual(ev["audit_seq"], 5)

    def test_bad_kind_refused(self):
        with self.assertRaises(SecureInferenceError):
            secure_inference_audit_event("nope", {}, 1)

    def test_bad_seq_refused(self):
        with self.assertRaises(SecureInferenceError):
            secure_inference_audit_event("predicted", {}, True)


class TestMain(unittest.TestCase):
    def test_main_runs(self):
        from secure_inference import main

        main()


if __name__ == "__main__":
    unittest.main()
