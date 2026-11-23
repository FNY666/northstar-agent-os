"""Tests for the homomorphic training interface (simulated)."""

import unittest

from homomorphic_training import (
    EncryptedValue,
    EncryptedVector,
    HomomorphicTraining,
    HomomorphicTrainingError,
    IntegrityError,
    KeyMismatchError,
    NoiseExceededError,
    TrainingStep,
    HOMOMORPHIC_TRAINING_SCHEMA,
    HOMOMORPHIC_TRAINING_VERSION,
    BOOTSTRAP_NOISE,
    MAX_NOISE,
    homomorphic_training_audit_event,
    keygen,
    main,
)


def make_trainer(seed=b"test-seed", n=2, scale=100):
    return HomomorphicTraining(seed, n, scale)


class VersionPinTest(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(HOMOMORPHIC_TRAINING_VERSION, "homomorphic-training.v1")

    def test_schema_pin(self):
        self.assertEqual(
            HOMOMORPHIC_TRAINING_SCHEMA, "northstar.homomorphic-training.v1")

    def test_keygen_pins(self):
        kp = keygen(b"s")
        self.assertTrue(kp.key_id.startswith("key-"))
        self.assertTrue(kp.public_pin.startswith("sha256:"))
        self.assertTrue(kp.secret_pin.startswith("sha256:"))
        self.assertEqual(kp.schema, HOMOMORPHIC_TRAINING_SCHEMA)


class ConstructorTest(unittest.TestCase):
    def test_bad_seed(self):
        with self.assertRaises(TypeError):
            HomomorphicTraining(b"", 2)
        with self.assertRaises(TypeError):
            HomomorphicTraining("str", 2)

    def test_bad_n_features(self):
        with self.assertRaises(TypeError):
            HomomorphicTraining(b"s", 0.5)
        with self.assertRaises(HomomorphicTrainingError):
            HomomorphicTraining(b"s", 0)
        with self.assertRaises(HomomorphicTrainingError):
            HomomorphicTraining(b"s", 2048)

    def test_bad_scale(self):
        with self.assertRaises(HomomorphicTrainingError):
            HomomorphicTraining(b"s", 2, scale=0)
        with self.assertRaises(TypeError):
            HomomorphicTraining(b"s", 2, scale=True)


class EncryptDecryptTest(unittest.TestCase):
    def test_roundtrip(self):
        t = make_trainer()
        ct = t.encrypt(42, 0)
        self.assertEqual(t.decrypt(ct), 42)
        self.assertEqual(ct.noise, 0)

    def test_bool_rejected(self):
        t = make_trainer()
        with self.assertRaises(TypeError):
            t.encrypt(True, 0)

    def test_negative_roundtrip(self):
        t = make_trainer()
        ct = t.encrypt(-7, 0)
        self.assertEqual(t.decrypt(ct), -7)

    def test_bound_rejected(self):
        t = make_trainer()
        with self.assertRaises(HomomorphicTrainingError):
            t.encrypt(2**63, 0)

    def test_tamper_fails_closed(self):
        t = make_trainer()
        ct = t.encrypt(5, 0)
        bad = EncryptedValue(
            key_id=ct.key_id, value=999, noise=ct.noise,
            nonce=ct.nonce, digest=ct.digest)
        with self.assertRaises(IntegrityError):
            t.decrypt(bad)

    def test_cross_key_rejected(self):
        t1 = make_trainer(b"a")
        t2 = make_trainer(b"b")
        ct = t1.encrypt(5, 0)
        with self.assertRaises(KeyMismatchError):
            t2.decrypt(ct)


class VectorTest(unittest.TestCase):
    def test_vector_roundtrip(self):
        t = make_trainer()
        v = t.encrypt_vector([1, 2], 0)
        self.assertEqual(t.decrypt_vector(v), (1, 2))
        self.assertTrue(v.digest.startswith("sha256:"))

    def test_empty_vector_rejected(self):
        t = make_trainer()
        with self.assertRaises(HomomorphicTrainingError):
            t.encrypt_vector([], 0)

    def test_determinism(self):
        t1 = make_trainer()
        t2 = make_trainer()
        v1 = t1.encrypt_vector([3, 4], 0)
        v2 = t2.encrypt_vector([3, 4], 0)
        self.assertEqual(v1.digest, v2.digest)


class ForwardTest(unittest.TestCase):
    def test_forward_value(self):
        t = make_trainer()
        # S=100: w=(3.0,5.0), x=(1.0,2.0), b=2.0 -> 3*1+5*2+2 = 15.0
        w = t.encrypt_vector([300, 500], 0)
        x = t.encrypt_vector([100, 200], 0)
        b = t.encrypt(200, 0)
        pred = t.encrypted_forward(w, x, b, 0)
        self.assertEqual(t.decrypt(pred), 1500)

    def test_forward_wrong_shape(self):
        t = make_trainer()
        w = t.encrypt_vector([1, 2, 3], 0)
        x = t.encrypt_vector([1, 2], 0)
        b = t.encrypt(0, 0)
        with self.assertRaises(HomomorphicTrainingError):
            t.encrypted_forward(w, x, b, 0)


class BackwardTest(unittest.TestCase):
    def test_gradient_value(self):
        t = make_trainer()
        # S=100 fixed point: pred=10.0, y=4.0, x=(2.0, 3.0)
        # err=600; grad_w=(trunc(600*200/100), trunc(600*300/100))=(1200,1800)
        pred = t.encrypt(1000, 0)
        y = t.encrypt(400, 0)
        x = t.encrypt_vector([200, 300], 0)
        grad_w, grad_b = t.encrypted_backward(pred, y, x, 0)
        self.assertEqual(t.decrypt_vector(grad_w), (1200, 1800))
        self.assertEqual(t.decrypt(grad_b), 600)

    def test_zero_error_zero_grad(self):
        t = make_trainer()
        pred = t.encrypt(500, 0)
        y = t.encrypt(500, 0)
        x = t.encrypt_vector([200, 300], 0)
        grad_w, grad_b = t.encrypted_backward(pred, y, x, 0)
        self.assertEqual(t.decrypt_vector(grad_w), (0, 0))
        self.assertEqual(t.decrypt(grad_b), 0)


class TrainStepTest(unittest.TestCase):
    def test_step_updates_params(self):
        t = make_trainer()
        w = t.encrypt_vector([100, 100], 0)
        b = t.encrypt(100, 0)
        gw = t.encrypt_vector([10, 20], 0)
        gb = t.encrypt(5, 0)
        # lr = 1/1: s_new = s - trunc(1*g/1)
        w2, b2, step = t.train_step(w, b, gw, gb, 1, 1, 1)
        self.assertEqual(t.decrypt_vector(w2), (90, 80))
        self.assertEqual(t.decrypt(b2), 95)
        self.assertIsInstance(step, TrainingStep)
        self.assertEqual(step.lr_num, 1)
        self.assertEqual(step.lr_den, 1)

    def test_lr_truncates_toward_zero(self):
        t = make_trainer()
        w = t.encrypt_vector([100, 100], 0)
        b = t.encrypt(100, 0)
        gw = t.encrypt_vector([10, -10], 0)
        gb = t.encrypt(7, 0)
        # lr = 1/3: trunc(10/3)=3, trunc(-10/3)=-3, trunc(7/3)=2
        w2, b2, _ = t.train_step(w, b, gw, gb, 1, 3, 0)
        self.assertEqual(t.decrypt_vector(w2), (97, 103))
        self.assertEqual(t.decrypt(b2), 98)

    def test_bad_lr_rejected(self):
        t = make_trainer()
        w = t.encrypt_vector([1, 1], 0)
        b = t.encrypt(1, 0)
        gw = t.encrypt_vector([1, 1], 0)
        gb = t.encrypt(1, 0)
        with self.assertRaises(HomomorphicTrainingError):
            t.train_step(w, b, gw, gb, -1, 100, 0)
        with self.assertRaises(HomomorphicTrainingError):
            t.train_step(w, b, gw, gb, 1, 0, 0)

    def test_zero_lr_no_change(self):
        t = make_trainer()
        w = t.encrypt_vector([50, 60], 0)
        b = t.encrypt(70, 0)
        gw = t.encrypt_vector([1, 1], 0)
        gb = t.encrypt(1, 0)
        w2, b2, _ = t.train_step(w, b, gw, gb, 0, 100, 0)
        self.assertEqual(t.decrypt_vector(w2), (50, 60))
        self.assertEqual(t.decrypt(b2), 70)

    def test_noise_budget_enforced(self):
        t = make_trainer()
        # huge gradient noise pushed via repeated mul: direct mint check
        noisy = t.encrypt(2**62, 0)  # near bound
        with self.assertRaises(NoiseExceededError):
            t._mint(1, MAX_NOISE + 1)

    def test_step_record_shape(self):
        t = make_trainer()
        w = t.encrypt_vector([1, 2], 0)
        b = t.encrypt(3, 0)
        gw = t.encrypt_vector([0, 0], 0)
        gb = t.encrypt(0, 0)
        _, _, step = t.train_step(w, b, gw, gb, 1, 100, 5)
        self.assertEqual(step.step, 5)
        self.assertTrue(step.param_digest_after.startswith("sha256:"))
        self.assertNotEqual(step.param_digest_before, "")
        self.assertLessEqual(step.max_noise, MAX_NOISE)


class EndToEndTest(unittest.TestCase):
    def test_encrypted_sgd_reduces_loss(self):
        t = make_trainer(scale=100)
        w = t.encrypt_vector([0, 0], 0)
        b = t.encrypt(0, 0)

        def trunc(a, b):
            q, _ = divmod(abs(a), abs(b))
            return -q if a < 0 else q

        def loss():
            # Mirror encrypted_forward exactly: trunc(w*x/S) summed + b,
            # compared against the S-scaled label.
            total = 0
            for xs, y in data:
                wv = t.decrypt_vector(w)
                bv = t.decrypt(b)
                pred = sum(trunc(a * b, 100) for a, b in zip(wv, xs)) + bv
                total += (pred - y) ** 2
            return total

        # y = 3*x1 + 5*x2 + 200 (all scaled by 100)
        data = [([100, 200], 3 * 100 + 5 * 200 + 200),
                ([300, 100], 3 * 300 + 5 * 100 + 200)]
        before = loss()
        for i, (xs, y) in enumerate(data * 3):
            x_ct = t.encrypt_vector(xs, i)
            y_ct = t.encrypt(y, i)
            pred = t.encrypted_forward(w, x_ct, b, i)
            grad_w, grad_b = t.encrypted_backward(pred, y_ct, x_ct, i)
            w, b, _ = t.train_step(w, b, grad_w, grad_b, 1, 100, i)
            w = t.bootstrap_vector(w, i)
            b = t.bootstrap(b, i)
        after = loss()
        self.assertLess(after, before)


class BootstrapTest(unittest.TestCase):
    def test_bootstrap_refreshes_noise(self):
        t = make_trainer()
        ct = t.encrypt(9, 0)
        noisy = t._mul(ct, ct)  # noise > 0
        self.assertGreater(noisy.noise, 0)
        fresh = t.bootstrap(noisy, 1)
        self.assertEqual(fresh.noise, BOOTSTRAP_NOISE)
        self.assertEqual(t.decrypt(fresh), 81)

    def test_bootstrap_vector(self):
        t = make_trainer()
        v = t.encrypt_vector([1, 2], 0)
        fresh = t.bootstrap_vector(v, 1)
        self.assertEqual(t.decrypt_vector(fresh), (1, 2))
        self.assertTrue(all(x.noise == BOOTSTRAP_NOISE
                            for x in fresh.values))

    def test_bootstrap_cross_key_rejected(self):
        t1 = make_trainer(b"a")
        t2 = make_trainer(b"b")
        ct = t1.encrypt(5, 0)
        with self.assertRaises(KeyMismatchError):
            t2.bootstrap(ct, 0)


class AuditTest(unittest.TestCase):
    def test_audit_shapes(self):
        for kind in ("keygen", "encrypt", "forward", "backward",
                     "train-step", "bootstrap", "decrypt",
                     "integrity-failed", "noise-exceeded"):
            ev = homomorphic_training_audit_event(kind, 7, detail="x")
            self.assertEqual(ev["schema"], "audit.ndjson/1")
            self.assertEqual(ev["kind"], f"homomorphic-training.{kind}")
            self.assertEqual(ev["module"], HOMOMORPHIC_TRAINING_SCHEMA)
            self.assertEqual(ev["seq"], 7)

    def test_bad_kind_rejected(self):
        with self.assertRaises(ValueError):
            homomorphic_training_audit_event("nope", 0)

    def test_bad_seq_rejected(self):
        with self.assertRaises(ValueError):
            homomorphic_training_audit_event("encrypt", -1)


class MainTest(unittest.TestCase):
    def test_main(self):
        main()  # must not raise


if __name__ == "__main__":
    unittest.main()
