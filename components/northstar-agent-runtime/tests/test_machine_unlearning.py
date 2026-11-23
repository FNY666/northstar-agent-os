"""Tests for machine_unlearning.py — certified unlearning registry (simulated)."""
import threading
import unittest

from machine_unlearning import (
    MachineUnlearning,
    TrainingRecord,
    ForgetRequest,
    UnlearningCertificate,
    UnlearningError,
    machine_unlearning_audit_event,
    VERSION,
    SCHEMA,
)


class TestPins(unittest.TestCase):
    def test_version_and_schema(self):
        self.assertTrue(VERSION.startswith("machine-unlearning.v"))
        self.assertEqual(SCHEMA, "northstar.machine-unlearning.v1")


class TestTraining(unittest.TestCase):
    def setUp(self):
        self.mu = MachineUnlearning()

    def test_add_roundtrip(self):
        rec = self.mu.add_training("d1", {"x": 1}, 0)
        self.assertEqual(rec.data_id, "d1")
        self.assertTrue(rec.data_pin.startswith("sha256:"))
        self.assertIn("d1", self.mu.retained_ids())

    def test_duplicate_add_rejected(self):
        self.mu.add_training("d1", "a", 0)
        with self.assertRaises(UnlearningError):
            self.mu.add_training("d1", "b", 1)

    def test_empty_data_id_rejected(self):
        with self.assertRaises(UnlearningError):
            self.mu.add_training("", "a", 0)

    def test_non_str_id_rejected(self):
        with self.assertRaises(UnlearningError):
            self.mu.add_training(1, "a", 0)

    def test_bool_seq_rejected(self):
        with self.assertRaises(UnlearningError):
            self.mu.add_training("d1", "a", True)

    def test_negative_seq_rejected(self):
        with self.assertRaises(UnlearningError):
            self.mu.add_training("d1", "a", -1)

    def test_record_frozen(self):
        rec = self.mu.add_training("d1", "a", 0)
        with self.assertRaises(Exception):
            rec.data_id = "x"  # frozen dataclass

    def test_schema_pin_enforced(self):
        with self.assertRaises(UnlearningError):
            TrainingRecord(data_id="d", data_pin="p", added_seq=0, schema_pin="bogus")

    def test_data_pin_deterministic(self):
        r1 = self.mu.add_training("d1", {"b": 2, "a": 1}, 0)
        mu2 = MachineUnlearning()
        r2 = mu2.add_training("d1", {"a": 1, "b": 2}, 0)
        self.assertEqual(r1.data_pin, r2.data_pin)


class TestForget(unittest.TestCase):
    def setUp(self):
        self.mu = MachineUnlearning()
        self.mu.add_training("d1", "a", 0)
        self.mu.add_training("d2", "b", 1)

    def test_forget_happy(self):
        req = self.mu.forget("d1", 2)
        self.assertIsInstance(req, ForgetRequest)
        self.assertEqual(self.mu.forgotten_ids(), ("d1",))
        self.assertEqual(self.mu.retained_ids(), ("d2",))

    def test_forget_unknown_rejected(self):
        with self.assertRaises(UnlearningError):
            self.mu.forget("nope", 2)

    def test_forget_idempotent(self):
        r1 = self.mu.forget("d1", 2)
        r2 = self.mu.forget("d1", 3)
        self.assertEqual(r1, r2)
        kinds = [e["kind"] for e in self.mu.events()]
        self.assertEqual(kinds.count("forgotten"), 1)

    def test_readd_after_forget_rejected(self):
        self.mu.forget("d1", 2)
        with self.assertRaises(UnlearningError):
            self.mu.add_training("d1", "a", 3)


class TestVerifyAndCertify(unittest.TestCase):
    def setUp(self):
        self.mu = MachineUnlearning()
        self.mu.add_training("d1", "a", 0)
        self.mu.add_training("d2", "b", 1)

    def test_verify_before_forget_true(self):
        self.assertTrue(self.mu.verify_forgotten())

    def test_verify_after_forget_true(self):
        self.mu.forget("d1", 2)
        self.assertTrue(self.mu.verify_forgotten())

    def test_certify_shape(self):
        self.mu.forget("d1", 2)
        cert = self.mu.certify(3)
        self.assertIsInstance(cert, UnlearningCertificate)
        self.assertEqual(cert.forgotten, ("d1",))
        self.assertEqual(cert.retained, ("d2",))
        self.assertTrue(cert.all_requests_honored)
        self.assertTrue(cert.certificate_pin.startswith("sha256:"))

    def test_certify_bad_seq_rejected(self):
        with self.assertRaises(UnlearningError):
            self.mu.certify(-1)

    def test_certificate_deterministic(self):
        self.mu.forget("d1", 2)
        c1 = self.mu.certify(3)
        mu2 = MachineUnlearning()
        mu2.add_training("d1", "a", 0)
        mu2.add_training("d2", "b", 1)
        mu2.forget("d1", 2)
        c2 = mu2.certify(3)
        self.assertEqual(c1.certificate_pin, c2.certificate_pin)

    def test_registry_digest_changes(self):
        d1 = self.mu.registry_digest()
        self.mu.forget("d1", 2)
        d2 = self.mu.registry_digest()
        self.assertNotEqual(d1, d2)


class TestAudit(unittest.TestCase):
    def test_audit_shapes(self):
        for kind in ("training-added", "forgotten", "certified"):
            ev = machine_unlearning_audit_event(kind, 0, note="n")
            self.assertEqual(ev["audit"], "audit.ndjson/1")
            self.assertEqual(ev["schema"], SCHEMA)
            self.assertIn("event_pin", ev)

    def test_audit_bad_kind_rejected(self):
        with self.assertRaises(UnlearningError):
            machine_unlearning_audit_event("bogus", 0)

    def test_audit_bad_seq_rejected(self):
        with self.assertRaises(UnlearningError):
            machine_unlearning_audit_event("certified", True)


class TestConcurrency(unittest.TestCase):
    def test_thread_safe(self):
        mu = MachineUnlearning()
        threads = [
            threading.Thread(target=mu.add_training, args=("d%d" % i, i, i))
            for i in range(20)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(mu.retained_ids()), 20)


class TestMain(unittest.TestCase):
    def test_main(self):
        from machine_unlearning import main
        main()


if __name__ == "__main__":
    unittest.main()
