"""Tests for the VDF (verifiable delay function) interface."""

import unittest

import vdf_interface as vdf_mod
from vdf_interface import (
    FIELD_PRIME,
    MAX_STEPS,
    SCHEMA_PIN,
    VDF,
    VDF_VERSION,
    Evaluation,
    VDFError,
    VDFProof,
    vdf_audit_event,
)


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(vdf_mod.VDF_VERSION, "vdf-interface.v1")
        self.assertEqual(VDF().version, VDF_VERSION)

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.vdf-interface.v1")


class TestConstructor(unittest.TestCase):
    def test_prime_is_pinned(self):
        self.assertEqual(VDF().prime, FIELD_PRIME)

    def test_max_steps_pin(self):
        self.assertEqual(MAX_STEPS, 1 << 16)


class TestStepsValidation(unittest.TestCase):
    def setUp(self):
        self.v = VDF()

    def _expect_vdf_error(self, steps):
        with self.assertRaises(VDFError):
            self.v.evaluate(b"x", steps)

    def test_zero_steps_rejected(self):
        self._expect_vdf_error(0)

    def test_negative_steps_rejected(self):
        self._expect_vdf_error(-8)

    def test_non_power_of_two_rejected(self):
        self._expect_vdf_error(3)
        self._expect_vdf_error(6)
        self._expect_vdf_error(1000)

    def test_bool_steps_rejected(self):
        with self.assertRaises(TypeError):
            self.v.evaluate(b"x", True)

    def test_str_steps_rejected(self):
        with self.assertRaises(TypeError):
            self.v.evaluate(b"x", "16")

    def test_too_large_steps_rejected(self):
        self._expect_vdf_error(1 << 17)


class TestInputValidation(unittest.TestCase):
    def setUp(self):
        self.v = VDF()

    def test_str_input_rejected(self):
        with self.assertRaises(TypeError):
            self.v.evaluate("northstar", 8)

    def test_none_input_rejected(self):
        with self.assertRaises(TypeError):
            self.v.evaluate(None, 8)

    def test_empty_input_rejected(self):
        with self.assertRaises(VDFError):
            self.v.evaluate(b"", 8)


class TestEvaluate(unittest.TestCase):
    def setUp(self):
        self.v = VDF()

    def test_happy_path(self):
        ev = self.v.evaluate(b"northstar", 16)
        self.assertIsInstance(ev, Evaluation)
        self.assertEqual(ev.steps, 16)
        self.assertTrue(ev.input_digest.startswith("sha256:"))
        self.assertEqual(len(ev.proof.levels), 4)  # log2(16)

    def test_determinism(self):
        e1 = self.v.evaluate(b"northstar", 8)
        e2 = self.v.evaluate(b"northstar", 8)
        self.assertEqual(e1.output, e2.output)
        self.assertEqual(e1.proof.levels, e2.proof.levels)

    def test_input_sensitivity(self):
        e1 = self.v.evaluate(b"northstar", 8)
        e2 = self.v.evaluate(b"northstar!", 8)
        self.assertNotEqual(e1.output, e2.output)

    def test_steps_one(self):
        ev = self.v.evaluate(b"a", 1)
        self.assertEqual(len(ev.proof.levels), 0)  # log2(1) = 0
        self.assertTrue(self.v.verify(b"a", ev.output, ev.proof, 1))

    def test_as_dict_shape(self):
        ev = self.v.evaluate(b"northstar", 4)
        d = ev.as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertEqual(d["steps"], 4)
        self.assertEqual(d["input_digest"], ev.input_digest)
        self.assertEqual(len(d["proof"]["levels"]), 2)
        self.assertEqual(d["proof"]["schema"], SCHEMA_PIN)

    def test_records_frozen(self):
        ev = self.v.evaluate(b"northstar", 4)
        with self.assertRaises(AttributeError):
            ev.output = 1  # type: ignore
        with self.assertRaises(AttributeError):
            ev.proof.levels = ()  # type: ignore


class TestVerify(unittest.TestCase):
    def setUp(self):
        self.v = VDF()
        self.ev = self.v.evaluate(b"northstar", 16)

    def test_roundtrip(self):
        self.assertTrue(self.v.verify(b"northstar", self.ev.output,
                                      self.ev.proof, 16))

    def test_wrong_output_rejected(self):
        bad = (self.ev.output + 1) % FIELD_PRIME
        if bad < 1:
            bad = 2
        self.assertFalse(self.v.verify(b"northstar", bad, self.ev.proof, 16))

    def test_wrong_input_rejected(self):
        self.assertFalse(self.v.verify(b"northstar?", self.ev.output,
                                       self.ev.proof, 16))

    def test_wrong_steps_rejected(self):
        # Proof has log2(16)=4 levels; 8 needs 3 -> level-count mismatch.
        self.assertFalse(self.v.verify(b"northstar", self.ev.output,
                                       self.ev.proof, 8))

    def test_tampered_proof_level_rejected(self):
        levels = list(self.ev.proof.levels)
        levels[0] = (levels[0] + 1) % FIELD_PRIME
        if levels[0] < 1:
            levels[0] = 2
        bad_proof = VDFProof(levels=tuple(levels))
        self.assertFalse(self.v.verify(b"northstar", self.ev.output,
                                       bad_proof, 16))

    def test_cross_input_proof_rejected(self):
        other = self.v.evaluate(b"other", 16)
        self.assertFalse(self.v.verify(b"northstar", self.ev.output,
                                       other.proof, 16))

    def test_bad_proof_type_raises(self):
        with self.assertRaises(TypeError):
            self.v.verify(b"northstar", self.ev.output, "nope", 16)

    def test_bad_steps_raises_not_false(self):
        with self.assertRaises(VDFError):
            self.v.verify(b"northstar", self.ev.output, self.ev.proof, 3)


class TestProofRecord(unittest.TestCase):
    def test_non_tuple_levels_rejected(self):
        with self.assertRaises(TypeError):
            VDFProof(levels=[1, 2])  # type: ignore

    def test_out_of_range_level_rejected(self):
        with self.assertRaises(VDFError):
            VDFProof(levels=(0,))
        with self.assertRaises(VDFError):
            VDFProof(levels=(FIELD_PRIME,))

    def test_schema_mismatch_rejected(self):
        with self.assertRaises(VDFError):
            VDFProof(levels=(1,), schema="bogus")


class TestAuditEvent(unittest.TestCase):
    def test_evaluated_shape(self):
        r = vdf_audit_event("evaluated", 7, steps=16)
        self.assertEqual(r["event"], "vdf-interface")
        self.assertEqual(r["kind"], "evaluated")
        self.assertEqual(r["audit_seq"], 7)
        self.assertEqual(r["schema"], "audit.ndjson/1")
        self.assertEqual(r["steps"], 16)

    def test_verified_shape(self):
        r = vdf_audit_event("verified", 0)
        self.assertEqual(r["kind"], "verified")

    def test_rejected_shape(self):
        r = vdf_audit_event("rejected", 3)
        self.assertEqual(r["kind"], "rejected")

    def test_bad_kind_rejected(self):
        with self.assertRaises(ValueError):
            vdf_audit_event("bogus", 0)

    def test_bad_seq_rejected(self):
        with self.assertRaises(ValueError):
            vdf_audit_event("evaluated", -1)
        with self.assertRaises(ValueError):
            vdf_audit_event("evaluated", True)


class TestMain(unittest.TestCase):
    def test_main_runs(self):
        vdf_mod.main()


if __name__ == "__main__":
    unittest.main()
