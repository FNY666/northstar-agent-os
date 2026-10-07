"""Tests for model_watermark.py: simulated DNN watermarking interface."""

import random
import struct
import unittest

import model_watermark as mw
from model_watermark import (
    AGREEMENT_THRESHOLD,
    DEFAULT_BITS,
    MIN_FLOATS,
    MODEL_WATERMARK_VERSION,
    SCHEMA_PIN,
    ModelWatermark,
    ModelWatermarkError,
    RobustnessReport,
    TriggerSet,
    TriggerVerificationReport,
    VerificationReport,
    WatermarkCapacityError,
    WatermarkRecord,
    key_fingerprint,
    make_trigger_set,
    model_watermark_audit_event,
    verify_trigger,
)


def _toy_model(n_floats=96, seed=7):
    rng = random.Random(seed)
    blob = struct.pack("<%df" % n_floats,
                       *(rng.uniform(-1.0, 1.0) for _ in range(n_floats)))
    return {"fc1.weight": blob, "fc2.bias": blob[:n_floats * 2]}


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(MODEL_WATERMARK_VERSION, "model-watermark.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.model-watermark.v1")

    def test_key_fingerprint_shape(self):
        fp = key_fingerprint(b"k")
        self.assertTrue(fp.startswith("sha256:"))
        self.assertEqual(len(fp), len("sha256:") + 64)

    def test_key_fingerprint_str_bytes_equal(self):
        self.assertEqual(key_fingerprint("k"), key_fingerprint(b"k"))


class TestConstructor(unittest.TestCase):
    def test_empty_key_rejected(self):
        with self.assertRaises(ModelWatermarkError):
            ModelWatermark("")

    def test_bad_key_type_rejected(self):
        with self.assertRaises(TypeError):
            ModelWatermark(123)

    def test_bad_bits_rejected(self):
        with self.assertRaises(TypeError):
            ModelWatermark("k", bits=0)
        with self.assertRaises(TypeError):
            ModelWatermark("k", bits=True)

    def test_key_id_published(self):
        self.assertEqual(ModelWatermark("k").key_id, key_fingerprint(b"k"))


class TestEmbed(unittest.TestCase):
    def test_embed_returns_new_model_and_record(self):
        model = _toy_model()
        marked, record = ModelWatermark("k").embed(model)
        self.assertIsInstance(record, WatermarkRecord)
        self.assertEqual(record.bits, DEFAULT_BITS)
        self.assertEqual(record.key_id, key_fingerprint(b"k"))
        self.assertEqual(record.schema, SCHEMA_PIN)
        self.assertNotEqual(record.model_digest_before, record.model_digest_after)

    def test_embed_does_not_mutate_input(self):
        model = _toy_model()
        before = {n: bytes(b) for n, b in model.items()}
        ModelWatermark("k").embed(model)
        for n in model:
            self.assertEqual(bytes(model[n]), before[n])

    def test_embed_deterministic(self):
        m1, _ = ModelWatermark("k").embed(_toy_model())
        m2, _ = ModelWatermark("k").embed(_toy_model())
        self.assertEqual(bytes(m1["fc1.weight"]), bytes(m2["fc1.weight"]))

    def test_embed_rejects_empty_model(self):
        with self.assertRaises(ModelWatermarkError):
            ModelWatermark("k").embed({})

    def test_embed_rejects_non_mapping(self):
        with self.assertRaises(TypeError):
            ModelWatermark("k").embed([("a", b"1234")])

    def test_embed_rejects_non_float32_blob(self):
        with self.assertRaises(ModelWatermarkError):
            ModelWatermark("k").embed({"a": b"12345"})

    def test_embed_rejects_tiny_model(self):
        tiny = {"a": struct.pack("<4f", 0.1, 0.2, 0.3, 0.4)}
        with self.assertRaises(WatermarkCapacityError):
            ModelWatermark("k").embed(tiny)


class TestVerify(unittest.TestCase):
    def test_roundtrip_valid(self):
        marked, _ = ModelWatermark("k").embed(_toy_model())
        report = ModelWatermark("k").verify(marked)
        self.assertIsInstance(report, VerificationReport)
        self.assertTrue(report.valid)
        self.assertEqual(report.confidence, 1.0)
        self.assertEqual(report.bits_matched, report.bits_checked)

    def test_wrong_key_fails(self):
        marked, _ = ModelWatermark("k").embed(_toy_model())
        report = ModelWatermark("wrong").verify(marked)
        self.assertFalse(report.valid)
        self.assertLess(report.confidence, AGREEMENT_THRESHOLD)

    def test_unmarked_model_fails(self):
        report = ModelWatermark("k").verify(_toy_model())
        self.assertFalse(report.valid)

    def test_single_bit_flip_still_valid_but_noticed(self):
        marked, _ = ModelWatermark("k").embed(_toy_model())
        blob = bytearray(bytes(marked["fc1.weight"]))
        blob[0] ^= 0x01  # flip LSB of first float
        tampered = dict(marked)
        tampered["fc1.weight"] = bytes(blob)
        report = ModelWatermark("k").verify(tampered)
        self.assertLess(report.bits_matched, report.bits_checked)


class TestRobustness(unittest.TestCase):
    def test_robustness_report_shape(self):
        rep = ModelWatermark("k").robustness()
        self.assertIsInstance(rep, RobustnessReport)
        self.assertEqual(rep.schema, SCHEMA_PIN)
        levels = {e.level for e in rep.expectations}
        self.assertTrue(levels <= {"tolerant", "partial", "destroyed"})
        self.assertGreaterEqual(len(rep.expectations), 4)

    def test_robustness_honest_about_quantization(self):
        rep = ModelWatermark("k").robustness()
        q = [e for e in rep.expectations if "quant" in e.transform][0]
        self.assertEqual(q.level, "destroyed")


class TestTriggerSet(unittest.TestCase):
    def test_trigger_set_deterministic(self):
        a = make_trigger_set("k", n=4)
        b = make_trigger_set("k", n=4)
        self.assertIsInstance(a, TriggerSet)
        self.assertEqual(a.as_dict(), b.as_dict())

    def test_trigger_set_distinct_triggers(self):
        ts = make_trigger_set("k", n=4)
        inputs = [t.input for t in ts.triggers]
        self.assertEqual(len(set(inputs)), 4)

    def test_trigger_verify_hit(self):
        ts = make_trigger_set("k", n=4)
        oracle = {t.input: t.expected_output for t in ts.triggers}
        rep = verify_trigger(oracle.get, ts)
        self.assertIsInstance(rep, TriggerVerificationReport)
        self.assertTrue(rep.valid)
        self.assertEqual(rep.hit_rate, 1.0)
        self.assertEqual(rep.oracle_errors, 0)

    def test_trigger_verify_miss(self):
        ts = make_trigger_set("k", n=4)
        rep = verify_trigger(lambda b: b"wrong", ts)
        self.assertFalse(rep.valid)
        self.assertEqual(rep.hit_rate, 0.0)

    def test_trigger_oracle_error_counts_as_miss(self):
        ts = make_trigger_set("k", n=2)

        def boom(b):
            raise RuntimeError("host exploded")

        rep = verify_trigger(boom, ts)
        self.assertFalse(rep.valid)
        self.assertEqual(rep.oracle_errors, 2)

    def test_trigger_bad_oracle_type(self):
        with self.assertRaises(TypeError):
            verify_trigger("not-callable", make_trigger_set("k", n=2))

    def test_trigger_set_bad_n(self):
        with self.assertRaises(TypeError):
            make_trigger_set("k", n=0)


class TestAuditEvent(unittest.TestCase):
    def test_audit_event_shape(self):
        ev = model_watermark_audit_event("verified", 3, valid=True, key_id="sha256:x")
        self.assertEqual(ev["schema"], "audit.ndjson/1")
        self.assertEqual(ev["seq"], 3)
        self.assertEqual(ev["event"], "model-watermark.verified")
        self.assertTrue(ev["valid"])

    def test_audit_rejects_unknown_kind(self):
        with self.assertRaises(ValueError):
            model_watermark_audit_event("bogus", 0)

    def test_audit_rejects_bad_seq(self):
        with self.assertRaises(ValueError):
            model_watermark_audit_event("verified", -1)

    def test_audit_never_logs_raw_key(self):
        with self.assertRaises(ValueError):
            model_watermark_audit_event("embedded", 0, key="supersecret")


class TestMain(unittest.TestCase):
    def test_main_self_check(self):
        mw.main()


if __name__ == "__main__":
    unittest.main()
