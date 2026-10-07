"""Tests for data_poisoning_detector (spec requires 15; 24 shipped)."""

import unittest

from data_poisoning_detector import (
    DATA_POISONING_VERSION,
    SCHEMA_PIN,
    POISONING_THRESHOLD,
    TRIGGER_MIN_COUNT,
    DataSample,
    PoisoningReport,
    make_sample,
    analyze_dataset,
    detect_poisoning,
    poisoning_audit_event,
)


def clean_dataset(n=40):
    return (
        [make_sample([1.0 + 0.1 * i, 2.0], "a", "batch-1", i) for i in range(n // 2)]
        + [make_sample([9.0, 8.0 + 0.1 * i], "b", "batch-1", n // 2 + i) for i in range(n // 2)]
    )


class TestVersionPin(unittest.TestCase):
    def test_version(self):
        self.assertEqual(DATA_POISONING_VERSION, "data-poisoning-detector.v1")

    def test_schema(self):
        self.assertEqual(SCHEMA_PIN, "northstar.data-poisoning.v1")


class TestDataSample(unittest.TestCase):
    def test_frozen(self):
        s = make_sample([1.0], "a", "src", 0)
        with self.assertRaises(Exception):
            s.label = "b"

    def test_bool_feature_rejected(self):
        with self.assertRaises(TypeError):
            make_sample([True], "a", "src", 0)

    def test_non_numeric_feature_rejected(self):
        with self.assertRaises(TypeError):
            make_sample(["x"], "a", "src", 0)

    def test_nan_rejected(self):
        with self.assertRaises(ValueError):
            make_sample([float("nan")], "a", "src", 0)

    def test_empty_features_rejected(self):
        with self.assertRaises(TypeError):
            make_sample([], "a", "src", 0)

    def test_bool_seq_rejected(self):
        with self.assertRaises(TypeError):
            make_sample([1.0], "a", "src", True)

    def test_empty_label_rejected(self):
        with self.assertRaises(TypeError):
            make_sample([1.0], "", "src", 0)


class TestValidation(unittest.TestCase):
    def test_non_list_input(self):
        with self.assertRaises(TypeError):
            detect_poisoning("not a list")

    def test_non_sample_element(self):
        with self.assertRaises(TypeError):
            detect_poisoning([{"features": [1.0]}])

    def test_mixed_dims_rejected(self):
        samples = [make_sample([1.0], "a", "s", 0), make_sample([1.0, 2.0], "a", "s", 1)]
        with self.assertRaises(ValueError):
            detect_poisoning(samples)

    def test_empty_dataset_no_verdict(self):
        self.assertFalse(detect_poisoning([]))
        r = analyze_dataset([])
        self.assertEqual(r.sample_count, 0)
        self.assertFalse(r.tripped)


class TestClean(unittest.TestCase):
    def test_clean_does_not_trip(self):
        self.assertFalse(detect_poisoning(clean_dataset()))
        r = analyze_dataset(clean_dataset())
        self.assertEqual(r.anomaly_score, 0.0)
        self.assertEqual(r.affected_samples, ())

    def test_report_shape(self):
        r = analyze_dataset(clean_dataset())
        self.assertIsInstance(r, PoisoningReport)
        d = r.as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertEqual(d["sample_count"], 40)


class TestLabelFlips(unittest.TestCase):
    def test_identical_features_conflicting_labels(self):
        samples = [make_sample([1.0, 2.0], "a", "s", i) for i in range(15)]
        samples += [make_sample([1.0, 2.0], "b", "s", 15 + i) for i in range(15)]
        r = analyze_dataset(samples)
        self.assertTrue(r.tripped)
        self.assertEqual(r.flip_score, 1.0)
        self.assertEqual(len(r.affected_samples), 30)

    def test_near_identical_within_quantize(self):
        # 0.00004 rounds to the same bucket at 3 decimals.
        samples = [make_sample([1.00004, 2.0], "a", "s", 0),
                   make_sample([1.0, 2.0], "b", "s", 1)]
        r = analyze_dataset(samples)
        self.assertGreater(r.flip_score, 0.0)


class TestOutliers(unittest.TestCase):
    def test_pocket_trips(self):
        samples = clean_dataset()
        samples += [make_sample([100.0, 100.0], "b", "evil", 40 + i) for i in range(6)]
        r = analyze_dataset(samples)
        self.assertEqual(r.outlier_score, 1.0)
        self.assertTrue(r.tripped)

    def test_single_stray_below_threshold(self):
        samples = clean_dataset() + [make_sample([100.0, 100.0], "b", "evil", 40)]
        r = analyze_dataset(samples)
        self.assertLess(r.outlier_score, POISONING_THRESHOLD)


class TestTriggers(unittest.TestCase):
    def test_rare_constant_coherent_label(self):
        samples = [make_sample([1.0, 2.0 + 0.11 * i], "a", "s", i) for i in range(100)]
        samples += [make_sample([777.7, 2.0], "b", "s", 100 + i) for i in range(5)]
        r = analyze_dataset(samples)
        self.assertTrue(r.tripped)
        self.assertGreaterEqual(r.trigger_score, 0.8)
        self.assertEqual(len(r.affected_samples), 5)

    def test_below_min_count_not_trigger(self):
        samples = [make_sample([1.0, 2.0 + 0.11 * i], "a", "s", i) for i in range(100)]
        samples += [make_sample([777.7, 2.0], "b", "s", 100 + i) for i in range(TRIGGER_MIN_COUNT - 1)]
        r = analyze_dataset(samples)
        # count < 3: trigger signal must not fire on this shape
        self.assertLess(r.trigger_score, 0.8)


class TestAuditEvent(unittest.TestCase):
    def test_event_shape(self):
        r = analyze_dataset(clean_dataset())
        ev = poisoning_audit_event(r, "ds-1", 7)
        self.assertEqual(ev["schema"], "audit.ndjson/1")
        self.assertEqual(ev["event"], "data-poisoning-scan")
        self.assertEqual(ev["dataset_id"], "ds-1")
        self.assertIn("flip", ev["signals"])

    def test_bad_seq_rejected(self):
        r = analyze_dataset(clean_dataset())
        with self.assertRaises(TypeError):
            poisoning_audit_event(r, "ds-1", True)

    def test_empty_dataset_id_rejected(self):
        r = analyze_dataset(clean_dataset())
        with self.assertRaises(TypeError):
            poisoning_audit_event(r, "", 7)


if __name__ == "__main__":
    unittest.main()
