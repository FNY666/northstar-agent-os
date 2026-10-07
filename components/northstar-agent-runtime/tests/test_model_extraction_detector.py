"""Tests for model_extraction_detector.py: query logs as an extraction tripwire."""

import hashlib
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from model_extraction_detector import (
    SUSPICION_THRESHOLD,
    CLUSTER_THRESHOLD,
    DIVERSITY_THRESHOLD,
    EXTRACTION_DETECTOR_VERSION,
    SCHEMA_PIN,
    VOLUME_THRESHOLD,
    ExtractionDetectorError,
    ExtractionPattern,
    QueryRecord,
    analyze_queries,
    detect_extraction,
    extraction_audit_event,
)


def digest(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()


def make_record(i, **over):
    kwargs = {
        "query_id": f"q{i}",
        "client_id": "client-1",
        "seq": i,
        "input_digest": digest(f"input-{i}"),
        "input_len": 40,
    }
    kwargs.update(over)
    return kwargs


class VersionTest(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(EXTRACTION_DETECTOR_VERSION, "model-extraction-detector.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.model-extraction-detector.v1")

    def test_thresholds(self):
        self.assertEqual(SUSPICION_THRESHOLD, 0.7)
        self.assertEqual(VOLUME_THRESHOLD, 100)
        self.assertEqual(DIVERSITY_THRESHOLD, 0.9)
        self.assertEqual(CLUSTER_THRESHOLD, 5)

    def test_main_runs(self):
        from model_extraction_detector import main

        main()


class RecordTest(unittest.TestCase):
    def test_record_frozen(self):
        rec = QueryRecord("q", "c", 0, digest("x"), 10)
        with self.assertRaises(Exception):
            rec.seq = 99  # type: ignore[misc]

    def test_record_accepts_optional_fields(self):
        rec = QueryRecord("q", "c", 0, digest("x"), 10, output_class="a", confidence=0.5)
        self.assertEqual(rec.output_class, "a")
        self.assertEqual(rec.confidence, 0.5)

    def test_bad_digest_rejected(self):
        with self.assertRaises(ExtractionDetectorError):
            QueryRecord("q", "c", 0, "not-hex", 10)
        with self.assertRaises(ExtractionDetectorError):
            QueryRecord("q", "c", 0, "zz" * 32, 10)

    def test_bool_seq_rejected(self):
        with self.assertRaises(ExtractionDetectorError):
            QueryRecord("q", "c", True, digest("x"), 10)

    def test_negative_seq_rejected(self):
        with self.assertRaises(ExtractionDetectorError):
            QueryRecord("q", "c", -1, digest("x"), 10)

    def test_negative_input_len_rejected(self):
        with self.assertRaises(ExtractionDetectorError):
            QueryRecord("q", "c", 0, digest("x"), -1)

    def test_confidence_out_of_range_rejected(self):
        with self.assertRaises(ExtractionDetectorError):
            QueryRecord("q", "c", 0, digest("x"), 10, confidence=1.5)

    def test_empty_ids_rejected(self):
        with self.assertRaises(ExtractionDetectorError):
            QueryRecord("", "c", 0, digest("x"), 10)

    def test_mapping_input_accepted(self):
        batch = [
            make_record(0, input_digest=digest("same")),
            make_record(1, input_digest=digest("same")),
        ]
        self.assertFalse(detect_extraction(batch))
        pattern = analyze_queries(batch)
        self.assertEqual(pattern.query_count, 2)
        self.assertEqual(pattern.diversity_score, 0.5)

    def test_malformed_entry_type_error(self):
        with self.assertRaises(TypeError):
            detect_extraction([42])
        with self.assertRaises(TypeError):
            detect_extraction("not-a-sequence")

    def test_mapping_missing_key_fails_closed(self):
        with self.assertRaises(ExtractionDetectorError):
            detect_extraction([{"query_id": "q"}])


class DetectionTest(unittest.TestCase):
    def test_empty_batch_quiet(self):
        self.assertFalse(detect_extraction([]))
        pattern = analyze_queries([])
        self.assertEqual(pattern.query_count, 0)
        self.assertFalse(pattern.verdict)

    def test_benign_reuse_quiet(self):
        # same 3 prompts reused 20 times: low diversity
        batch = [
            make_record(i, input_digest=digest(f"prompt-{i % 3}"), input_len=40)
            for i in range(20)
        ]
        pattern = analyze_queries(batch)
        self.assertLess(pattern.diversity_score, DIVERSITY_THRESHOLD)
        self.assertFalse(detect_extraction(batch))

    def test_volume_trip(self):
        batch = [
            make_record(i, input_digest=digest(f"v-{i}"), input_len=40 + (i % 200))
            for i in range(150)
        ]
        pattern = analyze_queries(batch)
        self.assertEqual(pattern.volume_score, 1.0)
        self.assertTrue(pattern.verdict)

    def test_diversity_high_flags(self):
        # 90 distinct of 100 -> diversity 0.9 trips suspicion threshold
        batch = [
            make_record(i, input_digest=digest(f"d-{i}"), input_len=1000 + i * 50)
            for i in range(100)
        ]
        pattern = analyze_queries(batch)
        self.assertGreaterEqual(pattern.diversity_score, 0.9)
        self.assertTrue(pattern.verdict)

    def test_perturbation_cluster_trip(self):
        # 10 distinct digests in one length bucket, low volume otherwise.
        # diversity also maxes here; assert the perturbation signal itself.
        batch = [
            make_record(i, input_digest=digest(f"p-{i}"), input_len=64 + (i % 4))
            for i in range(10)
        ]
        pattern = analyze_queries(batch, volume_threshold=10_000)
        self.assertEqual(pattern.perturbation_score, 1.0)
        self.assertIn(pattern.strongest_signal, ("diversity", "perturbation"))
        self.assertTrue(pattern.verdict)

    def test_small_cluster_quiet(self):
        # 2 probes + one reused digest share the bucket: 3 distinct < 5,
        # perturbation 0.6 < 0.7 verdict bar, everything else diluted -> quiet.
        batch = [make_record(i, input_digest=digest(f"s-{i}"), input_len=64)
                 for i in range(2)]
        batch += [make_record(100 + i, input_digest=digest("same"), input_len=64)
                  for i in range(98)]
        pattern = analyze_queries(batch, volume_threshold=10_000)
        # 3 distinct digests share the bucket (2 probes + the reused one)
        self.assertAlmostEqual(pattern.perturbation_score, 3 / 5)
        self.assertLess(pattern.suspicion, SUSPICION_THRESHOLD)
        self.assertFalse(pattern.verdict)

    def test_coverage_spread_flags(self):
        batch = [
            make_record(
                i,
                input_digest=digest(f"c-{i}"),
                input_len=200 + i * 100,
                output_class=f"class-{i}",
            )
            for i in range(10)
        ]
        pattern = analyze_queries(batch)
        self.assertEqual(pattern.coverage_score, 1.0)
        self.assertTrue(pattern.verdict)

    def test_no_classes_no_coverage(self):
        batch = [make_record(i, input_digest=digest(f"n-{i}")) for i in range(5)]
        pattern = analyze_queries(batch)
        self.assertEqual(pattern.coverage_score, 0.0)

    def test_threshold_boundary(self):
        # suspicion exactly at threshold -> True (fail toward surfacing)
        batch = [
            make_record(i, input_digest=digest(f"e-{i}"), input_len=500 + i * 100)
            for i in range(70)
        ]
        exact = analyze_queries(batch).suspicion
        pattern = analyze_queries(batch, suspicion_threshold=exact)
        self.assertTrue(pattern.verdict)
        # just above the strongest signal -> quiet (calm batch, all signals low)
        calm = [
            make_record(i, input_digest=digest("same"), input_len=40)
            for i in range(10)
        ]
        self.assertFalse(detect_extraction(calm, suspicion_threshold=0.99))

    def test_custom_thresholds(self):
        batch = [make_record(i, input_digest=digest(f"t-{i}")) for i in range(10)]
        self.assertTrue(detect_extraction(batch, volume_threshold=5))
        # all signals low: reused digest, one bucket, tiny volume
        calm = [
            make_record(i, input_digest=digest("same"), input_len=40)
            for i in range(10)
        ]
        self.assertFalse(detect_extraction(calm, volume_threshold=1000,
                                           suspicion_threshold=0.99))

    def test_bad_threshold_rejected(self):
        with self.assertRaises(ExtractionDetectorError):
            detect_extraction([], volume_threshold=0)
        with self.assertRaises(ExtractionDetectorError):
            detect_extraction([], suspicion_threshold=1.5)
        with self.assertRaises(ExtractionDetectorError):
            detect_extraction([], cluster_threshold=-1)


class PatternTest(unittest.TestCase):
    def test_pattern_frozen(self):
        pattern = analyze_queries([make_record(0)])
        with self.assertRaises(Exception):
            pattern.verdict = True  # type: ignore[misc]

    def test_as_dict_shape(self):
        pattern = analyze_queries([make_record(0)])
        d = pattern.as_dict()
        for key in (
            "version",
            "schema",
            "query_count",
            "diversity_score",
            "volume_score",
            "perturbation_score",
            "coverage_score",
            "suspicion",
            "strongest_signal",
            "verdict",
        ):
            self.assertIn(key, d)
        self.assertEqual(d["schema"], SCHEMA_PIN)

    def test_audit_event_shape(self):
        pattern = analyze_queries([make_record(0)])
        event = extraction_audit_event(pattern)
        self.assertEqual(event["type"], "audit.ndjson/1")
        self.assertEqual(event["event"], "model-extraction-analysis")
        self.assertTrue(event["digest"].startswith("sha256:"))
        self.assertEqual(event["query_count"], 1)


if __name__ == "__main__":
    unittest.main()
