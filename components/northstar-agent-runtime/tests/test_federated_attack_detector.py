"""Tests for federated_attack_detector: Byzantine shapes in federated rounds."""

import math
import unittest

from federated_attack_detector import (
    FEDERATED_ATTACK_DETECTOR_VERSION,
    SCHEMA_PIN,
    ByzantineReport,
    ByzantineSignal,
    ClientUpdate,
    DIVERGENCE_THRESHOLD,
    MIN_COHORT,
    SCALE_THRESHOLD,
    SIGN_FLIP_THRESHOLD,
    byzantine_audit_event,
    detect_byzantine,
    scan_byzantine,
)


def honest(i, seq=1):
    """Near-median honest clients with small deterministic jitter."""
    base = [1.0, 2.0, 3.0]
    return ClientUpdate(
        f"honest-{i}", seq, tuple(b + 0.1 * ((i + k) % 3 - 1) for k, b in enumerate(base))
    )


class VersionPinTest(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(FEDERATED_ATTACK_DETECTOR_VERSION, "federated-attack-detector.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.federated-attack-detector.v1")

    def test_threshold_sanity(self):
        self.assertGreater(DIVERGENCE_THRESHOLD, 0)
        self.assertLess(SIGN_FLIP_THRESHOLD, 0)
        self.assertGreater(SCALE_THRESHOLD, 1)
        self.assertGreaterEqual(MIN_COHORT, 3)


class ClientUpdateTest(unittest.TestCase):
    def test_frozen(self):
        u = honest(0)
        with self.assertRaises(AttributeError):
            u.client_id = "x"  # type: ignore[misc]

    def test_rejects_empty_client_id(self):
        with self.assertRaises(TypeError):
            ClientUpdate("", 1, (1.0,))

    def test_rejects_bool_seq(self):
        with self.assertRaises(TypeError):
            ClientUpdate("a", True, (1.0,))

    def test_rejects_negative_seq(self):
        with self.assertRaises(TypeError):
            ClientUpdate("a", -1, (1.0,))

    def test_rejects_bool_vector_element(self):
        with self.assertRaises(TypeError):
            ClientUpdate("a", 1, (True, 1.0))

    def test_rejects_empty_vector(self):
        with self.assertRaises(TypeError):
            ClientUpdate("a", 1, ())

    def test_rejects_nonpositive_weight(self):
        with self.assertRaises(ValueError):
            ClientUpdate("a", 1, (1.0,), weight=0.0)

    def test_digest_is_pinned(self):
        u = honest(0)
        self.assertTrue(u.digest().startswith("sha256:"))
        self.assertEqual(u.digest(), honest(0).digest())


class SignFlipTest(unittest.TestCase):
    def test_sign_flip_flagged(self):
        cohort = [honest(0), honest(1), honest(2),
                  ClientUpdate("flipper", 1, (-1.0, -2.0, -3.0))]
        reports = scan_byzantine(cohort)
        self.assertEqual(len(reports), 1)
        self.assertEqual(reports[0].client_id, "flipper")
        self.assertEqual(reports[0].signal, ByzantineSignal.SIGN_FLIP)

    def test_mild_rotation_not_flagged(self):
        # Slightly rotated but still positively aligned: not a flip.
        cohort = [honest(0), honest(1), honest(2),
                  ClientUpdate("drifty", 1, (0.9, 1.8, 3.5))]
        self.assertFalse(detect_byzantine(cohort))


class ScaleTest(unittest.TestCase):
    def test_inflated_norm_flagged(self):
        cohort = [honest(0), honest(1), honest(2),
                  ClientUpdate("scaler", 1, (10.0, 20.0, 30.0))]
        reports = scan_byzantine(cohort)
        self.assertEqual(len(reports), 1)
        self.assertEqual(reports[0].client_id, "scaler")
        self.assertEqual(reports[0].signal, ByzantineSignal.SCALE)

    def test_inflated_weight_flagged(self):
        cohort = [honest(0), honest(1), honest(2),
                  ClientUpdate("heavy", 1, (1.0, 2.0, 3.0), weight=100.0)]
        reports = scan_byzantine(cohort)
        self.assertEqual(len(reports), 1)
        self.assertEqual(reports[0].client_id, "heavy")
        self.assertEqual(reports[0].signal, ByzantineSignal.SCALE)

    def test_reasonable_scale_clean(self):
        cohort = [honest(0), honest(1), honest(2),
                  ClientUpdate("big-but-ok", 1, (2.0, 4.0, 6.0))]
        self.assertFalse(detect_byzantine(cohort))


class DivergenceTest(unittest.TestCase):
    def test_divergence_flagged(self):
        cohort = [honest(0), honest(1), honest(2),
                  ClientUpdate("drifter", 1, (50.0, -40.0, 60.0))]
        reports = scan_byzantine(cohort)
        self.assertEqual(len(reports), 1)
        self.assertEqual(reports[0].client_id, "drifter")
        self.assertEqual(reports[0].signal, ByzantineSignal.DIVERGENCE)

    def test_honest_cohort_clean(self):
        cohort = [honest(0), honest(1), honest(2), honest(3)]
        self.assertFalse(detect_byzantine(cohort))
        self.assertEqual(scan_byzantine(cohort), ())


class CohortEdgeTest(unittest.TestCase):
    def test_below_min_cohort_no_reports(self):
        self.assertEqual(scan_byzantine([honest(0), honest(1)]), ())
        self.assertFalse(detect_byzantine([honest(0), honest(1)]))

    def test_empty_no_reports(self):
        self.assertEqual(scan_byzantine([]), ())

    def test_none_rejected(self):
        with self.assertRaises(TypeError):
            scan_byzantine(None)  # type: ignore[arg-type]

    def test_dimension_mismatch_rejected(self):
        with self.assertRaises(TypeError):
            scan_byzantine([honest(0), honest(1), ClientUpdate("odd", 1, (1.0, 2.0))])

    def test_mapping_inputs_accepted(self):
        cohort = [
            {"client_id": "a", "round_seq": 1, "vector": [1.0, 2.0, 3.0]},
            {"client_id": "b", "round_seq": 1, "vector": [1.1, 1.9, 3.1]},
            {"client_id": "c", "round_seq": 1, "vector": [0.9, 2.1, 2.9]},
            {"client_id": "bad", "round_seq": 1, "vector": [-1.0, -2.0, -3.0]},
        ]
        reports = scan_byzantine(cohort)
        self.assertEqual([r.client_id for r in reports], ["bad"])

    def test_non_record_rejected(self):
        with self.assertRaises(TypeError):
            scan_byzantine([honest(0), honest(1), "nope"])


class ReportShapeTest(unittest.TestCase):
    def test_reports_deterministic_order(self):
        cohort = [
            ClientUpdate("zeta-flip", 1, (-1.0, -2.0, -3.0)),
            honest(0),
            honest(1),
            honest(2),
            ClientUpdate("alpha-scale", 1, (10.0, 20.0, 30.0)),
        ]
        reports = scan_byzantine(cohort)
        self.assertEqual([r.client_id for r in reports],
                         ["alpha-scale", "zeta-flip"])

    def test_report_frozen_and_bounded_score(self):
        cohort = [honest(0), honest(1), honest(2),
                  ClientUpdate("flipper", 1, (-1.0, -2.0, -3.0))]
        (report,) = scan_byzantine(cohort)
        self.assertTrue(0.0 <= report.anomaly_score <= 1.0)
        with self.assertRaises(AttributeError):
            report.anomaly_score = 0.0  # type: ignore[misc]
        d = report.as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertEqual(d["signal"], "sign-flip")

    def test_strongest_signal_wins(self):
        # Both a flip and an inflation: exactly one report per client.
        cohort = [honest(0), honest(1), honest(2),
                  ClientUpdate("nasty", 1, (-10.0, -20.0, -30.0))]
        reports = scan_byzantine(cohort)
        self.assertEqual(len(reports), 1)
        self.assertEqual(reports[0].client_id, "nasty")


class AuditEventTest(unittest.TestCase):
    def test_audit_event_shape(self):
        (report,) = scan_byzantine(
            [honest(0), honest(1), honest(2),
             ClientUpdate("flipper", 1, (-1.0, -2.0, -3.0))]
        )
        event = byzantine_audit_event(report, 7)
        self.assertEqual(event["schema"], "audit.ndjson/1")
        self.assertEqual(event["seq"], 7)
        self.assertEqual(event["kind"], "federated-byzantine-flag")
        self.assertTrue(event["digest"].startswith("sha256:"))

    def test_audit_event_rejects_bool_seq(self):
        (report,) = scan_byzantine(
            [honest(0), honest(1), honest(2),
             ClientUpdate("flipper", 1, (-1.0, -2.0, -3.0))]
        )
        with self.assertRaises(TypeError):
            byzantine_audit_event(report, True)


class MainSelfCheckTest(unittest.TestCase):
    def test_main(self):
        from federated_attack_detector import main

        main()


if __name__ == "__main__":
    unittest.main()
