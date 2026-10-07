"""Targeted tests for spam_detector (heuristic + learned spam detection)."""

import ast
import unittest
from pathlib import Path

import spam_detector
from spam_detector import (
    SpamDetector,
    SpamError,
    BadTextError,
    BadLabelError,
    BadThresholdError,
    UnknownExampleError,
    SeqOrderError,
    spam_detector_audit_event,
)

SPAM_A = "WINNER! You won the lottery! Claim your FREE prize now!!!"
SPAM_B = "Cheap viagra cialis pharmacy pills, click here for discount!"
HAM_A = "Hi, are we still on for lunch tomorrow? Let me know."
HAM_B = "The meeting notes are attached. Please review when you can."
LOUD = (
    "CONGRATULATIONS!!! You are a WINNER! Claim your FREE lottery "
    "prize now!!! Click here http://spam.example/win $$$1000000"
)
QUIET = "Thanks for the update, I'll check the report tonight."


def make_trained() -> SpamDetector:
    d = SpamDetector()
    d.train(SPAM_A, "spam", 0)
    d.train(SPAM_B, "spam", 1)
    d.train(HAM_A, "ham", 2)
    d.train(HAM_B, "ham", 3)
    return d


class TestPins(unittest.TestCase):
    def test_version_pins(self):
        self.assertEqual(spam_detector.SPAM_DETECTOR_VERSION, "spam-detector.v1")
        self.assertEqual(spam_detector.SCHEMA_PIN, "northstar.spam-detector.v1")

    def test_stdlib_only(self):
        tree = ast.parse(Path(spam_detector.__file__).read_text())
        allowed = {
            "__future__", "hashlib", "math", "re", "threading",
            "dataclasses", "typing", "json", "canonical_json",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(
                        a.name.split(".")[0], allowed, a.name,
                    )
            elif isinstance(node, ast.ImportFrom):
                self.assertIn(node.module.split(".")[0], allowed)


class TestTrain(unittest.TestCase):
    def setUp(self):
        self.detector = SpamDetector()

    def test_train_roundtrip(self):
        rec = self.detector.train(SPAM_A, "spam", 0)
        self.assertTrue(rec.verify())
        self.assertEqual(rec.example_id, "ex-1")
        self.assertEqual(rec.label, "spam")
        self.assertTrue(rec.record_digest.startswith("sha256:"))
        self.assertEqual(rec.tokens, tuple(sorted(rec.tokens)))

    def test_train_ids_monotonic(self):
        r1 = self.detector.train(SPAM_A, "spam", 0)
        r2 = self.detector.train(HAM_A, "ham", 1)
        self.assertEqual((r1.example_id, r2.example_id), ("ex-1", "ex-2"))

    def test_train_updates_stats(self):
        self.detector.train(SPAM_A, "spam", 0)
        self.detector.train(SPAM_B, "spam", 1)
        self.detector.train(HAM_A, "ham", 2)
        stats = self.detector.stats()
        self.assertEqual(stats["examples"], 3)
        self.assertEqual(stats["spam_examples"], 2)
        self.assertEqual(stats["ham_examples"], 1)
        self.assertGreater(stats["vocab_size"], 0)

    def test_train_bad_label_refused(self):
        with self.assertRaises(BadLabelError):
            self.detector.train(SPAM_A, "junk", 0)
        with self.assertRaises(BadLabelError):
            self.detector.train(SPAM_A, "SPAM", 1)

    def test_train_bad_text_refused(self):
        with self.assertRaises(BadTextError):
            self.detector.train("", "spam", 0)
        with self.assertRaises(BadTextError):
            self.detector.train("   ", "spam", 1)
        with self.assertRaises(BadTextError):
            self.detector.train(123, "spam", 2)
        with self.assertRaises(BadTextError):
            self.detector.train(None, "spam", 3)

    def test_train_failed_call_burns_seq(self):
        with self.assertRaises(BadLabelError):
            self.detector.train(SPAM_A, "junk", 0)
        with self.assertRaises(SeqOrderError):
            self.detector.train(SPAM_A, "spam", 0)

    def test_token_stats(self):
        self.detector.train(SPAM_A, "spam", 0)
        self.detector.train(HAM_A, "ham", 1)
        ts = self.detector.token_stats("winner")
        self.assertIsNotNone(ts)
        self.assertGreater(ts["p_spam_given_token"], 0.5)
        self.assertEqual(ts["spam_count"], 1)
        self.assertIsNone(self.detector.token_stats("never-seen"))

    def test_training_record_lookup(self):
        rec = self.detector.train(SPAM_A, "spam", 0)
        fetched = self.detector.training_record("ex-1")
        self.assertEqual(fetched.record_digest, rec.record_digest)
        with self.assertRaises(UnknownExampleError):
            self.detector.training_record("ex-999")


class TestScore(unittest.TestCase):
    def setUp(self):
        self.detector = make_trained()

    def test_score_spam_high(self):
        report = self.detector.score(LOUD, 4)
        self.assertTrue(report.verify())
        self.assertGreaterEqual(report.score, 0.5)
        self.assertTrue(report.trained)
        self.assertTrue(report.text_digest.startswith("sha256:"))

    def test_score_report_shape(self):
        report = self.detector.score(LOUD, 4)
        self.assertGreaterEqual(report.score, 0.0)
        self.assertLessEqual(report.score, 1.0)
        feats = [c.feature for c in report.contributions]
        self.assertEqual(feats, sorted(feats))
        self.assertEqual(len(feats), 7)
        weights = {
            c.feature: c.weight
            for c in report.contributions
            if c.component == "heuristic"
        }
        self.assertAlmostEqual(sum(weights.values()), 1.0, places=9)

    def test_score_untrained_neutral_nb(self):
        fresh = SpamDetector()
        report = fresh.score(HAM_A, 0)
        self.assertTrue(report.verify())
        self.assertFalse(report.trained)
        self.assertAlmostEqual(report.naive_bayes, 0.5)

    def test_score_deterministic(self):
        r1 = self.detector.score(LOUD, 4)
        other = make_trained()
        r2 = other.score(LOUD, 4)
        self.assertEqual(r1.score, r2.score)
        self.assertEqual(r1.report_digest, r2.report_digest)

    def test_score_seq_rewind_refused(self):
        self.detector.score(LOUD, 4)
        with self.assertRaises(SeqOrderError):
            self.detector.score(LOUD, 4)
        with self.assertRaises(SeqOrderError):
            self.detector.score(LOUD, 3)

    def test_score_bad_seq_type(self):
        with self.assertRaises(SpamError):
            self.detector.score(LOUD, True)
        with self.assertRaises(SpamError):
            self.detector.score(LOUD, -1)


class TestClassify(unittest.TestCase):
    def setUp(self):
        self.detector = make_trained()

    def test_classify_spam(self):
        cls = self.detector.classify(LOUD, 4)
        self.assertTrue(cls.verify())
        self.assertEqual(cls.label, "spam")
        self.assertEqual(cls.threshold, 0.5)

    def test_classify_ham(self):
        cls = self.detector.classify(QUIET, 4)
        self.assertTrue(cls.verify())
        self.assertEqual(cls.label, "ham")

    def test_threshold_is_policy(self):
        cls = self.detector.classify(LOUD, 4, threshold=0.99)
        self.assertEqual(cls.label, "ham")
        self.assertEqual(cls.threshold, 0.99)

    def test_classify_threshold_bounds(self):
        # Failed calls burn their seq (ledger discipline), so each attempt
        # needs a fresh, strictly increasing seq.
        seq = 10
        for bad in (0.0, 1.0, 1.5, -0.1, True, "0.5", float("nan")):
            with self.assertRaises(BadThresholdError, msg=repr(bad)):
                self.detector.classify(LOUD, seq, threshold=bad)
            seq += 1

    def test_classify_seq_shared_ledger(self):
        self.detector.score(LOUD, 4)
        with self.assertRaises(SeqOrderError):
            self.detector.classify(LOUD, 4)


class TestAudit(unittest.TestCase):
    def test_audit_shapes(self):
        report = make_trained().score(LOUD, 4)
        ev = spam_detector_audit_event(
            "scored", 0, text_digest=report.text_digest, score=report.score
        )
        self.assertEqual(ev["schema"], "audit.ndjson/1")
        self.assertEqual(ev["event"], "scored")
        self.assertEqual(ev["module_version"], "spam-detector.v1")
        self.assertEqual(ev["module_schema"], "northstar.spam-detector.v1")
        self.assertEqual(ev["score"], report.score)

    def test_audit_unknown_kind(self):
        with self.assertRaises(SpamError):
            spam_detector_audit_event("nope", 0)

    def test_audit_text_never_crosses(self):
        ev = spam_detector_audit_event(
            "trained", 1, example_id="ex-1", label="spam"
        )
        joined = " ".join(str(v) for v in ev.values())
        self.assertNotIn(SPAM_A, joined)

    def test_main_self_check(self):
        # Runs the module's own main(); must not raise.
        spam_detector.main()


if __name__ == "__main__":
    unittest.main()
