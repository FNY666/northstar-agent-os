"""Tests for poisoning_defense (spec requires 15)."""

import ast
import hashlib
import subprocess
import sys
import threading
import unittest

from poisoning_defense import (
    POISONING_DEFENSE_VERSION,
    SCHEMA_PIN,
    THREAT_KINDS,
    CLEAN_ACTIONS,
    PoisoningDefense,
    DatasetRecord,
    DetectionRecord,
    CleaningRecord,
    VerificationReport,
    PoisoningDefenseError,
    BadIdError,
    BadDigestError,
    BadThreatError,
    BadActionError,
    BadCountError,
    DuplicateDatasetError,
    UnknownDatasetError,
    SeqOrderError,
    AuditKindError,
    poisoning_defense_audit_event,
)


def good_digest(tag=b"x"):
    return "sha256:" + hashlib.sha256(tag).hexdigest()


class TestPins(unittest.TestCase):
    def test_version(self):
        self.assertEqual(POISONING_DEFENSE_VERSION, "poisoning-defense.v1")

    def test_schema(self):
        self.assertEqual(SCHEMA_PIN, "northstar.poisoning-defense.v1")

    def test_threat_vocabulary(self):
        self.assertEqual(
            THREAT_KINDS,
            (
                "label-flip",
                "outlier-cluster",
                "trigger-pattern",
                "clean-label",
                "data-pipeline",
            ),
        )

    def test_action_vocabulary(self):
        self.assertEqual(
            CLEAN_ACTIONS,
            ("quarantine", "drop-samples", "relabel", "reweight", "abort-training"),
        )


class TestStdlibOnly(unittest.TestCase):
    def test_stdlib_only(self):
        with open("poisoning_defense.py") as f:
            tree = ast.parse(f.read())
        allowed = {
            "hashlib",
            "threading",
            "dataclasses",
            "typing",
            "__future__",
            "json",
            "canonical_json",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.assertIn(a.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                self.assertIn((node.module or "").split(".")[0], allowed)


class TestRegister(unittest.TestCase):
    def test_roundtrip(self):
        d = PoisoningDefense()
        rec = d.register_dataset(
            "ds-1", 1, sample_digest=good_digest(b"a"), n_samples=100
        )
        self.assertIsInstance(rec, DatasetRecord)
        self.assertTrue(rec.verify())
        self.assertEqual(rec.as_dict()["dataset_id"], "ds-1")
        self.assertEqual(d.dataset_record("ds-1"), rec)
        self.assertEqual(d.dataset_ids(), ("ds-1",))
        self.assertEqual(d.stats()["datasets"], 1)

    def test_duplicate_seq_burn(self):
        d = PoisoningDefense()
        d.register_dataset("ds-1", 1)
        n_rejected = len([r for r in d.audit_log() if r["kind"] == "rejected"])
        with self.assertRaises(DuplicateDatasetError):
            d.register_dataset("ds-1", 2)
        rejected = [r for r in d.audit_log() if r["kind"] == "rejected"]
        self.assertEqual(len(rejected), n_rejected + 1)
        self.assertEqual(rejected[-1]["seq"], 2)
        self.assertEqual(rejected[-1]["details"]["rejected_kind"], "register_dataset")

    def test_bad_inputs(self):
        d = PoisoningDefense()
        digest = good_digest()
        cases = [
            lambda s: d.register_dataset("", s),
            lambda s: d.register_dataset(123, s),
            lambda s: d.register_dataset("ds-1", s, sample_digest="not-a-pin"),
            lambda s: d.register_dataset("ds-1", s, sample_digest=b"bytes"),
            lambda s: d.register_dataset("ds-1", s, n_samples=-1),
            lambda s: d.register_dataset("ds-1", s, n_samples=True),
            lambda s: d.register_dataset("ds-1", s, n_samples="100"),
        ]
        seq = 1
        n_rejected = 0
        for case in cases:
            with self.assertRaises(PoisoningDefenseError):
                case(seq)
            seq += 1
            n_rejected += 1
        rejected = [r for r in d.audit_log() if r["kind"] == "rejected"]
        self.assertEqual(len(rejected), n_rejected)
        self.assertEqual(d.stats()["datasets"], 0)


class TestDetect(unittest.TestCase):
    def test_all_threats_accepted(self):
        d = PoisoningDefense()
        digest = good_digest()
        d.register_dataset("ds-1", 1, sample_digest=digest, n_samples=50)
        seq = 2
        for threat in THREAT_KINDS:
            rec = d.detect("ds-1", seq, threat, affected_digest=digest)
            self.assertIsInstance(rec, DetectionRecord)
            self.assertTrue(rec.verify())
            self.assertEqual(rec.threat, threat)
            self.assertEqual(rec.detection_id, f"det-{seq - 1}")
            seq += 1
        self.assertEqual(len(d.detections_for("ds-1")), len(THREAT_KINDS))

    def test_bad_inputs_seq_burn(self):
        d = PoisoningDefense()
        d.register_dataset("ds-1", 1)
        digest = good_digest()
        cases = [
            lambda s: d.detect("nope", s, "label-flip"),
            lambda s: d.detect("ds-1", s, "mystery-threat"),
            lambda s: d.detect("ds-1", s, 42),
            lambda s: d.detect("ds-1", s, "label-flip", affected_digest="raw"),
            lambda s: d.detect("", s, "label-flip"),
        ]
        seq = 2
        for case in cases:
            with self.assertRaises(PoisoningDefenseError):
                case(seq)
            seq += 1
        rejected = [r for r in d.audit_log() if r["kind"] == "rejected"]
        self.assertEqual(len(rejected), len(cases))
        for i, row in enumerate(rejected):
            self.assertEqual(row["seq"], 2 + i)
            self.assertEqual(row["details"]["rejected_kind"], "detect")


class TestClean(unittest.TestCase):
    def test_all_actions_accepted(self):
        d = PoisoningDefense()
        digest = good_digest()
        d.register_dataset("ds-1", 1, n_samples=10)
        seq = 2
        for action in CLEAN_ACTIONS:
            rec = d.clean("ds-1", seq, action, dropped_digest=digest)
            self.assertIsInstance(rec, CleaningRecord)
            self.assertTrue(rec.verify())
            self.assertEqual(rec.action, action)
            self.assertEqual(rec.cleaning_id, f"cln-{seq - 1}")
            seq += 1
        self.assertEqual(len(d.cleanings_for("ds-1")), len(CLEAN_ACTIONS))

    def test_bad_inputs_seq_burn(self):
        d = PoisoningDefense()
        d.register_dataset("ds-1", 1)
        cases = [
            lambda s: d.clean("nope", s, "quarantine"),
            lambda s: d.clean("ds-1", s, "nuke-it"),
            lambda s: d.clean("ds-1", s, None),
            lambda s: d.clean("ds-1", s, "quarantine", dropped_digest="raw-bytes"),
        ]
        seq = 2
        for case in cases:
            with self.assertRaises(PoisoningDefenseError):
                case(seq)
            seq += 1
        rejected = [r for r in d.audit_log() if r["kind"] == "rejected"]
        self.assertEqual(len(rejected), len(cases))
        self.assertTrue(all(r["details"]["rejected_kind"] == "clean" for r in rejected))


class TestVerify(unittest.TestCase):
    def test_read_purity(self):
        d = PoisoningDefense()
        digest = good_digest()
        d.register_dataset("ds-1", 1, sample_digest=digest, n_samples=20)
        d.detect("ds-1", 2, "trigger-pattern", affected_digest=digest)
        d.clean("ds-1", 3, "drop-samples", dropped_digest=digest)
        rows_before = len(d.audit_log())
        report = d.verify("ds-1", 4)
        self.assertIsInstance(report, VerificationReport)
        self.assertTrue(report.integrity_ok)
        self.assertTrue(report.verify())
        self.assertEqual(report.n_detections, 1)
        self.assertEqual(report.n_cleanings, 1)
        self.assertEqual(report.threats, ("trigger-pattern",))
        self.assertEqual(report.actions, ("drop-samples",))
        # same seq twice: pure read, seq not consumed, no audit rows
        report2 = d.verify("ds-1", 4)
        self.assertEqual(report.digest, report2.digest)
        self.assertEqual(len(d.audit_log()), rows_before)

    def test_unknown_dataset_as_data(self):
        d = PoisoningDefense()
        report = d.verify("ghost", 1)
        self.assertFalse(report.integrity_ok)
        self.assertEqual(report.n_detections, 0)
        self.assertTrue(report.verify())

    def test_tamper_as_data(self):
        d = PoisoningDefense()
        digest = good_digest()
        d.register_dataset("ds-1", 1, sample_digest=digest, n_samples=5)
        d.detect("ds-1", 2, "label-flip", affected_digest=digest)
        rec = d.detection_record("det-1")
        object.__setattr__(rec, "threat", "data-pipeline")
        report = d.verify("ds-1", 3)
        self.assertFalse(report.integrity_ok)


class TestSeqDiscipline(unittest.TestCase):
    def test_rewind_bare_no_consumption(self):
        d = PoisoningDefense()
        d.register_dataset("ds-1", 5)
        with self.assertRaises(SeqOrderError):
            d.register_dataset("ds-2", 4)
        rows = len(d.audit_log())
        with self.assertRaises(SeqOrderError):
            d.register_dataset("ds-2", 5)
        self.assertEqual(len(d.audit_log()), rows)
        rec = d.register_dataset("ds-2", 6)
        self.assertEqual(rec.dataset_id, "ds-2")

    def test_malformed_seqs(self):
        d = PoisoningDefense()
        for bad in (True, False, 0, -3, 1.5, "1", None, [1]):
            with self.assertRaises(SeqOrderError):
                d.register_dataset("ds-x", bad)
        with self.assertRaises(SeqOrderError):
            d.verify("ds-x", "4")


class TestAudit(unittest.TestCase):
    def test_shapes_and_kinds(self):
        d = PoisoningDefense()
        digest = good_digest()
        d.register_dataset("ds-1", 1, sample_digest=digest)
        d.detect("ds-1", 2, "outlier-cluster", affected_digest=digest)
        d.clean("ds-1", 3, "reweight", dropped_digest=digest)
        kinds = [r["kind"] for r in d.audit_log()]
        self.assertEqual(
            kinds, ["dataset-registered", "detection-booked", "cleaning-booked"]
        )
        for row in d.audit_log():
            self.assertEqual(row["schema"], "audit.ndjson/1")

    def test_leak_ban(self):
        banned = [
            "samples",
            "sample",
            "data",
            "features",
            "label",
            "payload",
            "trigger",
            "content",
            "raw",
            "text",
        ]
        for key in banned:
            with self.assertRaises(AuditKindError):
                poisoning_defense_audit_event("dataset-registered", 1, **{key: "x"})
        with self.assertRaises(AuditKindError):
            poisoning_defense_audit_event("bogus-kind", 1)

    def test_main_subprocess(self):
        proc = subprocess.run(
            [sys.executable, "poisoning_defense.py"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(proc.returncode, 0)
        self.assertIn("poisoning-defense OK", proc.stdout)


class TestDeterminismAndPurity(unittest.TestCase):
    def test_cross_instance_determinism(self):
        digest = good_digest(b"shared")
        a = PoisoningDefense()
        b = PoisoningDefense()
        for defense in (a, b):
            defense.register_dataset("ds-1", 1, sample_digest=digest, n_samples=7)
            defense.detect("ds-1", 2, "clean-label", affected_digest=digest)
            defense.clean("ds-1", 3, "abort-training")
        ra = a.verify("ds-1", 4)
        rb = b.verify("ds-1", 4)
        self.assertEqual(ra.digest, rb.digest)
        self.assertTrue(ra.verify() and rb.verify())

    def test_frozen_and_threaded_reads(self):
        d = PoisoningDefense()
        d.register_dataset("ds-1", 1)
        rec = d.dataset_record("ds-1")
        import dataclasses

        with self.assertRaises(dataclasses.FrozenInstanceError):
            rec.n_samples = 999

        errors = []

        def reader():
            try:
                for _ in range(200):
                    d.dataset_ids()
                    d.verify("ds-1", 2)
                    d.stats()
                    d.audit_log()
            except Exception as exc:  # pragma: no cover
                errors.append(exc)

        threads = [threading.Thread(target=reader) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
