"""Tests for benchmark_retirement_probes.py."""

import unittest

import benchmark_retirement_probes as brp


def _digests():
    return {
        "corpus": "sha256:" + "a" * 64,
        "harness": "sha256:" + "b" * 64,
        "task": "sha256:" + "c" * 64,
    }


def _live_record(**over):
    d = _digests()
    kw = {
        "benchmark_id": "tau2-bench",
        "corpus_digest": d["corpus"],
        "harness_digest": d["harness"],
        "task_info_digest": d["task"],
        "status": brp.STATUS_LIVE,
    }
    kw.update(over)
    return brp.build_record(**kw)


class CorpusShapeTests(unittest.TestCase):
    def test_attack_and_benign_counts(self):
        self.assertEqual(len(brp.BENCHMARK_RETIREMENT_PROBES), 10)
        self.assertEqual(len(brp.BENCHMARK_RETIREMENT_BENIGN), 3)

    def test_required_keys(self):
        for probe in (*brp.BENCHMARK_RETIREMENT_PROBES,
                      *brp.BENCHMARK_RETIREMENT_BENIGN):
            for key in ("probe", "family", "attack",
                        "gate_interaction", "expected", "reason"):
                self.assertIn(key, probe, probe.get("probe"))

    def test_unique_names(self):
        names = [p["probe"] for p in (*brp.BENCHMARK_RETIREMENT_PROBES,
                                     *brp.BENCHMARK_RETIREMENT_BENIGN)]
        self.assertEqual(len(names), len(set(names)))

    def test_deny_side_keywords_on_all_attacks(self):
        for probe in brp.BENCHMARK_RETIREMENT_PROBES:
            text = probe["gate_interaction"].lower()
            self.assertTrue(
                any(k in text for k in brp.DENY_SIDE_KEYWORDS),
                f"{probe['probe']} gate_interaction names no deny-side keyword",
            )

    def test_per_family_counts(self):
        # probes_in_family includes benign controls (sibling convention)
        self.assertEqual(len(brp.probes_in_family("saturation")), 5)   # 4 + 1
        self.assertEqual(len(brp.probes_in_family("contamination")), 4)  # 3 + 1
        self.assertEqual(len(brp.probes_in_family("retirement-evasion")), 4)  # 3 + 1
        self.assertEqual(len(brp.BENCHMARK_RETIREMENT_PROBES), 10)

    def test_expected_outcomes(self):
        outcomes = brp.expected_outcomes()
        for name in brp.attack_probe_names():
            self.assertEqual(outcomes[name], "deny")
        for name in brp.benign_probe_names():
            self.assertEqual(outcomes[name], "allow")

    def test_probe_by_name(self):
        probe = brp.probe_by_name("retirement-cited-live")
        self.assertEqual(probe["family"], "retirement-evasion")
        with self.assertRaises(KeyError):
            brp.probe_by_name("no-such-probe")

    def test_main_runs(self):
        brp.main()  # must not raise


class TriggerTests(unittest.TestCase):
    def test_canonical_triggers(self):
        triggers = brp.retirement_triggers()
        self.assertEqual(len(triggers), 6)
        self.assertIn(brp.TRIGGER_BENCHMARK_RETIRED, triggers)
        self.assertIn(brp.TRIGGER_CORPUS_REFRESHED, triggers)

    def test_complete_triggers_no_findings(self):
        self.assertEqual(brp.check_triggers(brp.retirement_triggers()), ())

    def test_missing_triggers_named(self):
        missing = brp.check_triggers(("benchmark-retired",))
        self.assertEqual(len(missing), 5)
        self.assertIn(brp.TRIGGER_HARNESS_UPDATED, missing)

    def test_malformed_triggers_all_missing(self):
        self.assertEqual(brp.check_triggers(None), brp.RETIREMENT_TRIGGERS)
        self.assertEqual(brp.check_triggers(42), brp.RETIREMENT_TRIGGERS)
        self.assertEqual(brp.check_triggers(("ok", 42)), brp.RETIREMENT_TRIGGERS)


class RecordTests(unittest.TestCase):
    def test_build_and_verify_round_trip(self):
        record = _live_record()
        self.assertTrue(brp.verify_record(record))
        self.assertTrue(record.digest.startswith("sha256:"))

    def test_tampered_record_fails(self):
        record = _live_record()
        tampered = brp.BenchmarkRecord(
            benchmark_id=record.benchmark_id,
            corpus_digest=record.corpus_digest,
            harness_digest=record.harness_digest,
            task_info_digest=record.task_info_digest,
            status=brp.STATUS_RETIRED,  # status changed, digest not recomputed
            digest=record.digest,
        )
        self.assertFalse(brp.verify_record(tampered))

    def test_bad_inputs_rejected(self):
        with self.assertRaises(ValueError):
            brp.build_record("", _digests()["corpus"],
                             _digests()["harness"], _digests()["task"])
        with self.assertRaises(ValueError):
            brp.build_record("x", "not-a-digest",
                             _digests()["harness"], _digests()["task"])
        with self.assertRaises(ValueError):
            _live_record(status="zombie")

    def test_retire_record(self):
        live = _live_record()
        retired = brp.retire_record(live)
        self.assertEqual(retired.status, brp.STATUS_RETIRED)
        self.assertTrue(brp.verify_record(retired))
        # the live record is untouched history
        self.assertTrue(brp.verify_record(live))
        self.assertNotEqual(live.digest, retired.digest)

    def test_retire_unverifiable_raises(self):
        live = _live_record()
        bad = brp.BenchmarkRecord(
            benchmark_id=live.benchmark_id,
            corpus_digest=live.corpus_digest,
            harness_digest=live.harness_digest,
            task_info_digest=live.task_info_digest,
            status=live.status,
            digest="sha256:" + "0" * 64,
        )
        with self.assertRaises(ValueError):
            brp.retire_record(bad)


class DetectRetirementTests(unittest.TestCase):
    def test_no_change_no_findings(self):
        record = _live_record()
        self.assertEqual(brp.detect_retirement(record, record), ())

    def test_corpus_harness_task_drift(self):
        old = _live_record()
        new = _live_record(corpus_digest="sha256:" + "d" * 64)
        findings = brp.detect_retirement(new, old)
        self.assertIn("corpus-drift", findings)
        new2 = _live_record(harness_digest="sha256:" + "e" * 64)
        self.assertIn("harness-drift", brp.detect_retirement(new2, old))
        new3 = _live_record(task_info_digest="sha256:" + "f" * 64)
        self.assertIn("task-info-drift", brp.detect_retirement(new3, old))

    def test_status_transitions(self):
        live = _live_record()
        retired = brp.retire_record(live)
        self.assertIn("status-retired", brp.detect_retirement(retired, live))
        quarantined = _live_record(status=brp.STATUS_QUARANTINED)
        self.assertIn("status-quarantined",
                      brp.detect_retirement(quarantined, live))
        # resurrected without a new corpus is evasion
        self.assertIn("status-resurrected",
                      brp.detect_retirement(live, retired))

    def test_benchmark_swapped(self):
        old = _live_record()
        new = _live_record(benchmark_id="other-bench")
        self.assertIn("benchmark-swapped", brp.detect_retirement(new, old))

    def test_unverifiable_is_the_finding(self):
        old = _live_record()
        bad = brp.BenchmarkRecord(
            benchmark_id=old.benchmark_id,
            corpus_digest=old.corpus_digest,
            harness_digest=old.harness_digest,
            task_info_digest=old.task_info_digest,
            status=old.status,
            digest="sha256:" + "0" * 64,
        )
        self.assertEqual(brp.detect_retirement(bad, old),
                         ("unverifiable-record",))


class SaturationTests(unittest.TestCase):
    def test_saturated(self):
        report = brp.check_saturation("tau2-bench", [0.999, 1.0, 0.995])
        self.assertTrue(report.saturated)
        self.assertEqual(len(report.scores), 3)

    def test_unsaturated(self):
        report = brp.check_saturation("tau2-bench", [0.62, 0.71, 0.58])
        self.assertFalse(report.saturated)

    def test_empty_scores_unverifiable(self):
        report = brp.check_saturation("tau2-bench", [])
        self.assertEqual(report.scores, ())
        self.assertFalse(report.saturated)

    def test_malformed_scores_unverifiable(self):
        report = brp.check_saturation("tau2-bench", ["high", None])
        self.assertEqual(report.scores, ())
        report2 = brp.check_saturation("tau2-bench", [1.5])
        self.assertEqual(report2.scores, ())

    def test_bad_ceiling_rejected(self):
        with self.assertRaises(ValueError):
            brp.check_saturation("tau2-bench", [0.5], ceiling=1.5)


class ContaminationTests(unittest.TestCase):
    def test_all_kinds_pinnable(self):
        for kind in brp.CONTAMINATION_KINDS:
            signal = brp.record_contamination("tau2-bench", kind, "evidence")
            self.assertEqual(signal.kind, kind)
            self.assertTrue(signal.digest.startswith("sha256:"))

    def test_unknown_kind_rejected(self):
        with self.assertRaises(ValueError):
            brp.record_contamination("tau2-bench", "vibes", "evidence")


class ClaimGateTests(unittest.TestCase):
    def test_live_proceeds(self):
        record = _live_record()
        sat = brp.check_saturation("tau2-bench", [0.62, 0.71])
        verdict, findings = brp.gate_benchmark_claim(record, sat, ())
        self.assertEqual(verdict, "proceed")
        self.assertEqual(findings, ())

    def test_retired_denied(self):
        retired = brp.retire_record(_live_record())
        verdict, findings = brp.gate_benchmark_claim(retired)
        self.assertEqual(verdict, "deny")
        self.assertIn("retired-cited-live", findings)

    def test_quarantined_denied(self):
        record = _live_record(status=brp.STATUS_QUARANTINED)
        verdict, findings = brp.gate_benchmark_claim(record)
        self.assertEqual(verdict, "deny")
        self.assertIn("quarantined-cited-live", findings)

    def test_contamination_denied(self):
        record = _live_record()
        signal = brp.record_contamination("tau2-bench", "train-on-test",
                                         "items in training corpus")
        verdict, findings = brp.gate_benchmark_claim(record, None, (signal,))
        self.assertEqual(verdict, "deny")
        self.assertIn("contamination-train-on-test", findings)

    def test_saturated_holds(self):
        record = _live_record()
        sat = brp.check_saturation("tau2-bench", [0.999, 1.0])
        verdict, findings = brp.gate_benchmark_claim(record, sat, ())
        self.assertEqual(verdict, "hold")
        self.assertIn("saturated-benchmark", findings)

    def test_unverifiable_record_denied(self):
        record = _live_record()
        bad = brp.BenchmarkRecord(
            benchmark_id=record.benchmark_id,
            corpus_digest=record.corpus_digest,
            harness_digest=record.harness_digest,
            task_info_digest=record.task_info_digest,
            status=record.status,
            digest="sha256:" + "0" * 64,
        )
        verdict, findings = brp.gate_benchmark_claim(bad)
        self.assertEqual(verdict, "deny")
        self.assertIn("unverifiable-record", findings)

    def test_saturation_mismatch_denied(self):
        record = _live_record()
        sat = brp.check_saturation("other-bench", [0.5])
        verdict, _ = brp.gate_benchmark_claim(record, sat, ())
        self.assertEqual(verdict, "deny")

    def test_unverifiable_saturation_denied(self):
        record = _live_record()
        sat = brp.check_saturation("tau2-bench", [])
        verdict, findings = brp.gate_benchmark_claim(record, sat, ())
        self.assertEqual(verdict, "deny")
        self.assertIn("unverifiable-saturation", findings)


if __name__ == "__main__":
    unittest.main()
