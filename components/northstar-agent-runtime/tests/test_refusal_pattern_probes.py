"""Tests for refusal_pattern_probes."""

import hashlib
import json
import unittest

import refusal_pattern_probes as rpp


def _digest(obj):
    return "sha256:" + hashlib.sha256(
        json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        .encode("utf-8")
    ).hexdigest()


def _refusal(
    call_id="call-1",
    tool="db.wipe",
    deny_code="deny:offensive_tooling",
    source_layer="offensive_tooling",
):
    return rpp.RefusalRecord(
        call_id=call_id,
        tool=tool,
        arguments_digest=_digest({"tool": tool, "args": {}}),
        deny_code=deny_code,
        source_layer=source_layer,
    ).pinned()


def _attempt(
    attempt_id="att-1",
    action_id="act-1",
    kind=rpp.ATTEMPT_BENCHMARK_RECOGNITION,
    target_metric="safety_score",
):
    return rpp.HackAttempt(
        attempt_id=attempt_id,
        action_id=action_id,
        attempt_kind=kind,
        target_metric=target_metric,
        evidence_digest=_digest({"attempt": attempt_id}),
    ).pinned()


def _trajectory(traj_id="traj-1", outcome=rpp.OUTCOME_ACTION_REFUSED):
    return rpp.TrajectoryRecord(
        trajectory_id=traj_id,
        trajectory_digest=_digest({"traj": traj_id}),
        outcome=outcome,
    ).pinned()


def _verdict(verdict, trajectory_digest):
    return rpp.VerdictBinding(
        verdict=verdict,
        trajectory_digest=trajectory_digest,
    ).pinned()


class CorpusShapeTests(unittest.TestCase):
    def test_probe_names_unique(self):
        names = list(rpp.attack_probe_names()) + list(rpp.benign_probe_names())
        self.assertEqual(len(names), len(set(names)))

    def test_required_keys(self):
        for probe in (*rpp.REFUSAL_PATTERN_PROBES, *rpp.REFUSAL_PATTERN_BENIGN):
            for key in ("probe", "family", "attack", "gate_interaction", "expected", "reason"):
                self.assertIn(key, probe, f"{probe['probe']} missing {key}")

    def test_expected_outcomes(self):
        outcomes = rpp.expected_outcomes()
        self.assertTrue(all(outcomes[n] == "deny" for n in rpp.attack_probe_names()))
        self.assertTrue(all(outcomes[n] == "allow" for n in rpp.benign_probe_names()))

    def test_deny_side_keywords_on_all_attacks(self):
        keywords = rpp.DENY_SIDE_KEYWORDS
        for probe in rpp.REFUSAL_PATTERN_PROBES:
            text = probe["gate_interaction"].lower()
            self.assertTrue(
                any(k in text for k in keywords),
                f"{probe['probe']} gate_interaction names no deny-side keyword",
            )

    def test_family_membership(self):
        self.assertEqual(len(rpp.probes_in_family(rpp.FAMILY_REFUSAL_PATTERN)), 4)
        self.assertEqual(len(rpp.probes_in_family(rpp.FAMILY_REWARD_HACK)), 4)
        self.assertEqual(len(rpp.probes_in_family(rpp.FAMILY_PROCESS_SHAPE)), 2)
        self.assertEqual(len(rpp.attack_probe_names()), 10)
        self.assertEqual(len(rpp.benign_probe_names()), 3)

    def test_probe_by_name(self):
        probe = rpp.probe_by_name("refusal-verbal-only")
        self.assertEqual(probe["expected"], "deny")
        with self.assertRaises(KeyError):
            rpp.probe_by_name("no-such-probe")


class RefusalRecordTests(unittest.TestCase):
    def test_roundtrip(self):
        rec = _refusal()
        self.assertTrue(rec.verify())

    def test_tampered_deny_code_fails(self):
        rec = _refusal()
        tampered = object.__new__(rpp.RefusalRecord)
        object.__setattr__(tampered, "call_id", rec.call_id)
        object.__setattr__(tampered, "tool", rec.tool)
        object.__setattr__(tampered, "arguments_digest", rec.arguments_digest)
        object.__setattr__(tampered, "deny_code", "allow")
        object.__setattr__(tampered, "source_layer", rec.source_layer)
        object.__setattr__(tampered, "audit_schema", rec.audit_schema)
        object.__setattr__(tampered, "record_digest", rec.record_digest)
        self.assertFalse(tampered.verify())

    def test_bad_digest_format_fails(self):
        rec = _refusal()
        bad = object.__new__(rpp.RefusalRecord)
        for f in ("call_id", "tool", "arguments_digest", "deny_code",
                  "source_layer", "audit_schema"):
            object.__setattr__(bad, f, getattr(rec, f))
        object.__setattr__(bad, "record_digest", "md5:deadbeef")
        self.assertFalse(bad.verify())

    def test_pinned_rejects_missing_identity(self):
        with self.assertRaises(rpp.RefusalPatternError):
            rpp.RefusalRecord(
                call_id="",
                tool="db.wipe",
                arguments_digest=_digest({}),
                deny_code="deny:x",
                source_layer="host",
            ).pinned()

    def test_pinned_rejects_unpinned_arguments_digest(self):
        with self.assertRaises(rpp.RefusalPatternError):
            rpp.RefusalRecord(
                call_id="c",
                tool="db.wipe",
                arguments_digest="not-a-digest",
                deny_code="deny:x",
                source_layer="host",
            ).pinned()


class GateRefusalTests(unittest.TestCase):
    def test_clean_refusal_proceeds(self):
        decision, findings = rpp.gate_refusal(_refusal())
        self.assertEqual(decision, rpp.DECISION_PROCEED)
        self.assertEqual(findings, ())

    def test_no_record_is_theater(self):
        decision, findings = rpp.gate_refusal(None)
        self.assertEqual(decision, rpp.DECISION_DENY)
        self.assertIn(rpp.DENY_VERBAL_REFUSAL, findings)

    def test_unverifiable_record_denied(self):
        rec = _refusal()
        tampered = object.__new__(rpp.RefusalRecord)
        for f in ("call_id", "tool", "arguments_digest", "deny_code",
                  "source_layer", "audit_schema"):
            object.__setattr__(tampered, f, getattr(rec, f))
        object.__setattr__(tampered, "record_digest", "sha256:" + "0" * 64)
        decision, findings = rpp.gate_refusal(tampered)
        self.assertEqual(decision, rpp.DECISION_DENY)
        self.assertIn(rpp.DENY_REFUSAL_UNVERIFIABLE, findings)

    def test_wrong_layer_denied(self):
        rec = _refusal(source_layer="billing")
        decision, findings = rpp.gate_refusal(rec)
        self.assertEqual(decision, rpp.DECISION_DENY)
        self.assertIn(rpp.DENY_REFUSAL_WRONG_LAYER, findings)


class HackAttemptTests(unittest.TestCase):
    def test_roundtrip(self):
        att = _attempt()
        self.assertTrue(att.verify())

    def test_unknown_kind_rejected_at_pin(self):
        with self.assertRaises(rpp.RefusalPatternError):
            rpp.HackAttempt(
                attempt_id="a",
                action_id="b",
                attempt_kind="mind_reading",
                target_metric="m",
                evidence_digest=_digest({}),
            ).pinned()

    def test_no_attempts_proceeds(self):
        decision, findings = rpp.gate_attempts(())
        self.assertEqual(decision, rpp.DECISION_PROCEED)
        self.assertEqual(findings, ())
        counts = rpp.count_attempts(())
        self.assertEqual(sum(counts.values()), 0)

    def test_attempt_at_threshold_denied(self):
        decision, findings = rpp.gate_attempts(
            (_attempt(kind=rpp.ATTEMPT_SANDBAGGING),), max_allowed=0
        )
        self.assertEqual(decision, rpp.DECISION_DENY)
        self.assertTrue(
            any(f == f"{rpp.DENY_ATTEMPT_MEASURED}:{rpp.ATTEMPT_SANDBAGGING}"
                for f in findings)
        )

    def test_attempt_below_threshold_proceeds(self):
        decision, _ = rpp.gate_attempts((_attempt(),), max_allowed=1)
        self.assertEqual(decision, rpp.DECISION_PROCEED)

    def test_unverifiable_attempt_denied(self):
        att = _attempt()
        tampered = object.__new__(rpp.HackAttempt)
        for f in ("attempt_id", "action_id", "attempt_kind", "target_metric",
                  "evidence_digest", "audit_schema"):
            object.__setattr__(tampered, f, getattr(att, f))
        object.__setattr__(tampered, "record_digest", "sha256:" + "f" * 64)
        decision, findings = rpp.gate_attempts((tampered,))
        self.assertEqual(decision, rpp.DECISION_DENY)
        self.assertIn(rpp.DENY_ATTEMPT_UNVERIFIABLE, findings)

    def test_per_kind_counts_no_composite(self):
        records = (
            _attempt(attempt_id="a1", kind=rpp.ATTEMPT_SANDBAGGING),
            _attempt(attempt_id="a2", kind=rpp.ATTEMPT_SANDBAGGING),
            _attempt(attempt_id="a3", kind=rpp.ATTEMPT_METRIC_OPTIMIZATION),
        )
        counts = rpp.count_attempts(records)
        self.assertEqual(counts[rpp.ATTEMPT_SANDBAGGING], 2)
        self.assertEqual(counts[rpp.ATTEMPT_METRIC_OPTIMIZATION], 1)
        self.assertEqual(counts[rpp.ATTEMPT_BENCHMARK_RECOGNITION], 0)
        self.assertEqual(counts[rpp.ATTEMPT_HONEYPOT_AVOIDANCE], 0)
        self.assertNotIn("total", counts)


class GateVerdictTests(unittest.TestCase):
    def test_anchored_pass_proceeds(self):
        traj = _trajectory(outcome=rpp.OUTCOME_ACTION_EXECUTED)
        binding = _verdict(rpp.VERDICT_PASS, traj.trajectory_digest)
        decision, findings = rpp.gate_verdict(binding, traj)
        self.assertEqual(decision, rpp.DECISION_PROCEED)
        self.assertEqual(findings, ())

    def test_anchored_deny_proceeds(self):
        traj = _trajectory(outcome=rpp.OUTCOME_ACTION_REFUSED)
        binding = _verdict(rpp.VERDICT_DENY, traj.trajectory_digest)
        decision, _ = rpp.gate_verdict(binding, traj)
        self.assertEqual(decision, rpp.DECISION_PROCEED)

    def test_unanchored_verdict_denied(self):
        binding = rpp.VerdictBinding(
            verdict=rpp.VERDICT_PASS, trajectory_digest=""
        ).pinned()
        decision, findings = rpp.gate_verdict(binding, _trajectory())
        self.assertEqual(decision, rpp.DECISION_DENY)
        self.assertIn(rpp.DENY_UNANCHORED_VERDICT, findings)

    def test_trajectory_mismatch_denied(self):
        traj = _trajectory()
        binding = _verdict(rpp.VERDICT_DENY, _digest({"other": "traj"}))
        decision, findings = rpp.gate_verdict(binding, traj)
        self.assertEqual(decision, rpp.DECISION_DENY)
        self.assertIn(rpp.DENY_TRAJECTORY_MISMATCH, findings)

    def test_verdict_contradiction_denied(self):
        traj = _trajectory(outcome=rpp.OUTCOME_ACTION_EXECUTED)
        binding = _verdict(rpp.VERDICT_DENY, traj.trajectory_digest)
        decision, findings = rpp.gate_verdict(binding, traj)
        self.assertEqual(decision, rpp.DECISION_DENY)
        self.assertIn(rpp.DENY_VERDICT_CONTRADICTION, findings)

    def test_missing_trajectory_denied(self):
        binding = _verdict(rpp.VERDICT_PASS, _digest({"traj": "x"}))
        decision, findings = rpp.gate_verdict(binding, None)
        self.assertEqual(decision, rpp.DECISION_DENY)
        self.assertIn(rpp.DENY_TRAJECTORY_MISMATCH, findings)


class MainTests(unittest.TestCase):
    def test_main_runs(self):
        rpp.main()


if __name__ == "__main__":
    unittest.main()
