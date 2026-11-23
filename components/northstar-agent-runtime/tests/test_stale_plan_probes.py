"""Targeted tests for stale_plan_probes: freshness gates and invalidation triggers."""

import io
import unittest
from contextlib import redirect_stdout

from stale_plan_probes import (
    FAMILIES,
    STALE_PLAN_PROBES,
    STALE_PLAN_BENIGN,
    STALE_PLAN_VERSION,
    StalePlanRecord,
    attack_probe_names,
    benign_probe_names,
    detect_restamped_plan,
    detect_snapshot_drift,
    expected_outcomes,
    gate_plan_freshness,
    invalidate_remaining_steps,
    main,
    parse_timestamp,
    plan_age_seconds,
    probe_by_name,
    probes_in_family,
    seal_plan_record,
    verify_freshness_decision,
)


def _digest(prefix: str) -> str:
    import hashlib

    return "sha256:" + hashlib.sha256(prefix.encode("utf-8")).hexdigest()


def _record(**over) -> StalePlanRecord:
    kwargs = {
        "plan_id": "plan-1",
        "plan_digest": _digest("steps"),
        "snapshot_time": 1_000_000.0,
        "max_age_seconds": 3600.0,
        "evidence_head_digest": _digest("head-1"),
    }
    kwargs.update(over)
    return StalePlanRecord(**kwargs)


HEAD = _digest("head-1")


class CorpusShapeTest(unittest.TestCase):
    def test_corpus_counts(self) -> None:
        self.assertEqual(len(STALE_PLAN_PROBES), 10)
        self.assertEqual(len(STALE_PLAN_BENIGN), 3)

    def test_families_defined(self) -> None:
        self.assertEqual(set(FAMILIES), {"stale-detection", "freshness-gates", "invalidation-triggers"})
        total = sum(len(v) for v in FAMILIES.values())
        self.assertEqual(total, 10)

    def test_required_keys(self) -> None:
        for probe in (*STALE_PLAN_PROBES, *STALE_PLAN_BENIGN):
            for key in ("probe", "family", "gate_interaction", "expected", "reason"):
                self.assertIn(key, probe, probe["probe"])

    def test_names_unique(self) -> None:
        names = [p["probe"] for p in (*STALE_PLAN_PROBES, *STALE_PLAN_BENIGN)]
        self.assertEqual(len(names), len(set(names)))

    def test_all_attacks_expected_deny(self) -> None:
        for probe in STALE_PLAN_PROBES:
            self.assertEqual(probe["expected"], "deny")

    def test_all_benign_expected_allow(self) -> None:
        for probe in STALE_PLAN_BENIGN:
            self.assertEqual(probe["expected"], "allow")
            self.assertIsNone(probe["attack"])

    def test_attack_gate_interactions_carry_deny_keywords(self) -> None:
        keywords = ("den", "halt", "refus", "reject", "invalid", "fail")
        for probe in STALE_PLAN_PROBES:
            interaction = probe["gate_interaction"].lower()
            self.assertTrue(
                any(k in interaction for k in keywords),
                f"{probe['probe']}: no deny-side keyword in gate_interaction",
            )

    def test_per_family_counts(self) -> None:
        self.assertEqual(len(probes_in_family("stale-detection")), 4)
        self.assertEqual(len(probes_in_family("freshness-gates")), 3)
        self.assertEqual(len(probes_in_family("invalidation-triggers")), 3)

    def test_accessors(self) -> None:
        self.assertEqual(len(attack_probe_names()), 10)
        self.assertEqual(len(benign_probe_names()), 3)
        self.assertIn("stale-expired-evidence-window", attack_probe_names())
        self.assertIn("benign-fresh-plan-dispatch", benign_probe_names())

    def test_probe_by_name(self) -> None:
        self.assertEqual(probe_by_name("stale-future-dated-snapshot")["family"], "stale-detection")
        with self.assertRaises(KeyError):
            probe_by_name("no-such-probe")

    def test_expected_outcomes(self) -> None:
        outcomes = expected_outcomes()
        self.assertEqual(outcomes["stale-expired-evidence-window"], "deny")
        self.assertEqual(outcomes["benign-fresh-plan-dispatch"], "allow")

    def test_main_runs(self) -> None:
        buf = io.StringIO()
        with redirect_stdout(buf):
            main()
        out = buf.getvalue()
        self.assertIn(STALE_PLAN_VERSION, out)
        self.assertIn("10", out)


class TimestampParseTest(unittest.TestCase):
    def test_epoch_number(self) -> None:
        self.assertEqual(parse_timestamp(1234.5), 1234.5)

    def test_rfc3339(self) -> None:
        value = parse_timestamp("2026-10-07T09:00:00Z")
        self.assertIsNotNone(value)
        self.assertIsInstance(value, float)

    def test_missing_returns_none(self) -> None:
        self.assertIsNone(parse_timestamp(None))
        self.assertIsNone(parse_timestamp(""))

    def test_bool_returns_none(self) -> None:
        self.assertIsNone(parse_timestamp(True))


class RecordTest(unittest.TestCase):
    def test_seal_round_trip(self) -> None:
        record = seal_plan_record(
            "p", _digest("s"), 1_000_000.0, 3600, _digest("h")
        )
        self.assertEqual(record.plan_id, "p")
        self.assertEqual(record.snapshot_time, 1_000_000.0)

    def test_seal_rejects_unparseable_time(self) -> None:
        with self.assertRaises(ValueError):
            seal_plan_record("p", _digest("s"), "not-a-time", 3600, _digest("h"))

    def test_fail_closed_bad_digest(self) -> None:
        with self.assertRaises(ValueError):
            _record(plan_digest="not-a-digest")

    def test_fail_closed_empty_plan_id(self) -> None:
        with self.assertRaises(ValueError):
            _record(plan_id="")

    def test_fail_closed_nonpositive_window(self) -> None:
        with self.assertRaises(ValueError):
            _record(max_age_seconds=0)


class FreshnessAgeTest(unittest.TestCase):
    def test_fresh(self) -> None:
        age, status = plan_age_seconds(_record(), 1_000_000.0 + 1800)
        self.assertEqual(status, "fresh")
        self.assertAlmostEqual(age, 1800)

    def test_boundary_is_fresh(self) -> None:
        # age == max_age is still fresh; strictly older is stale
        _, status = plan_age_seconds(_record(), 1_000_000.0 + 3600)
        self.assertEqual(status, "fresh")

    def test_stale(self) -> None:
        age, status = plan_age_seconds(_record(), 1_000_000.0 + 3601)
        self.assertEqual(status, "stale")
        self.assertAlmostEqual(age, 3601)

    def test_future_dated(self) -> None:
        age, status = plan_age_seconds(_record(), 999_999.0)
        self.assertEqual(status, "future-dated")
        self.assertIsNone(age)

    def test_non_numeric_as_of_rejected(self) -> None:
        with self.assertRaises(TypeError):
            plan_age_seconds(_record(), "later")


class GateTest(unittest.TestCase):
    def test_fresh_plan_allowed(self) -> None:
        decision = gate_plan_freshness(
            _record(), 1_000_000.0 + 60, ceiling_seconds=86400,
            registered_head_digest=HEAD,
        )
        self.assertEqual(decision.disposition, "allow")
        self.assertEqual(decision.findings, ())
        self.assertTrue(verify_freshness_decision(decision, _record()))

    def test_expired_window_denied(self) -> None:
        decision = gate_plan_freshness(
            _record(), 1_000_000.0 + 7200, ceiling_seconds=86400,
            registered_head_digest=HEAD,
        )
        self.assertEqual(decision.disposition, "deny")
        self.assertEqual(decision.findings, ("plan-snapshot-stale",))

    def test_future_dated_denied(self) -> None:
        decision = gate_plan_freshness(
            _record(), 999_000.0, ceiling_seconds=86400,
            registered_head_digest=HEAD,
        )
        self.assertEqual(decision.disposition, "deny")
        self.assertEqual(decision.findings, ("plan-snapshot-future-dated",))

    def test_window_over_ceiling_denied(self) -> None:
        decision = gate_plan_freshness(
            _record(), 1_000_000.0 + 60, ceiling_seconds=1800,
            registered_head_digest=HEAD,
        )
        self.assertEqual(decision.disposition, "deny")
        self.assertEqual(decision.findings, ("plan-window-over-ceiling",))

    def test_head_mismatch_denied(self) -> None:
        decision = gate_plan_freshness(
            _record(), 1_000_000.0 + 60, ceiling_seconds=86400,
            registered_head_digest=_digest("head-2"),
        )
        self.assertEqual(decision.disposition, "deny")
        self.assertEqual(decision.findings, ("plan-evidence-changed",))

    def test_first_failure_wins(self) -> None:
        # expired AND head-mismatched: the age check comes first
        decision = gate_plan_freshness(
            _record(), 1_000_000.0 + 7200, ceiling_seconds=86400,
            registered_head_digest=_digest("head-2"),
        )
        self.assertEqual(decision.findings, ("plan-snapshot-stale",))

    def test_tampered_decision_fails_verify(self) -> None:
        from stale_plan_probes import PlanFreshnessDecision

        decision = gate_plan_freshness(
            _record(), 1_000_000.0 + 60, ceiling_seconds=86400,
            registered_head_digest=HEAD,
        )
        bad = PlanFreshnessDecision(
            plan_id=decision.plan_id,
            disposition="allow",
            findings=(),
            decision_digest="sha256:" + "0" * 64,
        )
        self.assertFalse(verify_freshness_decision(bad, _record()))

    def test_fixed_vocabulary_enforced(self) -> None:
        from stale_plan_probes import PlanFreshnessDecision

        with self.assertRaises(ValueError):
            PlanFreshnessDecision(
                plan_id="p", disposition="maybe",
                findings=(), decision_digest="sha256:" + "0" * 64,
            )


class InvalidationTest(unittest.TestCase):
    def test_snapshot_drift_detected(self) -> None:
        self.assertEqual(
            detect_snapshot_drift(_record(), _digest("head-2")), "plan-evidence-changed"
        )

    def test_snapshot_drift_negative(self) -> None:
        self.assertIsNone(detect_snapshot_drift(_record(), HEAD))

    def test_restamped_plan_detected(self) -> None:
        old = _record()
        new = _record(snapshot_time=1_001_000.0)
        self.assertEqual(detect_restamped_plan(old, new), "evidence-restamped")

    def test_restamped_plan_genuine_reobservation(self) -> None:
        # new evidence head = a genuinely new observation, not a restamp
        old = _record()
        new = _record(snapshot_time=1_001_000.0, evidence_head_digest=_digest("head-2"))
        self.assertIsNone(detect_restamped_plan(old, new))

    def test_restamped_plan_different_plan_id(self) -> None:
        old = _record()
        new = _record(plan_id="plan-2", snapshot_time=1_001_000.0)
        self.assertIsNone(detect_restamped_plan(old, new))

    def test_invalidate_remaining_steps_mid_run_change(self) -> None:
        # evidence head changed mid-run: remaining steps invalidated
        decision = invalidate_remaining_steps(
            _record(), 1_000_000.0 + 60, ceiling_seconds=86400,
            registered_head_digest=_digest("head-2"),
        )
        self.assertEqual(decision.disposition, "deny")
        self.assertEqual(decision.findings, ("plan-evidence-changed",))

    def test_invalidate_remaining_steps_window_lapsed(self) -> None:
        # window lapsed mid-run: remaining steps invalidated
        decision = invalidate_remaining_steps(
            _record(), 1_000_000.0 + 7200, ceiling_seconds=86400,
            registered_head_digest=HEAD,
        )
        self.assertEqual(decision.disposition, "deny")
        self.assertEqual(decision.findings, ("plan-snapshot-stale",))

    def test_invalidate_remaining_steps_still_fresh(self) -> None:
        decision = invalidate_remaining_steps(
            _record(), 1_000_000.0 + 60, ceiling_seconds=86400,
            registered_head_digest=HEAD,
        )
        self.assertEqual(decision.disposition, "allow")


if __name__ == "__main__":
    unittest.main()
