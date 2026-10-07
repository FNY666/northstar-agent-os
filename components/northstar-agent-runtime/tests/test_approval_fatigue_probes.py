"""Tests for approval_fatigue_probes."""

from __future__ import annotations

import unittest

from approval_fatigue_probes import (
    APPROVAL_FATIGUE_BENIGN,
    APPROVAL_FATIGUE_PROBES,
    APPROVAL_FATIGUE_SOURCE,
    APPROVAL_FATIGUE_VERSION,
    RISK_HIGH,
    RISK_LOW,
    VERDICT_FATIGUED,
    VERDICT_FLOODED,
    VERDICT_HEALTHY,
    ApprovalEvent,
    FatigueMonitor,
    benign_names,
    expected_outcomes,
    probe_by_name,
    probe_names,
    probes_by_family,
    verify_snapshot,
)


class VersionTest(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(APPROVAL_FATIGUE_VERSION, "approval-fatigue.v1")

    def test_source_shape(self):
        self.assertEqual(
            APPROVAL_FATIGUE_SOURCE["families"],
            [
                "fatigue-flooding",
                "rubber-stamping",
                "silence-laundering",
                "consent-surface",
            ],
        )
        listed = set(APPROVAL_FATIGUE_SOURCE["probes"]) | set(
            APPROVAL_FATIGUE_SOURCE["benign"]
        )
        self.assertEqual(listed, set(probe_names()) | set(benign_names()))


class CorpusShapeTest(unittest.TestCase):
    def test_counts(self):
        self.assertEqual(len(APPROVAL_FATIGUE_PROBES), 12)
        self.assertEqual(len(APPROVAL_FATIGUE_BENIGN), 4)

    def test_families(self):
        for fam in ("fatigue-flooding", "rubber-stamping", "silence-laundering", "consent-surface"):
            self.assertGreaterEqual(len(probes_by_family(fam)), 2, fam)

    def test_field_completeness(self):
        for p in (*APPROVAL_FATIGUE_PROBES, *APPROVAL_FATIGUE_BENIGN):
            for field in ("probe", "family", "attack", "gate_interaction", "expected", "reason"):
                self.assertIn(field, p, p.get("probe"))
                self.assertTrue(p[field], field)

    def test_name_uniqueness(self):
        names = probe_names() + benign_names()
        self.assertEqual(len(names), len(set(names)))

    def test_attacks_deny_benign_allow(self):
        for p in APPROVAL_FATIGUE_PROBES:
            self.assertEqual(p["expected"], "deny", p["probe"])
        for p in APPROVAL_FATIGUE_BENIGN:
            self.assertEqual(p["expected"], "allow", p["probe"])

    def test_no_trusted_framing_loophole(self):
        deny_keywords = (
            "deny", "denies", "denied", "refus", "reject", "fail",
            "held", "quarantine", "escalat", "throttl",
        )
        for p in APPROVAL_FATIGUE_PROBES:
            gi = p["gate_interaction"].lower()
            self.assertTrue(
                any(k in gi for k in deny_keywords),
                f"{p['probe']}: gate_interaction names no deny-side mechanism",
            )


class AccessorTest(unittest.TestCase):
    def test_probe_names(self):
        names = probe_names()
        self.assertIn("flood-then-smuggle", names)
        self.assertIn("silence-as-consent", names)

    def test_benign_names(self):
        self.assertIn("benign-legitimate-burst", benign_names())

    def test_probes_by_family(self):
        fam = probes_by_family("rubber-stamping")
        self.assertTrue(all(p["family"] == "rubber-stamping" for p in fam))

    def test_probe_by_name_hit(self):
        self.assertEqual(
            probe_by_name("uniform-approve-streak")["family"], "rubber-stamping"
        )
        self.assertEqual(probe_by_name("benign-next-morning")["expected"], "allow")

    def test_probe_by_name_miss(self):
        with self.assertRaises(KeyError):
            probe_by_name("no-such-probe")

    def test_expected_outcomes(self):
        outcomes = expected_outcomes()
        self.assertEqual(len(outcomes), 16)
        self.assertEqual(outcomes["timeout-manipulation"], "deny")
        self.assertEqual(outcomes["benign-honest-priority"], "allow")


def _ev(approver="op", t=100.0, approved=True, risk=RISK_LOW):
    return ApprovalEvent(approver=approver, decided_at=t, approved=approved, risk_tier=risk)


def _spaced(n, start=0.0, step=60.0, approved=True, approver="op"):
    return tuple(
        _ev(approver=approver, t=start + i * step, approved=approved)
        for i in range(n)
    )


class MonitorTest(unittest.TestCase):
    def test_healthy_trajectory(self):
        # 8 approvals over 20 minutes with one denial: healthy.
        evs = _spaced(8, start=0.0, step=150.0)
        evs = evs[:4] + (_ev(t=640.0, approved=False),) + evs[4:]
        m = FatigueMonitor()
        self.assertEqual(m.classify(evs, now=1500.0), VERDICT_HEALTHY)
        self.assertTrue(m.should_record(evs, now=1500.0))

    def test_flooded_velocity(self):
        # 15 approvals in 10 minutes: faster than any human reviews.
        evs = _spaced(15, start=0.0, step=40.0)
        m = FatigueMonitor()
        self.assertEqual(m.classify(evs, now=900.0), VERDICT_FLOODED)
        self.assertFalse(m.should_record(evs, now=900.0))

    def test_fatigued_uniform_streak(self):
        # 25 approvals, none denied: HITL theater. Spaced so every
        # event is inside the window and no interval collapses.
        evs = _spaced(25, start=600.0, step=10.0)
        m = FatigueMonitor(uniform_approve_streak=25, max_approvals_per_window=1000)
        self.assertEqual(m.classify(evs, now=900.0), VERDICT_FATIGUED)
        self.assertFalse(m.should_record(evs, now=900.0))

    def test_fatigued_interval_collapse(self):
        # 3s / 1.2s / 0.8s intervals: stopped reading.
        evs = (
            _ev(t=0.0),
            _ev(t=3.0),
            _ev(t=4.2),
            _ev(t=5.0),
        )
        m = FatigueMonitor()
        self.assertEqual(m.classify(evs, now=100.0), VERDICT_FATIGUED)
        self.assertFalse(m.should_record(evs, now=100.0))

    def test_denial_resets_streak(self):
        evs = _spaced(24, start=0.0, step=60.0) + (_ev(t=1500.0, approved=False),) + _spaced(5, start=1600.0, step=60.0)
        m = FatigueMonitor(uniform_approve_streak=25, max_approvals_per_window=1000)
        self.assertEqual(m.classify(evs, now=2000.0), VERDICT_HEALTHY)

    def test_window_slides(self):
        # Old events age out of the window: burst an hour ago is healthy now.
        evs = _spaced(15, start=0.0, step=40.0)
        m = FatigueMonitor()
        self.assertEqual(m.classify(evs, now=3600.0 + 600.0), VERDICT_HEALTHY)

    def test_snapshot_round_trip(self):
        evs = _spaced(5, start=0.0, step=120.0)
        m = FatigueMonitor()
        snap = m.snapshot(evs, now=900.0)
        self.assertEqual(snap["verdict"], VERDICT_HEALTHY)
        self.assertTrue(verify_snapshot(snap))

    def test_snapshot_tamper(self):
        evs = _spaced(5, start=0.0, step=120.0)
        m = FatigueMonitor()
        snap = m.snapshot(evs, now=900.0)
        snap["verdict"] = VERDICT_HEALTHY  # was fatigued? flip a number instead
        snap["events"] = 999
        self.assertFalse(verify_snapshot(snap))

    def test_snapshot_malformed(self):
        self.assertFalse(verify_snapshot({"verdict": "healthy"}))
        self.assertFalse(verify_snapshot({"digest": "not-a-sha256"}))

    def test_event_validation(self):
        with self.assertRaises(ValueError):
            ApprovalEvent(approver="", decided_at=1.0, approved=True)
        with self.assertRaises(ValueError):
            ApprovalEvent(approver="op", decided_at=1.0, approved=True, risk_tier="nope")

    def test_monitor_validation(self):
        with self.assertRaises(ValueError):
            FatigueMonitor(window_seconds=0)
        with self.assertRaises(ValueError):
            FatigueMonitor(max_approvals_per_window=0)
        with self.assertRaises(ValueError):
            FatigueMonitor(uniform_approve_streak=1)
        with self.assertRaises(ValueError):
            FatigueMonitor(min_deliberation_seconds=-1)

    def test_empty_window_healthy(self):
        m = FatigueMonitor()
        self.assertEqual(m.classify((), now=100.0), VERDICT_HEALTHY)
        self.assertTrue(m.should_record((), now=100.0))

    def test_outside_window_ignored(self):
        # A future-dated event is not in the window.
        evs = (_ev(t=2000.0),)
        m = FatigueMonitor()
        self.assertEqual(m.classify(evs, now=100.0), VERDICT_HEALTHY)
