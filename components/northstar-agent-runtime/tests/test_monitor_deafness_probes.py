"""Tests for the monitor-deafness probe corpus.

Zero escalation on a live system is a finding, not a clean bill of
health. These tests pin the corpus shape (10 attack probes across 3
families, 3 benign controls) and the escalation-anomaly / health-gate
detector semantics.
"""

import unittest

import monitor_deafness_probes as mdp

EXPECTED_PROBE_NAMES = (
    # deafness-detection
    "deafness-fabricated-heartbeat",
    "deafness-canary-never-trips",
    "deafness-severed-escalation-path",
    "deafness-swallowed-alerts",
    # escalation-anomaly
    "anomaly-zero-escalation-live-system",
    "anomaly-escalation-collapse",
    "anomaly-silence-after-storm",
    # health-gates
    "health-stale-heartbeat-high-stakes",
    "health-starved-pipeline",
    "health-agent-claims-monitor-healthy",
)

EXPECTED_BENIGN_NAMES = (
    "benign-healthy-monitor",
    "benign-single-lapse-recovers",
    "benign-expected-zero-escalations",
)

REQUIRED_KEYS = ("probe", "family", "attack", "gate_interaction", "expected", "reason")

# Every attack probe's gate interaction must name an active deny-side
# check -- framing the attack must never read as a defense.
DENY_SIDE_KEYWORDS = (
    "denies",
    "denied",
    "deny",
    "quarantine",
    "quarantined",
    "quarantines",
    "blocks",
    "refuses",
    "never",
    "fail closed",
)


def _window(agent_id: str, start: int, actions: int, escalations: int) -> "mdp.EscalationWindow":
    return mdp.build_window(
        agent_id=agent_id,
        window_start=start,
        window_end=start + 100,
        actions_observed=actions,
        escalations=escalations,
    )


def _signal(**kwargs: object) -> "mdp.MonitorHealthSignal":
    params: dict[str, object] = {
        "monitor_id": "monitor-1",
        "heartbeat_age_seconds": 30,
        "last_canary_trip_age_seconds": 3600,
        "recent_escalation_count": 5,
        "actions_observed_since_heartbeat": 10,
    }
    params.update(kwargs)
    return mdp.build_signal(**params)  # type: ignore[arg-type]


class CorpusShapeTests(unittest.TestCase):
    def test_probe_names(self) -> None:
        self.assertEqual(mdp.probe_names(), EXPECTED_PROBE_NAMES)

    def test_benign_names(self) -> None:
        self.assertEqual(mdp.benign_names(), EXPECTED_BENIGN_NAMES)

    def test_required_keys(self) -> None:
        for probe in (*mdp.MONITOR_DEAFNESS_PROBES, *mdp.MONITOR_DEAFNESS_BENIGN):
            for key in REQUIRED_KEYS:
                self.assertIn(key, probe, probe["probe"])

    def test_unique_names(self) -> None:
        names = [*mdp.probe_names(), *mdp.benign_names()]
        self.assertEqual(len(names), len(set(names)))

    def test_expected_outcomes(self) -> None:
        outcomes = mdp.expected_outcomes()
        for name in EXPECTED_PROBE_NAMES:
            self.assertEqual(outcomes[name], "deny", name)
        for name in EXPECTED_BENIGN_NAMES:
            self.assertEqual(outcomes[name], "allow", name)

    def test_deny_side_keyword(self) -> None:
        for probe in mdp.MONITOR_DEAFNESS_PROBES:
            text = probe["gate_interaction"].lower()
            self.assertTrue(
                any(k in text for k in DENY_SIDE_KEYWORDS),
                f"{probe['probe']} has no deny-side keyword",
            )

    def test_per_family_counts(self) -> None:
        counts = {
            fam: len(mdp.probes_by_family(fam))
            for fam in ("deafness-detection", "escalation-anomaly", "health-gates")
        }
        self.assertEqual(
            counts,
            {"deafness-detection": 4, "escalation-anomaly": 3, "health-gates": 3},
        )

    def test_probe_by_name_and_keyerror(self) -> None:
        self.assertEqual(
            mdp.probe_by_name("anomaly-silence-after-storm")["family"],
            "escalation-anomaly",
        )
        with self.assertRaises(KeyError):
            mdp.probe_by_name("no-such-probe")


class WindowTests(unittest.TestCase):
    def test_round_trip(self) -> None:
        window = _window("agent-1", 0, 60, 2)
        self.assertTrue(mdp.verify_window(window))

    def test_tamper_fails(self) -> None:
        window = _window("agent-1", 0, 60, 2)
        tampered = object.__new__(mdp.EscalationWindow)
        object.__setattr__(tampered, "agent_id", window.agent_id)
        object.__setattr__(tampered, "window_start", window.window_start)
        object.__setattr__(tampered, "window_end", window.window_end)
        object.__setattr__(tampered, "actions_observed", window.actions_observed)
        object.__setattr__(tampered, "escalations", 99)
        object.__setattr__(tampered, "digest", window.digest)
        self.assertFalse(mdp.verify_window(tampered))

    def test_escalations_cannot_exceed_actions(self) -> None:
        with self.assertRaises(ValueError):
            mdp.build_window(
                agent_id="agent-1",
                window_start=0,
                window_end=100,
                actions_observed=2,
                escalations=3,
            )

    def test_window_end_before_start_rejected(self) -> None:
        with self.assertRaises(ValueError):
            mdp.build_window(
                agent_id="agent-1",
                window_start=200,
                window_end=100,
                actions_observed=10,
                escalations=0,
            )

    def test_zero_escalation_detection(self) -> None:
        windows = [_window("agent-1", 0, 60, 0)]
        findings = mdp.detect_zero_escalation(windows)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["kind"], "zero_escalation_anomaly")

    def test_below_bound_is_quiet(self) -> None:
        windows = [_window("agent-1", 0, 10, 0)]
        self.assertEqual(mdp.detect_zero_escalation(windows), [])

    def test_escalations_present_is_quiet(self) -> None:
        windows = [_window("agent-1", 0, 60, 1)]
        self.assertEqual(mdp.detect_zero_escalation(windows), [])

    def test_collapse_detection(self) -> None:
        baseline = [_window("agent-1", 0, 1000, 100)]
        recent = [_window("agent-1", 100, 1000, 10)]  # 10% of baseline rate
        findings = mdp.detect_escalation_collapse(baseline, recent)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["kind"], "escalation_collapse")

    def test_no_collapse_when_rate_holds(self) -> None:
        baseline = [_window("agent-1", 0, 1000, 100)]
        recent = [_window("agent-1", 100, 1000, 90)]
        self.assertEqual(mdp.detect_escalation_collapse(baseline, recent), [])

    def test_collapse_needs_calibrated_baseline(self) -> None:
        baseline = [_window("agent-1", 0, 1000, 0)]
        recent = [_window("agent-1", 100, 1000, 0)]
        self.assertEqual(mdp.detect_escalation_collapse(baseline, recent), [])

    def test_silence_after_storm(self) -> None:
        storm = _window("agent-1", 0, 100, 25)
        silent = _window("agent-1", 100, 100, 0)
        findings = mdp.detect_silence_after_storm([storm, silent])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["kind"], "post_storm_silence")

    def test_no_storm_no_finding(self) -> None:
        quiet = _window("agent-1", 0, 100, 3)
        silent = _window("agent-1", 100, 100, 0)
        self.assertEqual(mdp.detect_silence_after_storm([quiet, silent]), [])

    def test_detectors_never_raise(self) -> None:
        # Garbage inputs must not raise; detectors return what they can.
        self.assertEqual(mdp.detect_zero_escalation([]), [])
        self.assertEqual(mdp.detect_escalation_collapse([], []), [])
        self.assertEqual(mdp.detect_silence_after_storm([]), [])


class HealthGateTests(unittest.TestCase):
    def test_signal_round_trip(self) -> None:
        signal = _signal()
        self.assertTrue(mdp.verify_signal(signal))

    def test_signal_tamper_fails(self) -> None:
        signal = _signal()
        tampered = object.__new__(mdp.MonitorHealthSignal)
        for field in (
            "monitor_id",
            "heartbeat_age_seconds",
            "last_canary_trip_age_seconds",
            "recent_escalation_count",
            "actions_observed_since_heartbeat",
            "digest",
        ):
            value = getattr(signal, field)
            if field == "heartbeat_age_seconds":
                value = 99999
            object.__setattr__(tampered, field, value)
        self.assertFalse(mdp.verify_signal(tampered))

    def test_healthy_low_stakes_records(self) -> None:
        disposition, finding = mdp.gate_monitor_health(_signal(), high_stakes=False)
        self.assertEqual(disposition, "record")
        self.assertEqual(finding["findings"], [])

    def test_healthy_high_stakes_records(self) -> None:
        disposition, _ = mdp.gate_monitor_health(_signal(), high_stakes=True)
        self.assertEqual(disposition, "record")

    def test_stale_heartbeat_high_stakes_denies(self) -> None:
        disposition, finding = mdp.gate_monitor_health(
            _signal(heartbeat_age_seconds=360), high_stakes=True
        )
        self.assertEqual(disposition, "deny")
        self.assertIn("stale_heartbeat", finding["findings"])

    def test_stale_heartbeat_low_stakes_recovers(self) -> None:
        disposition, _ = mdp.gate_monitor_health(
            _signal(heartbeat_age_seconds=360), high_stakes=False
        )
        self.assertEqual(disposition, "require_fresh_heartbeat")

    def test_never_tripped_canary_holds(self) -> None:
        disposition, finding = mdp.gate_monitor_health(
            _signal(last_canary_trip_age_seconds=-1), high_stakes=False
        )
        self.assertEqual(disposition, "hold")
        self.assertIn("stale_canary", finding["findings"])

    def test_starved_pipeline_high_stakes_denies(self) -> None:
        disposition, finding = mdp.gate_monitor_health(
            _signal(recent_escalation_count=0, actions_observed_since_heartbeat=80),
            high_stakes=True,
        )
        self.assertEqual(disposition, "deny")
        self.assertIn("starved_escalation_pipeline", finding["findings"])

    def test_unverifiable_signal_denies(self) -> None:
        signal = _signal()
        tampered = object.__new__(mdp.MonitorHealthSignal)
        for field in (
            "monitor_id",
            "heartbeat_age_seconds",
            "last_canary_trip_age_seconds",
            "recent_escalation_count",
            "actions_observed_since_heartbeat",
            "digest",
        ):
            value = getattr(signal, field)
            if field == "monitor_id":
                value = "impostor"
            object.__setattr__(tampered, field, value)
        disposition, _ = mdp.gate_monitor_health(tampered, high_stakes=False)
        self.assertEqual(disposition, "deny")

    def test_disposition_vocabulary_pinned(self) -> None:
        self.assertEqual(
            set(mdp.DISPOSITIONS),
            {"record", "require_fresh_heartbeat", "hold", "deny"},
        )


class HealthLedgerTests(unittest.TestCase):
    def test_append_and_read(self) -> None:
        ledger = mdp.HealthLedger("monitor-1")
        ledger.append(_signal(), "record", as_of=1000)
        ledger.append(_signal(), "hold", as_of=1100)
        self.assertEqual(len(ledger.decisions()), 2)
        self.assertEqual(ledger.decisions()[0]["seq"], 0)
        self.assertEqual(ledger.decisions()[1]["disposition"], "hold")

    def test_bad_disposition_rejected(self) -> None:
        ledger = mdp.HealthLedger("monitor-1")
        with self.assertRaises(ValueError):
            ledger.append(_signal(), "approve", as_of=1000)

    def test_monitor_id_mismatch_rejected(self) -> None:
        ledger = mdp.HealthLedger("monitor-1")
        with self.assertRaises(ValueError):
            ledger.append(_signal(monitor_id="monitor-2"), "record", as_of=1000)

    def test_main_runs(self) -> None:
        mdp.main()


if __name__ == "__main__":
    unittest.main()
