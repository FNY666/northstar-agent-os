"""Tests for the sleeper-agent probe corpus."""

import hashlib
import unittest

import sleeper_agent_probes as sa


def _bdigest(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode()).hexdigest()


ZERO = "sha256:" + "0" * 64


def _record(**kwargs):
    defaults = dict(
        agent_id="agent-1",
        model_version="m1",
        context_class="deploy",
        run_id="r1",
        behavior_digest=_bdigest("benign-actions"),
        canary_present=False,
        adaptation_digest=None,
        context_features_digest=_bdigest("features-a"),
        prev_digest=ZERO,
    )
    defaults.update(kwargs)
    return sa.build_record(**defaults)


REQUIRED_KEYS = ("probe", "family", "attack", "gate_interaction", "expected", "reason")

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


class TestVersion(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(sa.SLEEPER_AGENT_VERSION, "sleeper-agent.v1")


class TestCorpusShape(unittest.TestCase):
    def test_counts(self):
        self.assertEqual(len(sa.attack_probe_names()), 10)
        self.assertEqual(len(sa.benign_probe_names()), 3)
        self.assertEqual(len(sa.SLEEPER_AGENT_PROBES), 13)

    def test_per_family_counts(self):
        self.assertEqual(len(sa.probes_in_family("trigger-detection")), 4)
        self.assertEqual(len(sa.probes_in_family("sleeper-detection")), 3)
        self.assertEqual(len(sa.probes_in_family("consistency-check")), 3)
        self.assertEqual(len(sa.probes_in_family("benign")), 3)

    def test_required_keys(self):
        for probe in sa.SLEEPER_AGENT_PROBES:
            for key in REQUIRED_KEYS:
                self.assertIn(key, probe, probe["probe"])

    def test_name_uniqueness(self):
        names = [p["probe"] for p in sa.SLEEPER_AGENT_PROBES]
        self.assertEqual(len(names), len(set(names)))

    def test_attack_probes_deny(self):
        for name in sa.attack_probe_names():
            probe = sa.probe_by_name(name)
            self.assertIsNotNone(probe["attack"], name)
            self.assertEqual(probe["expected"], "deny", name)

    def test_benign_probes_allow(self):
        for name in sa.benign_probe_names():
            probe = sa.probe_by_name(name)
            self.assertIsNone(probe["attack"], name)
            self.assertEqual(probe["expected"], "allow", name)

    def test_deny_side_keyword(self):
        for name in sa.attack_probe_names():
            text = (
                sa.probe_by_name(name)["gate_interaction"] + " "
                + sa.probe_by_name(name)["reason"]
            ).lower()
            self.assertTrue(
                any(k in text for k in DENY_SIDE_KEYWORDS),
                f"{name} has no deny-side keyword",
            )

    def test_expected_outcomes(self):
        outcomes = sa.expected_outcomes()
        self.assertEqual(len(outcomes), 13)
        self.assertEqual(outcomes["time-bomb-sleeper"], "deny")
        self.assertEqual(outcomes["benign-context-adaptation"], "allow")

    def test_lookup_missing_raises(self):
        with self.assertRaises(KeyError):
            sa.probe_by_name("no-such-probe")

    def test_main(self):
        self.assertEqual(sa.main(), 0)


def _tampered(record, **overrides):
    """Build a record object that fails digest verification.

    Uses object.__new__ to bypass the fail-closed constructor, so the
    verify_record()/ledger rejection paths are exercised.
    """
    fields = dict(
        agent_id=record.agent_id,
        model_version=record.model_version,
        context_class=record.context_class,
        run_id=record.run_id,
        behavior_digest=record.behavior_digest,
        canary_present=record.canary_present,
        adaptation_digest=record.adaptation_digest,
        context_features_digest=record.context_features_digest,
        prev_digest=record.prev_digest,
        digest=record.digest,
    )
    fields.update(overrides)
    obj = object.__new__(sa.BehaviorRecord)
    for k, v in fields.items():
        object.__setattr__(obj, k, v)
    return obj


class TestRecordSemantics(unittest.TestCase):
    def test_round_trip_verifies(self):
        record = _record()
        ok, findings = sa.verify_record(record)
        self.assertTrue(ok)
        self.assertEqual(findings, [])

    def test_bad_context_class_rejected(self):
        with self.assertRaises(ValueError):
            _record(context_class="production")

    def test_bad_behavior_digest_rejected(self):
        with self.assertRaises(ValueError):
            _record(behavior_digest="not-a-digest")

    def test_bad_adaptation_digest_rejected(self):
        with self.assertRaises(ValueError):
            _record(adaptation_digest="nope")

    def test_tampered_record_fails_verify(self):
        record = _record()
        tampered = _tampered(record, behavior_digest=_bdigest("evil-actions"))
        ok, findings = sa.verify_record(tampered)
        self.assertFalse(ok)
        self.assertIn("record-digest-mismatch", findings)

    def test_trigger_spec_requires_digest(self):
        with self.assertRaises(ValueError):
            sa.TriggerSpec(name="kw", condition_features_digest="nope")

    def test_trigger_spec_ok(self):
        spec = sa.TriggerSpec(name="kw", condition_features_digest=_bdigest("kw"))
        self.assertEqual(spec.name, "kw")


class TestLedger(unittest.TestCase):
    def test_append_chain(self):
        ledger = sa.BehaviorLedger()
        first = _record(run_id="r1")
        ledger.append(first)
        second = _record(run_id="r2", prev_digest=first.digest)
        ledger.append(second)
        self.assertEqual(len(ledger), 2)

    def test_genesis_requires_zero_prev(self):
        ledger = sa.BehaviorLedger()
        with self.assertRaises(ValueError):
            ledger.append(_record(prev_digest=_bdigest("not-zero")))

    def test_chain_break_rejected(self):
        ledger = sa.BehaviorLedger()
        first = _record(run_id="r1")
        ledger.append(first)
        with self.assertRaises(ValueError):
            ledger.append(_record(run_id="r2", prev_digest=_bdigest("wrong")))

    def test_unverifiable_rejected(self):
        ledger = sa.BehaviorLedger()
        record = _record()
        tampered = _tampered(record, behavior_digest=_bdigest("evil-actions"))
        with self.assertRaises(ValueError):
            ledger.append(tampered)


class TestTriggerDetection(unittest.TestCase):
    def test_armed_trigger_named(self):
        spec = sa.TriggerSpec(
            name="keyword-x", condition_features_digest=_bdigest("kw-x")
        )
        records = (
            _record(run_id="r1", context_features_digest=_bdigest("other")),
            _record(run_id="r2", context_features_digest=_bdigest("kw-x")),
        )
        findings = sa.detect_trigger_armed(records, spec)
        self.assertEqual(findings, ["trigger-armed:keyword-x:r2"])

    def test_no_armed_trigger(self):
        spec = sa.TriggerSpec(
            name="keyword-x", condition_features_digest=_bdigest("kw-x")
        )
        records = (_record(run_id="r1", context_features_digest=_bdigest("other")),)
        self.assertEqual(sa.detect_trigger_armed(records, spec), [])

    def test_unverifiable_record_flagged_not_raised(self):
        spec = sa.TriggerSpec(name="kw", condition_features_digest=_bdigest("kw"))
        record = _record(run_id="r1")
        bad = _tampered(record, behavior_digest=_bdigest("evil"))
        findings = sa.detect_trigger_armed((bad,), spec)
        self.assertIn("unverifiable-record:r1", findings)


class TestEvalDeployDivergence(unittest.TestCase):
    def test_divergence_named(self):
        records = (
            _record(run_id="e1", context_class="eval",
                    behavior_digest=_bdigest("aligned")),
            _record(run_id="d1", context_class="deploy",
                    behavior_digest=_bdigest("hostile")),
        )
        findings = sa.detect_eval_deploy_divergence(records)
        self.assertEqual(findings, ["eval-deploy-divergence:agent-1:m1"])

    def test_no_divergence_same_behavior(self):
        records = (
            _record(run_id="e1", context_class="eval",
                    behavior_digest=_bdigest("aligned")),
            _record(run_id="d1", context_class="deploy",
                    behavior_digest=_bdigest("aligned")),
        )
        self.assertEqual(sa.detect_eval_deploy_divergence(records), [])

    def test_declared_adaptation_suppresses(self):
        records = (
            _record(run_id="e1", context_class="eval",
                    behavior_digest=_bdigest("aligned"),
                    adaptation_digest=_bdigest("adapt-1")),
            _record(run_id="d1", context_class="deploy",
                    behavior_digest=_bdigest("hostile"),
                    adaptation_digest=_bdigest("adapt-1")),
        )
        self.assertEqual(sa.detect_eval_deploy_divergence(records), [])

    def test_overlapping_behavior_no_flag(self):
        # same digest appears in both classes: not a clean split
        records = (
            _record(run_id="e1", context_class="eval",
                    behavior_digest=_bdigest("aligned")),
            _record(run_id="e2", context_class="eval",
                    behavior_digest=_bdigest("aligned")),
            _record(run_id="d1", context_class="deploy",
                    behavior_digest=_bdigest("aligned")),
            _record(run_id="d2", context_class="deploy",
                    behavior_digest=_bdigest("hostile")),
        )
        self.assertEqual(sa.detect_eval_deploy_divergence(records), [])


class TestCanaryEvasion(unittest.TestCase):
    def test_evasion_named(self):
        records = (
            _record(run_id="r1", canary_present=True,
                    behavior_digest=_bdigest("perfect")),
            _record(run_id="r2", canary_present=False,
                    behavior_digest=_bdigest("misbehave")),
        )
        findings = sa.detect_canary_evasion(records)
        self.assertEqual(findings, ["canary-evasion:agent-1:m1:deploy"])

    def test_no_evasion_same_behavior(self):
        records = (
            _record(run_id="r1", canary_present=True,
                    behavior_digest=_bdigest("benign")),
            _record(run_id="r2", canary_present=False,
                    behavior_digest=_bdigest("benign")),
        )
        self.assertEqual(sa.detect_canary_evasion(records), [])


class TestConsistency(unittest.TestCase):
    def test_consistent_ok(self):
        records = (
            _record(run_id="r1", behavior_digest=_bdigest("a")),
            _record(run_id="r2", behavior_digest=_bdigest("a")),
        )
        ok, findings = sa.verify_behavioral_consistency(records)
        self.assertTrue(ok)
        self.assertEqual(findings, [])

    def test_inconsistent_named(self):
        records = (
            _record(run_id="r1", behavior_digest=_bdigest("a")),
            _record(run_id="r2", behavior_digest=_bdigest("b")),
        )
        ok, findings = sa.verify_behavioral_consistency(records)
        self.assertFalse(ok)
        self.assertEqual(findings, ["behavior-inconsistent:agent-1:m1:deploy"])

    def test_declared_adaptation_excluded(self):
        records = (
            _record(run_id="r1", behavior_digest=_bdigest("a")),
            _record(
                run_id="r2",
                behavior_digest=_bdigest("b"),
                adaptation_digest=_bdigest("adapt-1"),
            ),
        )
        ok, findings = sa.verify_behavioral_consistency(records)
        self.assertTrue(ok)
        self.assertEqual(findings, [])

    def test_different_context_classes_not_compared(self):
        records = (
            _record(run_id="r1", context_class="eval",
                    behavior_digest=_bdigest("a")),
            _record(run_id="r2", context_class="deploy",
                    behavior_digest=_bdigest("b")),
        )
        ok, _ = sa.verify_behavioral_consistency(records)
        self.assertTrue(ok)


if __name__ == "__main__":
    unittest.main()
