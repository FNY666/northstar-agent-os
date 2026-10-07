"""Tests for enforcement-gap probes, controller enforcement, P0 wiring validation."""

import unittest

import enforcement_gap_probes as eg


def _rec(severity="blocking", target="tool:shell/sha256:abc"):
    return eg.DetectionRecord(
        detector_id="detector-1",
        severity=severity,
        target=target,
        detail_digest="sha256:" + "0" * 64,
    )


def _dec(action="block", binding=True):
    return eg.EnforcementDecision(
        action=action, reason="controller decision", binding=binding
    )


class TestVersion(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(eg.ENFORCEMENT_GAP_VERSION, "enforcement-gap.v1")
        self.assertEqual(eg.SCHEMA_PIN, "northstar.enforcement-gap.v1")


class TestCorpusShape(unittest.TestCase):
    def test_counts(self):
        self.assertEqual(len(eg.probe_names()), 8)
        self.assertEqual(len(eg.benign_names()), 2)
        self.assertEqual(len(eg.ENFORCEMENT_GAP_PROBES), 10)

    def test_source_matches(self):
        self.assertEqual(
            list(eg.ENFORCEMENT_GAP_SOURCE["probes"]),
            [p["probe"] for p in eg.ENFORCEMENT_GAP_PROBES],
        )

    def test_probe_fields_complete(self):
        for p in eg.ENFORCEMENT_GAP_PROBES:
            for f in ("probe", "family", "attack", "gate_interaction", "expected", "reason"):
                self.assertIn(f, p, p["probe"])

    def test_name_uniqueness(self):
        names = [p["probe"] for p in eg.ENFORCEMENT_GAP_PROBES]
        self.assertEqual(len(names), len(set(names)))

    def test_attack_probes_expected_deny(self):
        for name in eg.probe_names():
            self.assertEqual(eg.probe_by_name(name)["expected"], "deny", name)

    def test_benign_probes_expected_allow(self):
        for name in eg.benign_names():
            self.assertEqual(eg.probe_by_name(name)["expected"], "allow", name)

    def test_attack_probes_have_attack_text(self):
        for name in eg.probe_names():
            self.assertIsNotNone(eg.probe_by_name(name)["attack"], name)

    def test_deny_side_keywords_in_gate_interaction(self):
        for p in eg.ENFORCEMENT_GAP_PROBES:
            self.assertTrue(
                eg.deny_side_keywords_ok(p["gate_interaction"]), p["probe"]
            )

    def test_probe_by_name_unknown_fail_closed(self):
        with self.assertRaises(KeyError):
            eg.probe_by_name("no-such-probe")


class TestEnforce(unittest.TestCase):
    def test_blocking_detection_with_block_is_enforced(self):
        v = eg.enforce(_rec("blocking"), _dec("block"), caller="gate")
        self.assertTrue(v.enforced)
        self.assertFalse(v.gap)

    def test_blocking_detection_without_decision_is_gap_and_fail_closed(self):
        v = eg.enforce(_rec("blocking"), None, caller="gate")
        self.assertTrue(v.gap)
        self.assertTrue(v.fail_closed_block)
        self.assertFalse(v.enforced)

    def test_blocking_detection_with_proceed_is_gap(self):
        v = eg.enforce(_rec("blocking"), _dec("proceed"), caller="gate")
        self.assertTrue(v.gap)
        self.assertTrue(v.fail_closed_block)

    def test_blocking_detection_advisory_block_is_gap(self):
        v = eg.enforce(_rec("blocking"), _dec("block", binding=False), caller="gate")
        self.assertTrue(v.gap)
        self.assertTrue(v.fail_closed_block)

    def test_blocking_detection_with_hold_is_enforced(self):
        v = eg.enforce(_rec("blocking"), _dec("hold"), caller="gate")
        self.assertTrue(v.enforced)
        self.assertFalse(v.gap)

    def test_warning_proceed_is_not_gap(self):
        v = eg.enforce(_rec("warning"), _dec("proceed"), caller="gate")
        self.assertFalse(v.gap)
        self.assertFalse(v.fail_closed_block)

    def test_warning_missing_decision_is_gap(self):
        v = eg.enforce(_rec("warning"), None, caller="gate")
        self.assertTrue(v.gap)
        self.assertFalse(v.fail_closed_block)

    def test_info_is_never_gap(self):
        v = eg.enforce(_rec("info"), None, caller="gate")
        self.assertFalse(v.gap)

    def test_verdict_digest_verifies(self):
        v = eg.enforce(_rec("blocking"), _dec("block"), caller="gate")
        self.assertTrue(eg.verify_verdict(v))

    def test_verdict_tamper_detected(self):
        v = eg.enforce(_rec("blocking"), _dec("block"), caller="gate")
        tampered = eg.EnforcementVerdict(
            record_digest=v.record_digest,
            decision_action="proceed",
            enforced=v.enforced,
            gap=v.gap,
            fail_closed_block=v.fail_closed_block,
            digest=v.digest,
        )
        self.assertFalse(eg.verify_verdict(tampered))

    def test_detection_record_fail_closed_validation(self):
        with self.assertRaises(ValueError):
            eg.DetectionRecord(
                detector_id="d",
                severity="critical",
                target="t",
                detail_digest="sha256:" + "0" * 64,
            )
        with self.assertRaises(ValueError):
            eg.DetectionRecord(
                detector_id="d",
                severity="blocking",
                target="t",
                detail_digest="not-a-digest",
            )

    def test_decision_fail_closed_validation(self):
        with self.assertRaises(ValueError):
            eg.EnforcementDecision(action="nuke", reason="x")


class TestWiringValidation(unittest.TestCase):
    def _binding(self, module="tool-allowlist", capability="tool-policy",
                call_site="action_gateway.dispatch", kind="gate", advisory=False):
        return eg.WiringBinding(
            module=module, capability=capability, call_site=call_site,
            binding_kind=kind, advisory=advisory,
        )

    def test_wired_module_passes(self):
        r = eg.validate_wiring(
            [("tool-allowlist", "tool-policy")], [self._binding()]
        )
        self.assertTrue(r.ok)
        self.assertEqual(r.gap_modules(), ())
        self.assertTrue(r.module_ok("tool-allowlist"))

    def test_unwired_module_is_gap(self):
        r = eg.validate_wiring(
            [("ghost-detector", "anomaly-flag")], [self._binding()]
        )
        self.assertFalse(r.ok)
        self.assertIn("ghost-detector", r.gap_modules())
        self.assertTrue(
            any("not-wired" in g for g in r.module_gaps("ghost-detector"))
        )

    def test_audit_only_binding_is_gap(self):
        r = eg.validate_wiring(
            [("tool-allowlist", "tool-policy")],
            [self._binding(kind="audit-only")],
        )
        self.assertFalse(r.ok)
        self.assertIn("tool-allowlist", r.gap_modules())
        self.assertTrue(
            any("audit-only" in g for g in r.module_gaps("tool-allowlist"))
        )

    def test_advisory_binding_is_gap(self):
        r = eg.validate_wiring(
            [("tool-allowlist", "tool-policy")],
            [self._binding(advisory=True)],
        )
        self.assertFalse(r.ok)
        self.assertTrue(
            any("advisory" in g for g in r.module_gaps("tool-allowlist"))
        )

    def test_binding_kind_validation_fail_closed(self):
        with self.assertRaises(ValueError):
            eg.WiringBinding(
                module="m", capability="c", call_site="s", binding_kind="vibes"
            )

    def test_empty_call_site_is_gap(self):
        r = eg.validate_wiring(
            [("tool-allowlist", "tool-policy")],
            [self._binding(call_site="")],
        )
        self.assertFalse(r.ok)

    def test_receipt_emission_binding_passes(self):
        r = eg.validate_wiring(
            [("receipt-gate", "output-receipt")],
            [self._binding(
                module="receipt-gate", capability="output-receipt",
                call_site="runner.emit", kind="receipt-emission",
            )],
        )
        self.assertTrue(r.ok)


if __name__ == "__main__":
    unittest.main()
