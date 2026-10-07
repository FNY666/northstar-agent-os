"""Tests for pre_completion_signal_probes.py."""

import unittest

import pre_completion_signal_probes as pcs


def _args_digest() -> str:
    return pcs._digest({"args": "v1"})


def _reading(**over) -> pcs.SignalReading:
    kw = {
        "signal_id": "sig-1",
        "signal_name": "latent-uncertainty",
        "value": 0.2,
        "call_id": "call-1",
        "arguments_digest": _args_digest(),
        "sequence": 3,
        "origin": "host-instrumented",
        "policy_revision": "rev-1",
    }
    kw.update(over)
    return pcs.SignalReading(**kw)


def _policy(**over) -> pcs.SignalPolicy:
    kw = {
        "trip_threshold": 0.7,
        "mandatory_classes": ("payment", "deploy"),
        "revision": "rev-1",
    }
    kw.update(over)
    return pcs.SignalPolicy(**kw)


class CorpusShapeTests(unittest.TestCase):
    def test_names_unique(self):
        names = pcs.probe_names()
        self.assertEqual(len(names), len(set(names)))

    def test_counts(self):
        self.assertEqual(len(pcs.attack_names()), 10)
        self.assertEqual(len(pcs.benign_names()), 3)

    def test_required_keys(self):
        for p in pcs.PRE_COMPLETION_SIGNAL_PROBES:
            for key in ("probe", "family", "attack", "gate_interaction", "expected", "reason"):
                self.assertIn(key, p, p.get("probe"))
            self.assertIn(p["expected"], ("deny", "allow"))

    def test_attack_gate_interactions_invoke_deny_side(self):
        for p in pcs.PRE_COMPLETION_SIGNAL_PROBES:
            if p["expected"] == "deny":
                self.assertTrue(
                    pcs.probe_invokes_deny_side(p), p["probe"]
                )

    def test_probe_by_name(self):
        p = pcs.probe_by_name("signal-misuse-calm-clears")
        self.assertEqual(p["family"], "signal-misuse")

    def test_probe_by_name_unknown_raises(self):
        with self.assertRaises(KeyError):
            pcs.probe_by_name("no-such-probe")

    def test_families(self):
        families = {p["family"] for p in pcs.PRE_COMPLETION_SIGNAL_PROBES}
        self.assertEqual(
            families,
            {"signal-suppression", "signal-absence", "signal-misuse", "benign"},
        )


class ReadingTests(unittest.TestCase):
    def test_round_trip_verifies(self):
        r = _reading()
        self.assertTrue(r.verify())
        self.assertTrue(r.well_formed())

    def test_tampered_value_fails_verify(self):
        r = _reading()
        object.__setattr__(r, "value", 0.99)
        self.assertFalse(r.verify())
        self.assertFalse(r.well_formed())

    def test_value_out_of_range_not_well_formed(self):
        for bad in (-0.1, 1.1):
            self.assertFalse(_reading(value=bad).well_formed())

    def test_bad_origin_not_well_formed(self):
        self.assertFalse(_reading(origin="vibes").well_formed())

    def test_bad_arguments_digest_not_well_formed(self):
        self.assertFalse(_reading(arguments_digest="nope").well_formed())

    def test_bound_to(self):
        r = _reading()
        self.assertTrue(r.bound_to("call-1", _args_digest()))
        self.assertFalse(r.bound_to("call-2", _args_digest()))

    def test_self_report_never_trips(self):
        r = _reading(origin="model-self-report", value=0.99)
        self.assertFalse(r.trips(0.7))

    def test_host_trips_at_threshold(self):
        self.assertTrue(_reading(value=0.7).trips(0.7))
        self.assertFalse(_reading(value=0.69).trips(0.7))

    def test_as_dict_round_trip(self):
        d = _reading().as_dict()
        self.assertEqual(d["signal_id"], "sig-1")
        self.assertTrue(d["digest"].startswith("sha256:"))


class PolicyTests(unittest.TestCase):
    def test_bad_threshold_raises(self):
        for bad in (0.0, 1.5, "high", True):
            with self.assertRaises(ValueError):
                _policy(trip_threshold=bad)

    def test_empty_revision_raises(self):
        with self.assertRaises(ValueError):
            _policy(revision="")


class EvaluateTests(unittest.TestCase):
    def _eval(self, policy=None, readings=(), **kw):
        args = {
            "policy": policy or _policy(),
            "call_id": "call-1",
            "arguments_digest": _args_digest(),
            "action_class": "query",
            "dispatch_sequence": 10,
            "readings": readings,
        }
        args.update(kw)
        return pcs.evaluate(**args)

    def test_calm_proceeds(self):
        ev = self._eval(readings=(_reading(value=0.2),))
        self.assertEqual(ev.verdict, "proceed")
        self.assertEqual(ev.findings, ())
        self.assertTrue(ev.verify())

    def test_trip_holds(self):
        ev = self._eval(readings=(_reading(value=0.93),))
        self.assertEqual(ev.verdict, "hold")
        self.assertIn("signal-trip", ev.findings)
        self.assertTrue(ev.verify())

    def test_conflict_holds_with_conflict_finding(self):
        ev = self._eval(
            readings=(
                _reading(signal_id="a", value=0.87),
                _reading(signal_id="b", signal_name="semantic-entropy", value=0.12),
            )
        )
        self.assertEqual(ev.verdict, "hold")
        self.assertIn("signal-conflict", ev.findings)

    def test_missing_mandatory_signal_holds(self):
        ev = self._eval(action_class="payment", readings=())
        self.assertEqual(ev.verdict, "hold")
        self.assertIn("missing-signal", ev.findings)

    def test_non_mandatory_class_no_readings_proceeds(self):
        ev = self._eval(action_class="query", readings=())
        self.assertEqual(ev.verdict, "proceed")

    def test_unbound_reading_rejects(self):
        ev = self._eval(readings=(_reading(call_id="other-call"),))
        self.assertEqual(ev.verdict, "reject")
        self.assertIn("unbound-reading", ev.findings)

    def test_tampered_reading_rejects(self):
        r = _reading()
        object.__setattr__(r, "value", 0.99)
        ev = self._eval(readings=(r,))
        self.assertEqual(ev.verdict, "reject")
        self.assertIn("unverifiable-reading", ev.findings)

    def test_post_hoc_reading_excluded(self):
        ev = self._eval(
            readings=(_reading(sequence=10, value=0.95),),
            dispatch_sequence=10,
        )
        self.assertEqual(ev.verdict, "proceed")
        self.assertIn("post-hoc-signal", ev.findings)

    def test_revision_mismatch_excluded(self):
        ev = self._eval(readings=(_reading(policy_revision="rev-2", value=0.95),))
        self.assertEqual(ev.verdict, "proceed")
        self.assertIn("revision-mismatch", ev.findings)

    def test_self_report_never_trips(self):
        ev = self._eval(
            readings=(_reading(origin="model-self-report", value=0.99),)
        )
        self.assertEqual(ev.verdict, "proceed")
        self.assertIn("self-reported-signal", ev.findings)
        self.assertNotIn("signal-trip", ev.findings)

    def test_verdict_vocabulary_has_no_allow(self):
        self.assertNotIn("allow", pcs.SIGNAL_VERDICTS)
        for p in pcs.PRE_COMPLETION_SIGNAL_PROBES:
            pass  # corpus verdicts are deny/allow on probes, not channel auth
        ev = self._eval(readings=(_reading(value=0.05),))
        self.assertNotEqual(ev.verdict, "allow")


class AbstainPathTests(unittest.TestCase):
    def test_hold_requires_abstain_path(self):
        ev = pcs.evaluate(
            policy=_policy(),
            call_id="call-1",
            arguments_digest=_args_digest(),
            action_class="query",
            dispatch_sequence=10,
            readings=(_reading(value=0.93),),
        )
        self.assertTrue(pcs.requires_abstain_path(ev))

    def test_proceed_does_not(self):
        ev = pcs.evaluate(
            policy=_policy(),
            call_id="call-1",
            arguments_digest=_args_digest(),
            action_class="query",
            dispatch_sequence=10,
            readings=(_reading(value=0.2),),
        )
        self.assertFalse(pcs.requires_abstain_path(ev))

    def test_reject_does_not_take_human_path(self):
        ev = pcs.evaluate(
            policy=_policy(),
            call_id="call-1",
            arguments_digest=_args_digest(),
            action_class="query",
            dispatch_sequence=10,
            readings=(_reading(call_id="other"),),
        )
        self.assertEqual(ev.verdict, "reject")
        self.assertFalse(pcs.requires_abstain_path(ev))

    def test_tampered_evaluation_requires_abstain_path(self):
        ev = pcs.evaluate(
            policy=_policy(),
            call_id="call-1",
            arguments_digest=_args_digest(),
            action_class="query",
            dispatch_sequence=10,
            readings=(_reading(value=0.2),),
        )
        object.__setattr__(ev, "verdict", "proceed-x")
        self.assertTrue(pcs.requires_abstain_path(ev))

    def test_main_runs(self):
        pcs.main()


if __name__ == "__main__":
    unittest.main()
