"""Tests for run_assert_eval_probes."""

import unittest

import run_assert_eval_probes as rae


def _digest(obj):
    return rae._digest(obj)


def _eval_set(**over):
    kw = dict(
        set_id="fixed-set",
        version="1",
        corpus_digest=_digest({"corpus": "v1"}),
    )
    kw.update(over)
    return rae.EvalSet(**kw)


def _axes(*verdicts):
    names = ("tool-call-safety", "exfiltration-resistance", "approval-binding")
    return tuple(
        rae.AxisVerdict(axis=n, verdict=v, detail="d") for n, v in zip(names, verdicts)
    )


def _run(**over):
    kw = dict(
        run_id="run-1",
        set_id="fixed-set",
        set_digest=_digest({"corpus": "v1"}),
        policy_digest=_digest({"policy": "p1"}),
        harness_digest=_digest({"harness": "h1"}),
        kind="initial",
        axis_verdicts=_axes("pass", "pass", "pass"),
    )
    kw.update(over)
    return rae.RunRecord(**kw)


def _assertion(**over):
    kw = dict(
        assertion_id="a-1",
        source_run_id="run-1",
        source_run_digest=_run().digest,
        axis="tool-call-safety",
        predicate="deny calls whose args carry credential values",
        falsifier="a denied call whose args carried no credential value",
    )
    kw.update(over)
    return rae.PolicyAssertion(**kw)


def _raw_run(**over):
    """Build a run then mutate fields raw, recomputing the digest.

    Bypasses the fail-closed constructor so integrity-sweep findings
    (set_drifted, unanchored_verdict, composite_score) can be exercised
    on records that still verify.
    """
    r = _run()
    for k, v in over.items():
        if k == "_extra_attrs":
            continue
        object.__setattr__(r, k, v)
    for k, v in over.get("_extra_attrs", {}).items():
        object.__setattr__(r, k, v)
    object.__setattr__(r, "digest", _digest(r._canonical()))
    return r


def _raw_assertion(**over):
    a = _assertion()
    for k, v in over.items():
        object.__setattr__(a, k, v)
    object.__setattr__(a, "digest", _digest(a._canonical()))
    return a


def _gate_with_loop(policy="p1", reeval_verdicts=("pass", "pass", "pass")):
    gate = rae.RunAssertGate()
    gate.register_set(_eval_set())
    gate.record_run(_run())
    gate.record_assertion(_assertion())
    gate.record_run(
        _run(
            run_id="run-2",
            kind="reeval",
            policy_digest=_digest({"policy": policy}),
            axis_verdicts=_axes(*reeval_verdicts),
        )
    )
    return gate


class CorpusShapeTests(unittest.TestCase):
    def test_counts(self):
        self.assertEqual(len(rae.attack_names()), 10)
        self.assertEqual(len(rae.benign_names()), 3)
        self.assertEqual(len(rae.probe_names()), 13)

    def test_unique_names(self):
        names = rae.probe_names()
        self.assertEqual(len(set(names)), len(names))

    def test_required_keys(self):
        for p in rae.RUN_ASSERT_EVAL_PROBES:
            for key in (
                "probe",
                "family",
                "attack",
                "gate_interaction",
                "expected",
                "reason",
            ):
                self.assertIn(key, p, p["probe"])
            self.assertIn(p["expected"], ("deny", "allow"))

    def test_attack_probes_invoke_deny_side(self):
        for name in rae.attack_names():
            probe = rae.probe_by_name(name)
            self.assertTrue(
                rae.probe_invokes_deny_side(probe),
                f"{name} gate_interaction names no deny-side mechanism",
            )

    def test_probe_by_name_unknown(self):
        with self.assertRaises(KeyError):
            rae.probe_by_name("no-such-probe")

    def test_families(self):
        families = {p["family"] for p in rae.RUN_ASSERT_EVAL_PROBES}
        self.assertEqual(
            families, {"loop-shortcircuit", "assertion-integrity", "evidence-binding"}
        )


class EvalSetTests(unittest.TestCase):
    def test_verify_round_trip(self):
        self.assertTrue(_eval_set().verify())

    def test_empty_set_id_rejected(self):
        with self.assertRaises(ValueError):
            _eval_set(set_id="")

    def test_bad_corpus_digest_rejected(self):
        with self.assertRaises(ValueError):
            _eval_set(corpus_digest="ci-latest")

    def test_tampered_digest_fails_verify(self):
        s = _eval_set()
        object.__setattr__(s, "version", "2")
        self.assertFalse(s.verify())


class RunRecordTests(unittest.TestCase):
    def test_verify_round_trip(self):
        self.assertTrue(_run().verify())

    def test_all_pass(self):
        self.assertTrue(_run().all_pass())

    def test_all_pass_false_on_fail(self):
        self.assertFalse(_run(axis_verdicts=_axes("pass", "fail", "pass")).all_pass())

    def test_all_pass_false_on_hold(self):
        self.assertFalse(_run(axis_verdicts=_axes("pass", "hold", "pass")).all_pass())

    def test_duplicate_axes_rejected(self):
        with self.assertRaises(ValueError):
            _run(
                axis_verdicts=(
                    rae.AxisVerdict("a", "pass", "d"),
                    rae.AxisVerdict("a", "pass", "d"),
                )
            )

    def test_empty_axes_rejected(self):
        with self.assertRaises(ValueError):
            _run(axis_verdicts=())

    def test_bad_kind_rejected(self):
        with self.assertRaises(ValueError):
            _run(kind="final")

    def test_bad_axis_verdict_rejected(self):
        with self.assertRaises(ValueError):
            rae.AxisVerdict(axis="a", verdict="maybe", detail="d")

    def test_tampered_run_fails_verify(self):
        r = _run()
        object.__setattr__(r, "kind", "reeval")
        self.assertFalse(r.verify())


class PolicyAssertionTests(unittest.TestCase):
    def test_verify_round_trip(self):
        self.assertTrue(_assertion().verify())

    def test_empty_falsifier_rejected(self):
        with self.assertRaises(ValueError):
            _assertion(falsifier="")

    def test_falsifier_equal_to_predicate_rejected(self):
        with self.assertRaises(ValueError):
            _assertion(predicate="p", falsifier="p")

    def test_tampered_assertion_fails_verify(self):
        a = _assertion()
        object.__setattr__(a, "axis", "other")
        self.assertFalse(a.verify())


class GateTests(unittest.TestCase):
    def test_full_loop_green_deploys(self):
        gate = _gate_with_loop()
        auth = gate.request_deploy(_digest({"policy": "p1"}))
        self.assertTrue(auth.verify())
        self.assertEqual(auth.reeval_run_id, "run-2")

    def test_deploy_without_reeval_denied(self):
        gate = rae.RunAssertGate()
        gate.register_set(_eval_set())
        gate.record_run(_run())
        with self.assertRaises(ValueError):
            gate.request_deploy(_digest({"policy": "p1"}))

    def test_stale_green_reeval_denied(self):
        gate = _gate_with_loop(policy="p1")
        with self.assertRaises(ValueError):
            gate.request_deploy(_digest({"policy": "p2-edited"}))

    def test_failing_reeval_denied(self):
        gate = _gate_with_loop(reeval_verdicts=("pass", "fail", "pass"))
        with self.assertRaises(ValueError):
            gate.request_deploy(_digest({"policy": "p1"}))

    def test_failing_initial_run_blocks_even_with_reeval(self):
        gate = rae.RunAssertGate()
        gate.register_set(_eval_set())
        initial = gate.record_run(_run(axis_verdicts=_axes("fail", "pass", "pass")))
        gate.record_assertion(_assertion(source_run_digest=initial.digest))
        gate.record_run(_run(run_id="run-2", kind="reeval"))
        # the re-eval passes, so the loop closed on the requested digest;
        # the failing initial run is the baseline, not a deployment blocker
        auth = gate.request_deploy(_digest({"policy": "p1"}))
        self.assertTrue(auth.verify())

    def test_drifted_set_run_denied(self):
        gate = rae.RunAssertGate()
        gate.register_set(_eval_set())
        with self.assertRaises(ValueError):
            gate.record_run(_run(set_digest=_digest({"corpus": "v2-edited"})))

    def test_set_drift_reregistration_denied(self):
        gate = rae.RunAssertGate()
        gate.register_set(_eval_set())
        with self.assertRaises(ValueError):
            gate.register_set(_eval_set(corpus_digest=_digest({"corpus": "v2"})))

    def test_orphan_assertion_denied(self):
        gate = rae.RunAssertGate()
        gate.register_set(_eval_set())
        with self.assertRaises(ValueError):
            gate.record_assertion(_assertion())

    def test_silent_regeneration_denied(self):
        gate = rae.RunAssertGate()
        gate.register_set(_eval_set())
        gate.record_run(_run())
        gate.record_assertion(_assertion())
        with self.assertRaises(ValueError):
            gate.record_assertion(_assertion(predicate="a different predicate"))

    def test_identical_rerecord_ok(self):
        gate = rae.RunAssertGate()
        gate.register_set(_eval_set())
        gate.record_run(_run())
        gate.record_assertion(_assertion())
        gate.record_assertion(_assertion())  # identical content: idempotent
        self.assertEqual(gate.assertion_count(), 1)

    def test_duplicate_run_id_denied(self):
        gate = rae.RunAssertGate()
        gate.register_set(_eval_set())
        gate.record_run(_run())
        with self.assertRaises(ValueError):
            gate.record_run(_run())

    def test_deploy_without_set_denied(self):
        gate = rae.RunAssertGate()
        with self.assertRaises(ValueError):
            gate.request_deploy(_digest({"policy": "p1"}))

    def test_malformed_policy_digest_denied(self):
        gate = _gate_with_loop()
        with self.assertRaises(ValueError):
            gate.request_deploy("v3-latest")


class IntegritySweepTests(unittest.TestCase):
    def test_clean_loop_ok(self):
        s = _eval_set()
        runs = (_run(), _run(run_id="run-2", kind="reeval"))
        assertions = (_assertion(),)
        ok, findings = rae.verify_loop_integrity(s, runs, assertions)
        self.assertTrue(ok)
        self.assertEqual(findings, ())

    def test_bad_digest(self):
        s = _eval_set()
        r = _run()
        object.__setattr__(r, "kind", "reeval")
        ok, findings = rae.verify_loop_integrity(s, (r,), ())
        self.assertFalse(ok)
        self.assertEqual(findings[0].kind, "bad_digest")

    def test_set_drifted(self):
        s = _eval_set()
        r = _raw_run(set_digest=_digest({"corpus": "v2-edited"}))
        ok, findings = rae.verify_loop_integrity(s, (r,), ())
        self.assertFalse(ok)
        kinds = {f.kind for f in findings}
        self.assertIn("set_drifted", kinds)

    def test_orphan_assertion(self):
        s = _eval_set()
        a = _assertion(source_run_digest=_digest({"run": "ghost"}))
        ok, findings = rae.verify_loop_integrity(s, (_run(),), (a,))
        self.assertFalse(ok)
        kinds = {f.kind for f in findings}
        self.assertIn("orphan_assertion", kinds)

    def test_tautology_assertion_empty_falsifier(self):
        s = _eval_set()
        a = _raw_assertion(falsifier="")
        ok, findings = rae.verify_loop_integrity(s, (_run(),), (a,))
        self.assertFalse(ok)
        kinds = {f.kind for f in findings}
        self.assertIn("tautology_assertion", kinds)

    def test_tautology_assertion_self_identical(self):
        s = _eval_set()
        a = _raw_assertion(predicate="p", falsifier="p")
        ok, findings = rae.verify_loop_integrity(s, (_run(),), (a,))
        self.assertFalse(ok)
        kinds = {f.kind for f in findings}
        self.assertIn("tautology_assertion", kinds)

    def test_composite_score(self):
        s = _eval_set()
        r = _raw_run(_extra_attrs={"score": 0.94})
        ok, findings = rae.verify_loop_integrity(s, (r,), ())
        self.assertFalse(ok)
        kinds = {f.kind for f in findings}
        self.assertIn("composite_score", kinds)

    def test_unanchored_verdict(self):
        s = _eval_set()
        r = _raw_run(policy_digest="v3-latest", harness_digest="ci-latest")
        ok, findings = rae.verify_loop_integrity(s, (r,), ())
        self.assertFalse(ok)
        kinds = {f.kind for f in findings}
        self.assertIn("unanchored_verdict", kinds)

    def test_finding_kind_validation(self):
        with self.assertRaises(ValueError):
            rae.LoopFinding(kind="nope", record_id="r", detail="d")

    def test_main(self):
        self.assertEqual(rae.main(), 0)


if __name__ == "__main__":
    unittest.main()
