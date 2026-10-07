"""Tests for planner_executor_seam_probes."""

import unittest

import planner_executor_seam_probes as pes


def _digest(obj):
    return pes._digest(obj)


def _plan_digest():
    return _digest({"plan": "p-1"})


def _make_handoff(**over):
    kw = dict(
        handoff_id="h-1",
        proposal_id="p-1",
        revision=1,
        plan_digest=_plan_digest(),
        planner_id="planner-1",
        executor_id="executor-1",
        authority_ceiling=("tool.read",),
        parent_ceiling=(),
        seam_verdict="admit",
        decided_by="gov-1",
        reason="ok",
    )
    kw.update(over)
    return pes.SeamHandoff(**kw)


def _raw_handoff(**over):
    """Build a handoff then mutate fields raw, recomputing the digest.

    Bypasses the fail-closed constructor so integrity-sweep findings
    (self_handoff, verdict_by_planner, missing_verdict) can be
    exercised on records that still verify.
    """
    h = _make_handoff()
    for k, v in over.items():
        object.__setattr__(h, k, v)
    object.__setattr__(h, "digest", _digest(h._canonical()))
    return h


def _plan_actions():
    return (
        pes.PlannedAction(
            tool="tool.read", arguments_digest=_digest({"q": 1}), seq=0
        ),
        pes.PlannedAction(
            tool="tool.write", arguments_digest=_digest({"q": 2}), seq=1
        ),
    )


class CorpusShapeTests(unittest.TestCase):
    def test_counts(self):
        self.assertEqual(len(pes.attack_names()), 10)
        self.assertEqual(len(pes.benign_names()), 3)
        self.assertEqual(len(pes.probe_names()), 13)

    def test_unique_names(self):
        names = pes.probe_names()
        self.assertEqual(len(set(names)), len(names))

    def test_required_keys(self):
        for p in pes.PLANNER_EXECUTOR_SEAM_PROBES:
            for key in ("probe", "family", "attack", "gate_interaction", "expected", "reason"):
                self.assertIn(key, p, p["probe"])
            self.assertIn(p["expected"], ("deny", "allow"))

    def test_attack_probes_invoke_deny_side(self):
        for name in pes.attack_names():
            probe = pes.probe_by_name(name)
            self.assertTrue(
                pes.probe_invokes_deny_side(probe),
                f"{name} gate_interaction names no deny-side mechanism",
            )

    def test_unknown_probe_raises(self):
        with self.assertRaises(KeyError):
            pes.probe_by_name("no-such-probe")

    def test_version_pinned(self):
        self.assertEqual(pes.PLANNER_EXECUTOR_SEAM_VERSION, "planner-executor-seam.v1")


class HandoffRecordTests(unittest.TestCase):
    def test_digest_round_trip(self):
        h = _make_handoff()
        self.assertTrue(h.verify())

    def test_tampered_handoff_fails_verify(self):
        h = _make_handoff()
        object.__setattr__(h, "reason", "changed")
        self.assertFalse(h.verify())

    def test_self_handoff_rejected_at_construction(self):
        with self.assertRaises(ValueError):
            _make_handoff(planner_id="same", executor_id="same")

    def test_admit_by_planner_rejected(self):
        with self.assertRaises(ValueError):
            _make_handoff(decided_by="planner-1")

    def test_admit_by_executor_rejected(self):
        with self.assertRaises(ValueError):
            _make_handoff(decided_by="executor-1")

    def test_empty_executor_rejected(self):
        with self.assertRaises(ValueError):
            _make_handoff(executor_id="")

    def test_bad_plan_digest_rejected(self):
        with self.assertRaises(ValueError):
            _make_handoff(plan_digest="not-a-digest")

    def test_widens_ceiling(self):
        h = _make_handoff(
            authority_ceiling=("tool.read", "payments.refund"),
            parent_ceiling=("tool.read",),
        )
        self.assertTrue(h.widens_ceiling())

    def test_root_grant_cannot_widen(self):
        h = _make_handoff(authority_ceiling=("anything",), parent_ceiling=())
        self.assertFalse(h.widens_ceiling())

    def test_subset_ceiling_ok(self):
        h = _make_handoff(
            authority_ceiling=("tool.read",),
            parent_ceiling=("tool.read", "tool.write"),
        )
        self.assertFalse(h.widens_ceiling())


class SeamGateTests(unittest.TestCase):
    def test_admit_and_dispatch_end_to_end(self):
        gate = pes.SeamGate()
        gate.admit_handoff(_make_handoff())
        auth = gate.authorize_dispatch(
            proposal_id="p-1",
            revision=1,
            tool="tool.read",
            arguments_digest=_digest({"q": 1}),
            executor_id="executor-1",
            plan_actions=_plan_actions(),
        )
        self.assertTrue(auth.verify())
        self.assertEqual(auth.executor_id, "executor-1")

    def test_bad_digest_handoff_rejected(self):
        gate = pes.SeamGate()
        h = _make_handoff()
        object.__setattr__(h, "reason", "tampered")
        with self.assertRaises(ValueError):
            gate.admit_handoff(h)

    def test_non_admit_verdict_rejected(self):
        gate = pes.SeamGate()
        with self.assertRaises(ValueError):
            gate.admit_handoff(_make_handoff(seam_verdict="hold"))

    def test_widening_ceiling_rejected(self):
        gate = pes.SeamGate()
        with self.assertRaises(ValueError):
            gate.admit_handoff(
                _make_handoff(
                    authority_ceiling=("tool.read", "payments.refund"),
                    parent_ceiling=("tool.read",),
                )
            )

    def test_revision_replay_rejected(self):
        gate = pes.SeamGate()
        gate.admit_handoff(_make_handoff(handoff_id="h-1", revision=1))
        with self.assertRaises(ValueError):
            gate.admit_handoff(_make_handoff(handoff_id="h-2", revision=1))

    def test_higher_revision_supersedes(self):
        gate = pes.SeamGate()
        gate.admit_handoff(_make_handoff(handoff_id="h-1", revision=1))
        gate.admit_handoff(_make_handoff(handoff_id="h-2", revision=2))
        self.assertEqual(gate.current("p-1").revision, 2)

    def test_dispatch_wrong_executor_rejected(self):
        gate = pes.SeamGate()
        gate.admit_handoff(_make_handoff())
        with self.assertRaises(ValueError):
            gate.authorize_dispatch(
                proposal_id="p-1",
                revision=1,
                tool="tool.read",
                arguments_digest=_digest({"q": 1}),
                executor_id="executor-2",
                plan_actions=_plan_actions(),
            )

    def test_dispatch_unproposed_action_rejected(self):
        gate = pes.SeamGate()
        gate.admit_handoff(_make_handoff())
        with self.assertRaises(ValueError):
            gate.authorize_dispatch(
                proposal_id="p-1",
                revision=1,
                tool="tool.evil",
                arguments_digest=_digest({"q": 9}),
                executor_id="executor-1",
                plan_actions=_plan_actions(),
            )

    def test_dispatch_superseded_revision_rejected(self):
        gate = pes.SeamGate()
        gate.admit_handoff(_make_handoff(handoff_id="h-1", revision=1))
        gate.admit_handoff(_make_handoff(handoff_id="h-2", revision=2))
        with self.assertRaises(ValueError):
            gate.authorize_dispatch(
                proposal_id="p-1",
                revision=1,
                tool="tool.read",
                arguments_digest=_digest({"q": 1}),
                executor_id="executor-1",
                plan_actions=_plan_actions(),
            )

    def test_dispatch_no_handoff_rejected(self):
        gate = pes.SeamGate()
        with self.assertRaises(ValueError):
            gate.authorize_dispatch(
                proposal_id="p-1",
                revision=1,
                tool="tool.read",
                arguments_digest=_digest({"q": 1}),
                executor_id="executor-1",
                plan_actions=_plan_actions(),
            )


class IntegritySweepTests(unittest.TestCase):
    def test_clean_list_ok(self):
        ok, findings = pes.verify_seam_integrity([_make_handoff()])
        self.assertTrue(ok)
        self.assertEqual(findings, ())

    def test_empty_list_ok(self):
        ok, findings = pes.verify_seam_integrity(())
        self.assertTrue(ok)
        self.assertEqual(findings, ())

    def test_bad_digest_finding(self):
        h = _make_handoff()
        object.__setattr__(h, "reason", "tampered")
        ok, findings = pes.verify_seam_integrity([h])
        self.assertFalse(ok)
        self.assertEqual(findings[0].kind, "bad_digest")

    def test_self_handoff_finding(self):
        h = _raw_handoff(planner_id="executor-1")
        ok, findings = pes.verify_seam_integrity([h])
        self.assertFalse(ok)
        self.assertTrue(any(f.kind == "self_handoff" for f in findings))

    def test_verdict_by_planner_finding(self):
        h = _raw_handoff(decided_by="planner-1")
        ok, findings = pes.verify_seam_integrity([h])
        self.assertFalse(ok)
        self.assertTrue(any(f.kind == "verdict_by_planner" for f in findings))

    def test_verdict_by_executor_finding(self):
        h = _raw_handoff(decided_by="executor-1")
        ok, findings = pes.verify_seam_integrity([h])
        self.assertFalse(ok)
        self.assertTrue(any(f.kind == "verdict_by_executor" for f in findings))

    def test_ceiling_widened_finding(self):
        h = _make_handoff(
            authority_ceiling=("tool.read", "payments.refund"),
            parent_ceiling=("tool.read",),
        )
        ok, findings = pes.verify_seam_integrity([h])
        self.assertFalse(ok)
        self.assertTrue(any(f.kind == "ceiling_widened" for f in findings))

    def test_missing_verdict_finding(self):
        h = _raw_handoff(seam_verdict="")
        ok, findings = pes.verify_seam_integrity([h])
        self.assertFalse(ok)
        self.assertTrue(any(f.kind == "missing_verdict" for f in findings))

    def test_revision_regression_finding(self):
        h1 = _make_handoff(handoff_id="h-1", revision=2)
        h2 = _make_handoff(handoff_id="h-2", revision=1)
        ok, findings = pes.verify_seam_integrity([h1, h2])
        self.assertFalse(ok)
        self.assertTrue(any(f.kind == "revision_regression" for f in findings))

    def test_never_raises(self):
        # A sweep over garbage must report, not raise.
        ok, findings = pes.verify_seam_integrity([_raw_handoff(seam_verdict="")])
        self.assertFalse(ok)
        self.assertGreater(len(findings), 0)

    def test_main(self):
        self.assertEqual(pes.main(), 0)


if __name__ == "__main__":
    unittest.main()
