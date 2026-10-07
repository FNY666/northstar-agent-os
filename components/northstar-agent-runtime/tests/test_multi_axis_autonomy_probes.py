"""Tests for multi_axis_autonomy_probes."""

import hashlib
import json
import unittest

import multi_axis_autonomy_probes as maa


def _digest(obj):
    return "sha256:" + hashlib.sha256(
        json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        .encode("utf-8")
    ).hexdigest()


def _reading(action_id="a1", axis=maa.AXIS_REVERSIBILITY, risk=maa.RISK_LOW,
             revision="pol-1"):
    return maa.AxisReading(
        action_id=action_id,
        axis=axis,
        risk=risk,
        evidence_digest=_digest({"axis": axis, "risk": risk}),
        policy_revision=revision,
    ).pinned()


def _profile(action_id="a1", risks=None, revision="pol-1"):
    risks = risks or {}
    return maa.AxisProfile(
        action_id=action_id,
        readings=tuple(
            _reading(action_id, axis, risks.get(axis, maa.RISK_LOW), revision)
            for axis in maa.AXES
        ),
    ).pinned()


def _policy(ceilings=None, revision="pol-1"):
    ceilings = ceilings or {axis: maa.RISK_HIGH for axis in maa.AXES}
    return maa.AxisPolicy(
        policy_revision=revision,
        ceilings=tuple(sorted(ceilings.items())),
    ).pinned()


class CorpusShapeTests(unittest.TestCase):
    def test_probe_names_unique(self):
        names = list(maa.attack_probe_names()) + list(maa.benign_probe_names())
        self.assertEqual(len(names), len(set(names)))

    def test_required_keys(self):
        for probe in (*maa.MULTI_AXIS_AUTONOMY_PROBES, *maa.MULTI_AXIS_AUTONOMY_BENIGN):
            for key in ("probe", "family", "attack", "gate_interaction", "expected", "reason"):
                self.assertIn(key, probe, f"{probe['probe']} missing {key}")

    def test_expected_outcomes(self):
        outcomes = maa.expected_outcomes()
        self.assertTrue(all(outcomes[n] == "deny" for n in maa.attack_probe_names()))
        self.assertTrue(all(outcomes[n] == "allow" for n in maa.benign_probe_names()))

    def test_deny_side_keywords_on_all_attacks(self):
        keywords = maa.DENY_SIDE_KEYWORDS
        for probe in maa.MULTI_AXIS_AUTONOMY_PROBES:
            text = probe["gate_interaction"].lower()
            self.assertTrue(
                any(k in text for k in keywords),
                f"{probe['probe']} gate_interaction names no deny-side keyword",
            )

    def test_family_counts(self):
        self.assertEqual(len(maa.probes_in_family("axis-representation")), 4)
        self.assertEqual(len(maa.probes_in_family("per-axis-gating")), 3)
        self.assertEqual(len(maa.probes_in_family("axis-binding")), 3)

    def test_probe_by_name(self):
        probe = maa.probe_by_name("axis-composite-collapse")
        self.assertEqual(probe["expected"], "deny")
        with self.assertRaises(KeyError):
            maa.probe_by_name("no-such-probe")

    def test_axes_fixed_vocabulary(self):
        self.assertEqual(len(maa.AXES), 5)
        self.assertIn(maa.AXIS_BLAST_RADIUS, maa.AXES)
        self.assertIn(maa.AXIS_DATA_SENSITIVITY, maa.AXES)


class ReadingTests(unittest.TestCase):
    def test_round_trip_verify(self):
        reading = _reading()
        self.assertTrue(reading.verify())

    def test_tampered_risk_fails(self):
        reading = _reading(risk=maa.RISK_LOW)
        tampered = maa.AxisReading(
            action_id=reading.action_id,
            axis=reading.axis,
            risk=maa.RISK_HIGH,
            evidence_digest=reading.evidence_digest,
            policy_revision=reading.policy_revision,
            digest=reading.digest,
        )
        self.assertFalse(tampered.verify())

    def test_unknown_axis_rejected(self):
        with self.assertRaises(maa.MultiAxisAutonomyError):
            maa.AxisReading(
                action_id="a1", axis="vibes", risk=maa.RISK_LOW,
                evidence_digest=_digest({}), policy_revision="pol-1",
            )

    def test_unknown_risk_rejected(self):
        with self.assertRaises(maa.MultiAxisAutonomyError):
            maa.AxisReading(
                action_id="a1", axis=maa.AXIS_REVERSIBILITY, risk="catastrophic",
                evidence_digest=_digest({}), policy_revision="pol-1",
            )

    def test_bad_evidence_digest_rejected(self):
        with self.assertRaises(maa.MultiAxisAutonomyError):
            maa.AxisReading(
                action_id="a1", axis=maa.AXIS_REVERSIBILITY, risk=maa.RISK_LOW,
                evidence_digest="not-a-digest", policy_revision="pol-1",
            )


class ProfileTests(unittest.TestCase):
    def test_complete_profile_verifies(self):
        self.assertTrue(_profile().verify())

    def test_missing_axis_is_malformed(self):
        readings = tuple(_reading(axis=a) for a in maa.AXES[:4])
        with self.assertRaises(maa.MultiAxisAutonomyError):
            maa.AxisProfile(action_id="a1", readings=readings)

    def test_duplicate_axis_is_malformed(self):
        readings = tuple(_reading(axis=a) for a in (*maa.AXES, maa.AXES[0]))
        with self.assertRaises(maa.MultiAxisAutonomyError):
            maa.AxisProfile(action_id="a1", readings=readings)

    def test_unverifiable_reading_rejected(self):
        good = _reading()
        bad = maa.AxisReading(
            action_id="a1", axis=maa.AXIS_REVERSIBILITY, risk=maa.RISK_HIGH,
            evidence_digest=good.evidence_digest,
            policy_revision=good.policy_revision, digest=good.digest,
        )
        with self.assertRaises(maa.MultiAxisAutonomyError):
            maa.AxisProfile(
                action_id="a1",
                readings=tuple(
                    bad if a == maa.AXIS_REVERSIBILITY else _reading(axis=a)
                    for a in maa.AXES
                ),
            )

    def test_reading_for(self):
        profile = _profile(risks={maa.AXIS_BLAST_RADIUS: maa.RISK_HIGH})
        self.assertEqual(
            profile.reading_for(maa.AXIS_BLAST_RADIUS).risk, maa.RISK_HIGH
        )


class GateTests(unittest.TestCase):
    def test_all_below_ceiling_proceeds(self):
        verdict = maa.decide_per_axis(_profile(), _policy())
        self.assertTrue(verdict.verify())
        self.assertEqual(verdict.action_decision(), maa.DECISION_PROCEED)
        self.assertEqual(len(verdict.findings), 0)

    def test_at_ceiling_holds_named_axis(self):
        policy = _policy({a: maa.RISK_LOW for a in maa.AXES})
        verdict = maa.decide_per_axis(_profile(), policy)
        self.assertEqual(verdict.action_decision(), maa.DECISION_HOLD)
        self.assertEqual(
            verdict.decision_for(maa.AXIS_REVERSIBILITY), maa.DECISION_HOLD
        )
        self.assertTrue(
            all(f.code == maa.DENY_AT_CEILING for f in verdict.findings)
        )
        self.assertTrue(all(f.verify() for f in verdict.findings))

    def test_above_ceiling_denies_named_axis(self):
        profile = _profile(risks={maa.AXIS_BLAST_RADIUS: maa.RISK_HIGH})
        policy = _policy({a: maa.RISK_MEDIUM for a in maa.AXES})
        verdict = maa.decide_per_axis(_profile(), policy)
        self.assertEqual(verdict.action_decision(), maa.DECISION_PROCEED)
        verdict = maa.decide_per_axis(profile, policy)
        self.assertEqual(verdict.action_decision(), maa.DECISION_DENY)
        self.assertEqual(
            verdict.decision_for(maa.AXIS_BLAST_RADIUS), maa.DECISION_DENY
        )
        blast = [f for f in verdict.findings if f.axis == maa.AXIS_BLAST_RADIUS]
        self.assertEqual(len(blast), 1)
        self.assertEqual(blast[0].code, maa.DENY_CEILING_EXCEEDED)

    def test_one_red_axis_denies_action(self):
        # Four low, one high, high ceiling everywhere except one axis:
        # the high axis must deny the whole action (no averaging).
        profile = _profile(risks={maa.AXIS_PERSISTENCE: maa.RISK_HIGH})
        ceilings = {a: maa.RISK_HIGH for a in maa.AXES}
        ceilings[maa.AXIS_PERSISTENCE] = maa.RISK_MEDIUM
        verdict = maa.decide_per_axis(profile, _policy(ceilings))
        self.assertEqual(verdict.action_decision(), maa.DECISION_DENY)

    def test_unverifiable_profile_refused(self):
        profile = _profile()
        bad = maa.AxisProfile(
            action_id=profile.action_id, readings=profile.readings,
            digest="sha256:" + "0" * 64,
        )
        with self.assertRaises(maa.MultiAxisAutonomyError):
            maa.decide_per_axis(bad, _policy())

    def test_verdict_binds_profile_digest(self):
        profile = _profile()
        verdict = maa.decide_per_axis(profile, _policy())
        self.assertEqual(verdict.profile_digest, profile.digest)

    def test_no_composite_field_anywhere(self):
        verdict = maa.decide_per_axis(_profile(), _policy())
        body = verdict.pinned()
        self.assertTrue(body.verify())
        # The digest body must never carry a composite score field.
        for key in ("score", "composite", "overall", "average"):
            self.assertNotIn(key, body.digest)

    def test_refuse_composite_score(self):
        finding = maa.refuse_composite_score("a1", 0.82)
        self.assertEqual(finding.code, maa.DENY_COMPOSITE_REFUSED)
        self.assertTrue(finding.verify())
        self.assertIn("0.82", finding.detail)

    def test_main_runs(self):
        maa.main()


if __name__ == "__main__":
    unittest.main()
