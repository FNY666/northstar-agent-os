"""Tests for counterfactual-explanation probes, quality gates, simulatability."""

import unittest

import counterfactual_explanation_probes as cx


PINNED_CF = (
    "A verified human approval bound to this exact call_id and "
    "arguments_digest would allow the ascent."
)

RULE_TABLE = {
    "denial.ceiling.needs_approval": {
        "counterfactual": PINNED_CF,
        "hard": False,
    },
    "denial.offensive.deny_by_default": {
        "counterfactual": (
            "No remediation exists. This is a hard deny that cannot "
            "be overridden by approval, ascent, or human decision."
        ),
        "hard": True,
    },
}

IMMUTABLES = ("call_id", "arguments_digest", "closed scope identity", "past human decision")

FIELDS = ("tool", "deny_code", "rule", "reason", "verdict")


def _claim(text, kind="checked", anchors=("reason",)):
    return cx.ExplanationClaim(text=text, kind=kind, anchors=tuple(anchors))


def _record(
    explanation_id="exp-1",
    implied_verdict="deny",
    claims=None,
    what_would_change=PINNED_CF,
    pinned_values=None,
):
    if claims is None:
        claims = (
            _claim("tool shell", kind="tool", anchors=("tool",)),
            _claim("deny_code denial.ceiling.needs_approval", kind="deny_code", anchors=("deny_code",)),
            _claim("rule ceiling", kind="rule", anchors=("rule",)),
            _claim("the ceiling does not contain this tool", kind="checked", anchors=("reason",)),
        )
    if pinned_values is None:
        pinned_values = {
            "tool": "shell",
            "deny_code": "denial.ceiling.needs_approval",
            "rule": "ceiling",
            "reason": "tool not in ceiling",
            "verdict": "deny",
        }
    return cx.ExplanationRecord(
        explanation_id=explanation_id,
        implied_verdict=implied_verdict,
        claims=tuple(claims),
        what_would_change=what_would_change,
        record_fields=FIELDS,
        pinned_values=dict(pinned_values),
    )


def _question(qid, actual):
    return cx.CounterfactualQuestion(
        question_id=qid, edit_description=f"edit {qid}", actual_verdict=actual
    )


class TestVersion(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(cx.COUNTERFACTUAL_EXPLANATION_VERSION, "counterfactual-explanation.v1")
        self.assertEqual(cx.SCHEMA_PIN, "northstar.counterfactual-explanation.v1")


class TestCorpusShape(unittest.TestCase):
    def test_counts(self):
        self.assertEqual(len(cx.probe_names()), 8)
        self.assertEqual(len(cx.benign_names()), 2)
        self.assertEqual(len(cx.COUNTERFACTUAL_EXPLANATION_PROBES), 10)

    def test_source_matches(self):
        self.assertEqual(
            list(cx.COUNTERFACTUAL_EXPLANATION_SOURCE["probes"]),
            [p["probe"] for p in cx.COUNTERFACTUAL_EXPLANATION_PROBES],
        )

    def test_probe_fields_complete(self):
        for p in cx.COUNTERFACTUAL_EXPLANATION_PROBES:
            for f in ("probe", "family", "attack", "gate_interaction", "expected", "reason"):
                self.assertIn(f, p, p["probe"])

    def test_name_uniqueness(self):
        names = [p["probe"] for p in cx.COUNTERFACTUAL_EXPLANATION_PROBES]
        self.assertEqual(len(names), len(set(names)))

    def test_attack_probes_expected_deny(self):
        for name in cx.probe_names():
            self.assertEqual(cx.probe_by_name(name)["expected"], "deny", name)

    def test_benign_probes_expected_allow(self):
        for name in cx.benign_names():
            self.assertEqual(cx.probe_by_name(name)["expected"], "allow", name)

    def test_attack_probes_have_attack_text(self):
        for name in cx.probe_names():
            self.assertIsNotNone(cx.probe_by_name(name)["attack"], name)

    def test_benign_probes_have_no_attack(self):
        for name in cx.benign_names():
            self.assertIsNone(cx.probe_by_name(name)["attack"], name)

    def test_probe_by_name_unknown_raises(self):
        with self.assertRaises(KeyError):
            cx.probe_by_name("nope")

    def test_deny_side_keywords(self):
        for p in cx.COUNTERFACTUAL_EXPLANATION_PROBES:
            self.assertTrue(cx.probe_invokes_deny_side(p), p["probe"])

    def test_family_shape(self):
        for p in cx.COUNTERFACTUAL_EXPLANATION_PROBES:
            self.assertEqual(p["family"], "counterfactual-explanation")


class TestRecord(unittest.TestCase):
    def test_digest_verifies(self):
        self.assertTrue(_record().verify_digest())

    def test_digest_tamper_fails(self):
        rec = _record()
        object.__setattr__(rec, "digest", "sha256:" + "0" * 64)
        self.assertFalse(rec.verify_digest())

    def test_claim_kind_closed(self):
        with self.assertRaises(ValueError):
            cx.ExplanationClaim(text="x", kind="vibes", anchors=("reason",))

    def test_claim_text_required(self):
        with self.assertRaises(ValueError):
            cx.ExplanationClaim(text="", kind="checked", anchors=("reason",))

    def test_implied_verdict_closed(self):
        with self.assertRaises(ValueError):
            _record(implied_verdict="maybe")

    def test_claims_non_empty(self):
        with self.assertRaises(ValueError):
            _record(claims=())


class TestAnchoring(unittest.TestCase):
    def test_faithful_passes(self):
        f = cx.check_anchoring(_record())
        self.assertTrue(f.passed, f.reason)

    def test_unanchored_claim_fails(self):
        rec = _record(claims=(_claim("the approver was Alice", anchors=()),))
        f = cx.check_anchoring(rec)
        self.assertFalse(f.passed)

    def test_unknown_field_fails(self):
        rec = _record(claims=(_claim("x", anchors=("approver_name",)),))
        f = cx.check_anchoring(rec)
        self.assertFalse(f.passed)

    def test_value_mismatch_fails(self):
        rec = _record(claims=(_claim("tool curl", kind="tool", anchors=("tool",)),))
        f = cx.check_anchoring(rec)
        self.assertFalse(f.passed)

    def test_missing_deny_code_fails(self):
        rec = _record(claims=(_claim("some checked fact", anchors=("reason",)),))
        f = cx.check_anchoring(rec)
        self.assertFalse(f.passed)


class TestRuleConsistency(unittest.TestCase):
    def test_matching_counterfactual_passes(self):
        f = cx.check_rule_consistency(_record(), RULE_TABLE)
        self.assertTrue(f.passed, f.reason)

    def test_invented_counterfactual_fails(self):
        rec = _record(what_would_change="Just ask nicely and it will pass.")
        f = cx.check_rule_consistency(rec, RULE_TABLE)
        self.assertFalse(f.passed)

    def test_unknown_deny_code_no_invention_passes(self):
        pv = {
            "tool": "shell",
            "deny_code": "denial.weird.new",
            "rule": "weird",
            "reason": "new",
            "verdict": "deny",
        }
        claims = (
            _claim("deny_code denial.weird.new", kind="deny_code", anchors=("deny_code",)),
        )
        rec = _record(
            what_would_change="No known remediation exists; the renderer does not guess.",
            pinned_values=pv,
            claims=claims,
        )
        f = cx.check_rule_consistency(rec, RULE_TABLE)
        self.assertTrue(f.passed, f.reason)

    def test_unknown_deny_code_invention_fails(self):
        pv = {
            "tool": "shell",
            "deny_code": "denial.weird.new",
            "rule": "weird",
            "reason": "new",
            "verdict": "deny",
        }
        claims = (
            _claim("deny_code denial.weird.new", kind="deny_code", anchors=("deny_code",)),
        )
        rec = _record(
            what_would_change="Try again tomorrow.",
            pinned_values=pv,
            claims=claims,
        )
        f = cx.check_rule_consistency(rec, RULE_TABLE)
        self.assertFalse(f.passed)


class TestHardDeny(unittest.TestCase):
    def _hard_record(self, what_would_change, claims=None):
        pv = {
            "tool": "shell",
            "deny_code": "denial.offensive.deny_by_default",
            "rule": "offensive",
            "reason": "offensive tooling",
            "verdict": "deny",
        }
        if claims is None:
            claims = (
                _claim(
                    "deny_code denial.offensive.deny_by_default",
                    kind="deny_code",
                    anchors=("deny_code",),
                ),
                _claim(
                    "No remediation exists for this hard deny",
                    kind="hard_deny_statement",
                    anchors=("reason",),
                ),
            )
        return _record(
            what_would_change=what_would_change,
            pinned_values=pv,
            claims=claims,
        )

    def test_hard_deny_with_statement_passes(self):
        rec = self._hard_record(
            "No remediation exists. This is a hard deny that cannot "
            "be overridden by approval, ascent, or human decision."
        )
        f = cx.check_hard_deny(rec, RULE_TABLE)
        self.assertTrue(f.passed, f.reason)

    def test_hard_deny_fabricated_remediation_fails(self):
        rec = self._hard_record("Obtain a manager approval to proceed.")
        f = cx.check_hard_deny(rec, RULE_TABLE)
        self.assertFalse(f.passed)

    def test_hard_deny_missing_statement_fails(self):
        rec = self._hard_record(
            "No remediation exists. This is a hard deny that cannot "
            "be overridden by approval, ascent, or human decision.",
            claims=(
                _claim(
                    "deny_code denial.offensive.deny_by_default",
                    kind="deny_code",
                    anchors=("deny_code",),
                ),
            ),
        )
        f = cx.check_hard_deny(rec, RULE_TABLE)
        self.assertFalse(f.passed)

    def test_non_hard_deny_passes(self):
        f = cx.check_hard_deny(_record(), RULE_TABLE)
        self.assertTrue(f.passed, f.reason)


class TestPace(unittest.TestCase):
    def test_clean_passes(self):
        f = cx.check_pace(_record(), IMMUTABLES)
        self.assertTrue(f.passed, f.reason)

    def test_immutable_touch_fails(self):
        rec = _record(
            what_would_change="Revive the closed scope identity under a new name."
        )
        f = cx.check_pace(rec, IMMUTABLES)
        self.assertFalse(f.passed)


class TestQualityGate(unittest.TestCase):
    def test_all_pass(self):
        r = cx.run_quality_gate(_record(), RULE_TABLE, IMMUTABLES)
        self.assertTrue(r.passed)
        self.assertEqual(len(r.findings), 4)
        self.assertEqual(
            [f.gate for f in r.findings],
            ["anchoring", "rule-consistency", "hard-deny", "pace"],
        )

    def test_one_fail_fails_all(self):
        rec = _record(what_would_change="Just ask nicely and it will pass.")
        r = cx.run_quality_gate(rec, RULE_TABLE, IMMUTABLES)
        self.assertFalse(r.passed)
        failed = [f for f in r.findings if not f.passed]
        self.assertEqual(len(failed), 1)
        self.assertEqual(failed[0].gate, "rule-consistency")

    def test_findings_digest_pinned(self):
        r = cx.run_quality_gate(_record(), RULE_TABLE, IMMUTABLES)
        for f in r.findings:
            self.assertTrue(f.digest.startswith("sha256:"))
        self.assertTrue(r.digest.startswith("sha256:"))


class TestSimulatability(unittest.TestCase):
    def test_all_match_passes(self):
        questions = [_question("q1", "deny"), _question("q2", "allow")]
        r = cx.run_simulatability(
            _record(), questions, lambda rec, q: q.actual_verdict, threshold=2
        )
        self.assertTrue(r.passed)
        self.assertEqual(r.matches, 2)
        self.assertEqual(r.total, 2)

    def test_below_threshold_fails(self):
        questions = [_question("q1", "deny"), _question("q2", "allow")]
        r = cx.run_simulatability(
            _record(), questions, lambda rec, q: "deny", threshold=2
        )
        self.assertFalse(r.passed)
        self.assertEqual(r.matches, 1)

    def test_per_question_table(self):
        questions = [_question("q1", "deny"), _question("q2", "allow")]
        r = cx.run_simulatability(
            _record(), questions, lambda rec, q: "deny", threshold=1
        )
        by_id = {res.question_id: res for res in r.results}
        self.assertTrue(by_id["q1"].match)
        self.assertFalse(by_id["q2"].match)

    def test_bad_predictor_verdict_raises(self):
        questions = [_question("q1", "deny")]
        with self.assertRaises(ValueError):
            cx.run_simulatability(
                _record(), questions, lambda rec, q: "maybe", threshold=1
            )

    def test_empty_questions_raises(self):
        with self.assertRaises(ValueError):
            cx.run_simulatability(_record(), [], lambda rec, q: "deny", threshold=0)

    def test_bad_threshold_raises(self):
        questions = [_question("q1", "deny")]
        with self.assertRaises(ValueError):
            cx.run_simulatability(
                _record(), questions, lambda rec, q: "deny", threshold=5
            )


class TestAdapter(unittest.TestCase):
    def test_rule_table_from_counterfactual(self):
        import counterfactual as cf

        table = cx.rule_table_from_counterfactual(cf.RULE_EXPLANATIONS)
        self.assertIn("denial.ceiling.needs_approval", table)
        entry = table["denial.ceiling.needs_approval"]
        self.assertFalse(entry["hard"])
        self.assertIn("verified human approval", entry["counterfactual"])
        hard = table["denial.offensive.deny_by_default"]
        self.assertTrue(hard["hard"])
        self.assertIn("No remediation exists", hard["counterfactual"])

    def test_adapter_drives_rule_consistency(self):
        import counterfactual as cf

        table = cx.rule_table_from_counterfactual(cf.RULE_EXPLANATIONS)
        deny_code = "denial.ceiling.needs_approval"
        entry = table[deny_code]
        pv = {
            "tool": "shell",
            "deny_code": deny_code,
            "rule": "ceiling",
            "reason": "tool not in ceiling",
            "verdict": "deny",
        }
        claims = (
            _claim("tool shell", kind="tool", anchors=("tool",)),
            _claim(f"deny_code {deny_code}", kind="deny_code", anchors=("deny_code",)),
        )
        rec = _record(
            what_would_change=entry["counterfactual"],
            pinned_values=pv,
            claims=claims,
        )
        f = cx.check_rule_consistency(rec, table)
        self.assertTrue(f.passed, f.reason)


if __name__ == "__main__":
    unittest.main()
