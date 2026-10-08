"""Tests for the pinned denial explanation surface."""
import unittest

import counterfactual


class CounterfactualTests(unittest.TestCase):
    def test_rule_table_contains_reviewed_mutable_and_hard_denials(self):
        approval = counterfactual.RULE_EXPLANATIONS[
            "denial.ceiling.needs_approval"
        ]
        self.assertFalse(approval.hard)
        self.assertTrue(approval.counterfactuals[0].mutable)
        self.assertIn("verified human approval", approval.counterfactuals[0].text)

        hard = counterfactual.RULE_EXPLANATIONS[
            "denial.offensive.deny_by_default"
        ]
        self.assertTrue(hard.hard)
        self.assertFalse(hard.counterfactuals[0].mutable)
        self.assertIn("No remediation exists", hard.counterfactuals[0].text)

    def test_rule_table_is_immutable(self):
        with self.assertRaises(TypeError):
            counterfactual.RULE_EXPLANATIONS["denial.new.rule"] = object()

    def test_renderer_uses_audit_reason_and_pinned_counterfactual(self):
        rendered = counterfactual.render_denial(
            {
                "verdict": "deny",
                "deny_code": "denial.ceiling.needs_approval",
                "reason": "tool not in ceiling",
            }
        )
        self.assertIn("Recorded audit reason: tool not in ceiling", rendered)
        self.assertIn("verified human approval", rendered)

    def test_unknown_rule_does_not_invent_a_remediation(self):
        rendered = counterfactual.render_denial(
            {"verdict": "deny", "deny_code": "denial.unknown.rule"}
        )
        self.assertIn("No pinned rule explanation is available", rendered)
        self.assertNotIn("approval", rendered.lower())

    def test_renderer_rejects_non_denial_or_malformed_record(self):
        with self.assertRaises(ValueError):
            counterfactual.render_denial(
                {"verdict": "allow", "deny_code": "denial.ceiling.needs_approval"}
            )
        with self.assertRaises(ValueError):
            counterfactual.render_denial({"verdict": "deny"})


if __name__ == "__main__":
    unittest.main()
