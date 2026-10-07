"""Tests for compaction observation masking."""
from __future__ import annotations

import unittest

import support  # noqa: F401

from compaction_masking import (
    MASKING_VERSION,
    SENSITIVE_PATTERNS,
    CompactionGate,
    MaskedHistory,
    mask_observations,
    mask_report,
)


class PatternTests(unittest.TestCase):
    def test_stripe_style_api_key_is_masked(self):
        text = "key is sk-abcDEF1234567890xyz for the account"
        self.assertEqual(
            mask_observations(text),
            "key is [REDACTED:api_key] for the account",
        )

    def test_aws_access_key_is_masked(self):
        text = "using AKIAIOSFODNN7EXAMPLE here"
        self.assertIn("[REDACTED:api_key]", mask_observations(text))
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", mask_observations(text))

    def test_github_token_is_masked(self):
        text = "token ghp_abcdefghij1234567890abcdef deployed"
        masked = mask_observations(text)
        self.assertIn("[REDACTED:api_key]", masked)
        self.assertNotIn("ghp_", masked)

    def test_bearer_token_is_masked(self):
        text = "Authorization: Bearer abcDEF123._-~/+="
        masked = mask_observations(text)
        self.assertIn("[REDACTED:token]", masked)
        self.assertNotIn("Bearer abcDEF123", masked)

    def test_jwt_shape_is_masked(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c"
        self.assertEqual(mask_observations(f"got {jwt} back"), "got [REDACTED:token] back")

    def test_password_assignment_is_masked(self):
        text = "password: s3cr3t-hunter2"
        masked = mask_observations(text)
        self.assertIn("[REDACTED:password]", masked)
        self.assertNotIn("s3cr3t-hunter2", masked)

    def test_email_is_masked(self):
        text = "contact alice@example.com for details"
        masked = mask_observations(text)
        self.assertEqual(masked, "contact [REDACTED:email] for details")

    def test_phone_is_masked(self):
        text = "call +1 (415) 555-0132 tomorrow"
        masked = mask_observations(text)
        self.assertIn("[REDACTED:phone]", masked)
        self.assertNotIn("415", masked)

    def test_clean_text_is_unchanged(self):
        text = "the model completed the summarization without errors"
        self.assertEqual(mask_observations(text), text)

    def test_masking_is_idempotent(self):
        text = "sk-abcDEF1234567890xyz and bob@example.com"
        once = mask_observations(text)
        self.assertEqual(mask_observations(once), once)

    def test_empty_string(self):
        self.assertEqual(mask_observations(""), "")

    def test_non_string_raises(self):
        with self.assertRaises(TypeError):
            mask_observations(None)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            mask_observations(123)  # type: ignore[arg-type]


class MaskReportTests(unittest.TestCase):
    def test_counts_are_typed(self):
        masked, counts = mask_report("sk-abcDEF1234567890xyz bob@example.com bob@example.com")
        self.assertEqual(masked.count("[REDACTED:api_key]"), 1)
        self.assertEqual(masked.count("[REDACTED:email]"), 2)
        self.assertEqual(counts, {"api_key": 1, "email": 2})

    def test_clean_text_reports_empty_counts(self):
        masked, counts = mask_report("nothing sensitive here")
        self.assertEqual(masked, "nothing sensitive here")
        self.assertEqual(counts, {})


class CompactionGateTests(unittest.TestCase):
    def test_gate_masks_whole_history(self):
        gate = CompactionGate()
        history = [
            "user asked about sk-abcDEF1234567890xyz",
            "assistant replied to carol@example.org",
            "nothing sensitive in this one",
        ]
        result = gate.approve_for_compaction(history)
        self.assertIsInstance(result, MaskedHistory)
        self.assertEqual(len(result.entries), 3)
        self.assertIn("[REDACTED:api_key]", result.entries[0])
        self.assertIn("[REDACTED:email]", result.entries[1])
        self.assertEqual(result.entries[2], "nothing sensitive in this one")

    def test_gate_reports_redaction_counts(self):
        gate = CompactionGate()
        result = gate.approve_for_compaction(["pw password=hunter2", "mail a@b.co"])
        counts = dict(result.redaction_counts)
        self.assertEqual(counts.get("password"), 1)
        self.assertEqual(counts.get("email"), 1)
        self.assertTrue(result.masked_any)
        self.assertEqual(result.total_redactions, 2)

    def test_gate_preserves_order_and_length(self):
        gate = CompactionGate()
        history = [f"line {i} with sk-abcDEF1234567890xyz" for i in range(5)]
        result = gate.approve_for_compaction(history)
        self.assertEqual(len(result.entries), len(history))
        for entry in result.entries:
            self.assertIn("[REDACTED:api_key]", entry)

    def test_gate_does_not_mutate_input(self):
        gate = CompactionGate()
        history = ["secret sk-abcDEF1234567890xyz"]
        gate.approve_for_compaction(history)
        self.assertEqual(history, ["secret sk-abcDEF1234567890xyz"])

    def test_gate_clean_history_reports_no_masking(self):
        gate = CompactionGate()
        result = gate.approve_for_compaction(["hello", "world"])
        self.assertFalse(result.masked_any)
        self.assertEqual(result.redaction_counts, ())
        self.assertEqual(result.entries, ("hello", "world"))

    def test_gate_empty_history(self):
        gate = CompactionGate()
        result = gate.approve_for_compaction([])
        self.assertEqual(result.entries, ())
        self.assertFalse(result.masked_any)

    def test_gate_disabled_passes_through(self):
        gate = CompactionGate(enabled=False)
        history = ["sk-abcDEF1234567890xyz"]
        result = gate.approve_for_compaction(history)
        self.assertEqual(result.entries, ("sk-abcDEF1234567890xyz",))
        self.assertFalse(result.masked_any)

    def test_gate_rejects_non_string_entries(self):
        gate = CompactionGate()
        with self.assertRaises(TypeError):
            gate.approve_for_compaction(["ok", 42])  # type: ignore[list-item]

    def test_transparency_version_is_stamped(self):
        gate = CompactionGate()
        result = gate.approve_for_compaction(["x"])
        self.assertEqual(result.masking_version, MASKING_VERSION)
        payload = result.as_dict()
        self.assertEqual(payload["masking_version"], MASKING_VERSION)
        self.assertIn("redaction_counts", payload)

    def test_marker_type_is_never_bare(self):
        # Transparency: every redaction names its type; no silent deletion.
        masked, _ = mask_report("sk-abcDEF1234567890xyz")
        self.assertNotIn("sk-abcDEF", masked)
        self.assertRegex(masked, r"\[REDACTED:[a-z_]+\]")


class RegistryTests(unittest.TestCase):
    def test_expected_mask_types_exist(self):
        types = {name for name, _ in SENSITIVE_PATTERNS}
        self.assertEqual(types, {"api_key", "token", "password", "email", "phone"})


if __name__ == "__main__":
    unittest.main()
