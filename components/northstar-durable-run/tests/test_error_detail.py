"""R20: failure diagnoses must be preserved, bounded, and secret-free.

Before this change ``error_detail`` was always ``None`` for a plain
``ValueError`` (only ``PlannerModelCallFailed`` carried detail), which made
every non-planner failure undiagnosable: the report said ``error: ValueError``
and nothing else.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT)]

from planner_adapter import bounded_error_detail as _bounded_error_detail  # noqa: E402


class BoundedErrorDetailTests(unittest.TestCase):
    def test_value_error_message_is_preserved(self) -> None:
        detail = _bounded_error_detail(
            ValueError("expected_postconditions is self-contradictory: s1")
        )
        self.assertEqual(
            detail, "expected_postconditions is self-contradictory: s1"
        )

    def test_non_value_error_stays_opaque(self) -> None:
        # Arbitrary exception text may embed provider/model output; it must not
        # reach the report through this path.
        for error in (RuntimeError("boom"), OSError("no such file"), KeyError("k")):
            self.assertIsNone(_bounded_error_detail(error))

    def test_message_is_bounded_and_single_line(self) -> None:
        detail = _bounded_error_detail(ValueError("x" * 5000 + "\n\ttail"))
        self.assertEqual(len(detail), 400)
        self.assertNotIn("\n", detail)

    def test_control_characters_are_neutralised(self) -> None:
        detail = _bounded_error_detail(ValueError("a\x00b\x1bc"))
        self.assertNotIn("\x00", detail)
        self.assertNotIn("\x1b", detail)

    def test_credential_shaped_tokens_are_redacted(self) -> None:
        detail = _bounded_error_detail(
            ValueError("upstream rejected sk-abcdef1234567890 for tenant acme")
        )
        self.assertNotIn("sk-abcdef1234567890", detail)
        self.assertIn("<redacted>", detail)
        self.assertIn("tenant acme", detail, "non-secret context must survive")

    def test_empty_message_becomes_none(self) -> None:
        self.assertIsNone(_bounded_error_detail(ValueError("   \n  ")))

    def test_key_from_environment_is_redacted_whatever_its_shape(self) -> None:
        # The real provider key shape is unknown to this code; exact value
        # replacement is the layer that actually protects it.
        literal = "kx7Qopaque67charvalueThatMatchesNoKnownPrefix0000000000000000000"
        import os
        from unittest import mock

        with mock.patch.dict(os.environ, {"KAKOUAI_API_KEY": literal}):
            detail = _bounded_error_detail(
                ValueError(f"upstream said: key {literal} is not permitted")
            )
        self.assertNotIn(literal, detail)
        self.assertIn("<redacted>", detail)
        self.assertIn("not permitted", detail, "context must survive")

    def test_short_environment_values_are_not_blindly_replaced(self) -> None:
        # A one- or two-character env var must not turn the whole message into
        # '<redacted>' noise (and must not be treated as a secret).
        import os
        from unittest import mock

        with mock.patch.dict(os.environ, {"KAKOUAI_API_KEY": "a"}):
            detail = _bounded_error_detail(ValueError("plan admission failed"))
        self.assertEqual(detail, "plan admission failed")


if __name__ == "__main__":
    unittest.main()
