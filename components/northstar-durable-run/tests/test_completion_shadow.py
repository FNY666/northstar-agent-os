"""Tests for the shadow-only layered completion policy."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from completion_contract_v2 import CompletionResult  # noqa: E402
from completion_shadow import compose_shadow  # noqa: E402
from verifier import VerificationResult  # noqa: E402


def production(verdict, errors=()):
    return VerificationResult(verdict, tuple(errors), {})


def contract(verdict, errors=()):
    return CompletionResult(verdict, tuple(errors), ())


class CompletionShadowTest(unittest.TestCase):
    def test_only_both_verified_yields_layered_verified(self):
        result = compose_shadow(production("verified"), contract("verified"))
        self.assertEqual(result.verdict, "verified")
        self.assertFalse(result.execution_authorized)
        self.assertEqual(result.errors, ())

    def test_any_failure_dominates_the_composed_verdict(self):
        cases = (
            (production("failed", ("test exit code was 1",)), contract("verified")),
            (production("verified"), contract("failed", ("semantic_field:top_scorer",))),
            (production("failed", ("cancelled",)), contract("failed", ("digest",))),
        )
        for upstream, downstream in cases:
            with self.subTest(upstream=upstream.verdict, downstream=downstream.verdict):
                result = compose_shadow(upstream, downstream)
                self.assertEqual(result.verdict, "failed")
                self.assertFalse(result.execution_authorized)

    def test_insufficient_information_does_not_silently_downgrade_to_verified(self):
        result = compose_shadow(
            production("verified"), contract("insufficient_information", ("provenance_missing",))
        )
        self.assertEqual(result.verdict, "insufficient_information")
        self.assertFalse(result.execution_authorized)
        self.assertIn("contract:provenance_missing", result.errors)

    def test_unknown_is_fail_closed_and_diagnostics_are_namespaced(self):
        result = compose_shadow(
            production("unknown", ("event history unavailable",)),
            contract("unknown", ("evidence_terminal_state_unavailable",)),
        )
        self.assertEqual(result.verdict, "unknown")
        self.assertFalse(result.execution_authorized)
        self.assertEqual(
            result.errors,
            (
                "production:event history unavailable",
                "contract:evidence_terminal_state_unavailable",
            ),
        )

    def test_empty_nonverified_errors_still_leave_a_diagnostic(self):
        result = compose_shadow(production("unknown"), contract("verified"))
        self.assertEqual(result.errors, ("production:not_verified:unknown",))
