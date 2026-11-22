"""Keep the mutation declarations honest without running the slow harness.

mutation_check.py proves the guards can fail, but its declarations match source
text and would rot silently if the code moved. This check is fast enough to run
on every test pass and fails when a declaration no longer matches the code.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

COMPONENT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(COMPONENT_ROOT))

from mutation_check import MUTATIONS  # noqa: E402


class MutationDeclarationTest(unittest.TestCase):
    def test_every_declaration_matches_its_target_exactly_once(self):
        for mutation in MUTATIONS:
            with self.subTest(mutation=mutation.name):
                target = COMPONENT_ROOT / mutation.target
                self.assertTrue(target.is_file(), f"{mutation.target} is missing")
                occurrences = target.read_text(encoding="utf-8").count(mutation.old)
                self.assertEqual(
                    occurrences,
                    1,
                    f"{mutation.name}: fragment occurs {occurrences} times in {mutation.target}",
                )

    def test_declarations_are_unique_and_well_formed(self):
        names = [mutation.name for mutation in MUTATIONS]
        self.assertEqual(len(names), len(set(names)), "mutation names must be unique")
        for mutation in MUTATIONS:
            with self.subTest(mutation=mutation.name):
                self.assertIn(mutation.expect, {"fail", "pass"})
                self.assertNotEqual(mutation.old, mutation.new)
                self.assertTrue(mutation.guard.startswith("tests."))

    def test_a_neutral_control_is_declared(self):
        # Without one, a harness that failed every mutation would look correct.
        self.assertTrue(
            any(mutation.expect == "pass" for mutation in MUTATIONS),
            "at least one mutation must expect the guards to keep passing",
        )
