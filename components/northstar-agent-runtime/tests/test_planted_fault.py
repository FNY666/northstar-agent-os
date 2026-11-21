"""Acceptance tests for the planted-fault-under-seal method.

The method comes from the fieldnotes_ai Moltbook post *A check that has
never failed has not shown it can: plant the fault under seal* and its
comments, which stated three rules:

1. plant in the **input**, never in the memory;
2. the **planter is never the checker**;
3. a **miss voids the earlier passes** back to the last observed catch.

These tests drive the whole path end to end -- post the commitment,
plant the fault, run the check blind, reveal, book the catch -- and then
drive the miss path with a deliberately narrowed *test double* check.  The
repository's real checks (the alert trigger registry) are never weakened
to make a miss happen.
"""
from __future__ import annotations

import unittest

import support  # noqa: F401

from alert_trigger_registry import DEFAULT_REGISTRY
from planted_fault import (
    INPUT_TARGET,
    REVEALED,
    STATUS_CATCH,
    STATUS_MISS,
    STATUS_PASS,
    STATUS_VOID,
    STATUS_VOID_PLANT,
    VOID_PLANT,
    CheckOutcome,
    EvidenceLedger,
    PlantNote,
    PlantTargetError,
    PlantedFaultError,
    SeparationError,
    plant,
    post_commitment,
    reveal,
    run_check,
)


def _note(**overrides) -> PlantNote:
    """A kill-switch plant: run 3 of 5 turns a permission.allow into a deny."""
    fields = dict(
        plant_id="plant-1",
        run_index=3,
        field="outcome",
        wrong_value="permission.deny",
        true_value="permission.allow",
        planted_by="planter-alpha",
        check_scope="kill-switch",
        target_kind=INPUT_TARGET,
    )
    fields.update(overrides)
    return PlantNote(**fields)


def _allow_record() -> dict:
    """The input record of a run whose real outcome was an allow."""
    return {
        "outcome": "permission.allow",
        "intent": "permission-allow",
        "subject": "Shell",
        "authorization": "rule:mode:default",
    }


def _kill_switch_check(record) -> bool:
    """The real check: does the kill-switch trigger fire on this record?

    This is the registry's own ``matches()`` -- the check under test is
    never modified, narrowed, or replaced here.
    """
    return bool(DEFAULT_REGISTRY.matches(record))


class CommitmentTests(unittest.TestCase):
    """Rule 0: the commitment is posted before the check runs."""

    def test_commitment_matches_the_note_that_was_posted(self):
        note = _note()
        commitment = post_commitment(note)
        self.assertTrue(commitment.startswith("sha256:"))
        self.assertEqual(len(commitment), len("sha256:") + 64)

    def test_commitment_is_bound_to_the_note_contents(self):
        note = _note()
        commitment = post_commitment(note)
        other = _note(plant_id="plant-2")
        self.assertNotEqual(commitment, post_commitment(other))

    def test_a_changed_note_does_not_match_the_posted_commitment(self):
        ledger = EvidenceLedger()
        note = _note()
        commitment = post_commitment(note, ledger)
        tampered = PlantNote(
            plant_id=note.plant_id,
            run_index=note.run_index,
            field=note.field,
            wrong_value="permission.config-drift",
            true_value=note.true_value,
            planted_by=note.planted_by,
            check_scope=note.check_scope,
            target_kind=note.target_kind,
        )
        result = reveal(tampered, commitment, ledger)
        self.assertEqual(result.outcome, VOID_PLANT)
        self.assertEqual(len(ledger.catches()), 0)
        self.assertTrue(any(row.status == STATUS_VOID_PLANT for row in ledger.rows))

    def test_revealing_before_the_check_runs_voids_the_plant(self):
        ledger = EvidenceLedger()
        note = _note()
        commitment = post_commitment(note, ledger)
        result = reveal(note, commitment, ledger)
        self.assertEqual(result.outcome, VOID_PLANT)
        self.assertEqual(len(ledger.catches()), 0)
        self.assertEqual(len(ledger.misses()), 0)


class PlantInputTests(unittest.TestCase):
    """Rule 1: the plant goes in the input, never in the memory."""

    def test_plant_writes_the_wrong_value_into_the_input(self):
        note = _note()
        faulted = plant(_allow_record(), note, "planter-alpha")
        self.assertEqual(faulted["outcome"], "permission.deny")
        self.assertEqual(faulted["subject"], "Shell")

    def test_plant_returns_a_copy_and_leaves_the_original_alone(self):
        original = _allow_record()
        faulted = plant(original, _note(), "planter-alpha")
        self.assertEqual(original["outcome"], "permission.allow")
        self.assertEqual(faulted["outcome"], "permission.deny")
        self.assertIsNot(faulted, original)

    def test_plant_into_memory_is_refused(self):
        note = _note(target_kind="memory")
        with self.assertRaises(PlantTargetError):
            plant(_allow_record(), note, "planter-alpha")

    def test_plant_into_notes_is_refused(self):
        note = _note(target_kind="notes")
        with self.assertRaises(PlantTargetError):
            plant(_allow_record(), note, "planter-alpha")

    def test_plant_of_a_field_the_input_does_not_have_is_refused(self):
        note = _note(field="not_a_field")
        with self.assertRaises(PlantedFaultError):
            plant(_allow_record(), note, "planter-alpha")


class SeparationTests(unittest.TestCase):
    """Rule 2: the planter is never the checker -- identity is the subject."""

    def test_the_same_subject_may_not_both_plant_and_check(self):
        note = _note(planted_by="planter-alpha")
        faulted = plant(_allow_record(), note, "planter-alpha")
        with self.assertRaises(SeparationError):
            run_check(_kill_switch_check, faulted, "planter-alpha")

    def test_ones_own_later_run_is_still_oneself(self):
        # The rule is about the subject, not the process: the same
        # subject id checking in a later run is still refused.
        note = _note(planted_by="planter-alpha")
        faulted = plant(_allow_record(), note, "planter-alpha")
        with self.assertRaises(SeparationError):
            run_check(_kill_switch_check, faulted, "planter-alpha", EvidenceLedger())

    def test_a_different_subject_may_check(self):
        note = _note(planted_by="planter-alpha")
        faulted = plant(_allow_record(), note, "planter-alpha")
        outcome = run_check(_kill_switch_check, faulted, "checker-beta")
        self.assertTrue(outcome.caught)

    def test_a_planter_that_is_not_the_notes_planter_is_refused(self):
        note = _note(planted_by="planter-alpha")
        with self.assertRaises(SeparationError):
            plant(_allow_record(), note, "planter-gamma")


class EvidenceLedgerTests(unittest.TestCase):
    """Rule 3: a miss voids the earlier passes back to the last observed catch."""

    def test_a_catch_is_booked_as_evidence(self):
        ledger = EvidenceLedger()
        note = _note()
        commitment = post_commitment(note, ledger)
        faulted = plant(_allow_record(), note, "planter-alpha")
        run_check(_kill_switch_check, faulted, "checker-beta", ledger)
        result = reveal(note, commitment, ledger)
        self.assertEqual(result.outcome, REVEALED)
        self.assertEqual(len(ledger.catches()), 1)
        self.assertEqual(ledger.catches()[0].status, STATUS_CATCH)

    def test_a_miss_voids_the_passes_after_the_last_catch(self):
        ledger = EvidenceLedger()
        ledger.record_catch("plant-0", 1, seq=10)
        ledger.record_pass("kill-switch", 2, seq=11)
        ledger.record_pass("kill-switch", 3, seq=12)
        ledger.record_miss("plant-1", 4, seq=13)
        statuses = {row.seq: row.status for row in ledger.passes()}
        self.assertEqual(statuses[11], STATUS_VOID)
        self.assertEqual(statuses[12], STATUS_VOID)
        self.assertEqual(len(ledger.voided_passes()), 2)
        self.assertEqual(len(ledger.valid_passes()), 0)

    def test_the_void_stops_at_the_last_catch(self):
        ledger = EvidenceLedger()
        ledger.record_pass("kill-switch", 1, seq=5)
        ledger.record_catch("plant-0", 2, seq=6)
        ledger.record_pass("kill-switch", 3, seq=7)
        ledger.record_miss("plant-1", 4, seq=8)
        statuses = {row.seq: row.status for row in ledger.passes()}
        # Before the last observed catch: untouched.
        self.assertEqual(statuses[5], STATUS_PASS)
        # After it: void.
        self.assertEqual(statuses[7], STATUS_VOID)
        self.assertEqual(len(ledger.valid_passes()), 1)

    def test_a_miss_with_no_prior_catch_voids_every_pass(self):
        ledger = EvidenceLedger()
        ledger.record_pass("kill-switch", 1, seq=1)
        ledger.record_pass("kill-switch", 2, seq=2)
        ledger.record_miss("plant-1", 3, seq=3)
        self.assertEqual(len(ledger.voided_passes()), 2)
        self.assertEqual(len(ledger.valid_passes()), 0)

    def test_the_miss_row_is_booked_as_a_miss(self):
        ledger = EvidenceLedger()
        ledger.record_miss("plant-1", 3, seq=4)
        self.assertEqual(len(ledger.misses()), 1)
        self.assertEqual(ledger.misses()[0].status, STATUS_MISS)

    def test_a_void_plant_stays_dead(self):
        ledger = EvidenceLedger()
        note = _note()
        commitment = post_commitment(note, ledger)
        result = reveal(note, commitment, ledger)
        self.assertEqual(result.outcome, VOID_PLANT)
        # A second reveal cannot revive the plant into a catch.
        again = reveal(note, commitment, ledger)
        self.assertEqual(again.outcome, VOID_PLANT)
        self.assertEqual(len(ledger.catches()), 0)


class EndToEndPathTests(unittest.TestCase):
    """One real path driven from end to end -- then the miss path."""

    def test_the_real_path_is_driven_from_commitment_to_catch(self):
        # (a) post the commitment, (b) plant a permission.deny into run 3
        # of 5, (c) run the kill-switch check blind, (d) reveal,
        # (e) the catch is booked.
        ledger = EvidenceLedger()
        note = _note(run_index=3)
        commitment = post_commitment(note, ledger)
        self.assertTrue(commitment.startswith("sha256:"))

        runs = [_allow_record() for _ in range(5)]
        faulted = plant(runs[note.run_index - 1], note, "planter-alpha")
        self.assertEqual(faulted["outcome"], "permission.deny")

        outcome = run_check(_kill_switch_check, faulted, "checker-beta", ledger)
        self.assertTrue(outcome.caught, "the kill-switch trigger must fire on the planted deny")
        self.assertEqual(outcome.checker_id, "checker-beta")

        result = reveal(note, commitment, ledger)
        self.assertEqual(result.outcome, REVEALED)
        self.assertEqual(len(ledger.catches()), 1)
        self.assertEqual(ledger.catches()[0].plant_id, note.plant_id)
        self.assertEqual(len(ledger.misses()), 0)

    def test_the_miss_path_voids_the_passes_after_the_last_catch(self):
        # (b) a deliberately narrowed TEST DOUBLE that cannot see the
        # planted field -- the repository's real check is never weakened.
        def narrowed_check(record) -> bool:
            """A test double: it only looks at a field the plant did not touch."""
            return record.get("subject") == "NeverMatches"

        ledger = EvidenceLedger()
        ledger.record_catch("plant-0", 1, seq=1)
        ledger.record_pass("kill-switch", 2, seq=2)
        ledger.record_pass("kill-switch", 3, seq=3)

        note = _note(plant_id="plant-2", run_index=4)
        commitment = post_commitment(note, ledger)
        faulted = plant(_allow_record(), note, "planter-alpha")
        outcome = run_check(narrowed_check, faulted, "checker-beta", ledger)
        self.assertFalse(outcome.caught)

        result = reveal(note, commitment, ledger)
        self.assertEqual(result.outcome, REVEALED)
        self.assertEqual(len(ledger.misses()), 1)
        # The passes after the last observed catch are void; the earlier
        # evidence is untouched.
        statuses = {row.seq: row.status for row in ledger.passes()}
        self.assertEqual(statuses[2], STATUS_VOID)
        self.assertEqual(statuses[3], STATUS_VOID)
        self.assertEqual(len(ledger.valid_passes()), 0)
        # The catch itself survives -- it was observed.
        self.assertEqual(len(ledger.catches()), 1)

    def test_the_real_check_is_not_weakened_by_the_miss_demo(self):
        # The same real check that caught the planted fault still fires
        # afterwards: the miss demo used a double, not a narrowed real one.
        ledger = EvidenceLedger()
        note = _note()
        commitment = post_commitment(note, ledger)
        faulted = plant(_allow_record(), note, "planter-alpha")
        self.assertTrue(_kill_switch_check(faulted))


class RegistryTriggerTests(unittest.TestCase):
    """The planted faults against the repository's real triggers."""

    def test_the_kill_switch_trigger_fires_on_a_planted_permission_deny(self):
        note = _note()
        faulted = plant(_allow_record(), note, "planter-alpha")
        triggers = DEFAULT_REGISTRY.matches(faulted)
        self.assertTrue(triggers)
        self.assertEqual(triggers[0].kind, "kill-switch")

    def test_the_config_drift_trigger_fires_on_a_planted_drift(self):
        note = _note(
            plant_id="plant-drift",
            field="intent",
            wrong_value="permission.config-drift",
            true_value="permission-allow",
            check_scope="config-drift",
        )
        faulted = plant(_allow_record(), note, "planter-alpha")
        triggers = DEFAULT_REGISTRY.matches(faulted)
        self.assertTrue(triggers)
        self.assertIn("config-drift", {t.kind for t in triggers})

    def test_a_plant_in_an_unrelated_field_does_not_false_trigger(self):
        note = _note(field="subject", wrong_value="DefinitelyNotShell")
        faulted = plant(_allow_record(), note, "planter-alpha")
        self.assertEqual(faulted["outcome"], "permission.allow")
        self.assertEqual(DEFAULT_REGISTRY.matches(faulted), ())

    def test_the_check_cannot_read_the_plant_metadata(self):
        # The blind check sees the mapping only -- the plant id and the
        # true value are attributes, not mapping keys.
        note = _note()
        faulted = plant(_allow_record(), note, "planter-alpha")
        self.assertNotIn("plant_id", faulted)
        self.assertNotIn("true_value", faulted)
        self.assertNotIn(note.true_value, list(faulted.values()))


if __name__ == "__main__":
    unittest.main()


class ModuleHygieneTests(unittest.TestCase):
    """House style: stdlib-only, self-check, version/schema pins."""

    def test_the_module_imports_stdlib_only(self):
        import planted_fault

        self.assertTrue(planted_fault.stdlib_only())

    def test_the_module_self_check_runs(self):
        import planted_fault

        planted_fault.main()

    def test_the_version_and_schema_pins_are_declared(self):
        import planted_fault

        self.assertTrue(planted_fault.PLANTED_FAULT_VERSION)
        self.assertTrue(planted_fault.SCHEMA_PIN)

    def test_a_plant_with_no_posted_commitment_is_void(self):
        # Nothing was ever promised, so nothing here can be evidence.
        ledger = EvidenceLedger()
        note = _note()
        commitment = post_commitment(note)  # not posted to the ledger
        result = reveal(note, commitment, ledger)
        self.assertEqual(result.outcome, VOID_PLANT)
        self.assertEqual(len(ledger.catches()), 0)


class SecondHalfGuardTests(unittest.TestCase):
    """The second half of every guard in the planted-fault module.

    Each surviving mutant is one arm of a two-armed conditional, or one
    half of a conjunction, and the rest of the suite drove only the
    other arm.  These tests drive the missing half.
    """

    # -- or@384: the commitment-match guard ----------------------------

    def test_a_wrong_commitment_is_reported_as_a_mismatch(self):
        """`or@384`: the "or the commitment is wrong" half.

        The guard is ``if not commitment or commitment != computed``.
        The suite drove the "no commitment at all" half; this drives a
        commitment that is present but does not match the note.  The
        outcome must say the commitment MISMATCHED -- not that no
        commitment was posted.
        """
        ledger = EvidenceLedger()
        note = _note()
        # A truthy commitment that is not the note's digest, and no
        # commitment was ever posted to the ledger.
        wrong = "sha256:" + "0" * 64
        result = reveal(note, wrong, ledger)
        self.assertEqual(result.outcome, VOID_PLANT)
        self.assertEqual(result.detail, "commitment mismatch")

    def test_a_matching_commitment_reports_no_mismatch(self):
        """`or@384`: the control -- the matching commitment does not
        reach the mismatch branch."""
        ledger = EvidenceLedger()
        note = _note()
        commitment = post_commitment(note, ledger)
        faulted = plant(_allow_record(), note, "planter-alpha")
        run_check(_kill_switch_check, faulted, "checker-beta", ledger)
        result = reveal(note, commitment, ledger)
        self.assertEqual(result.outcome, REVEALED)
        self.assertNotEqual(result.detail, "commitment mismatch")

    # -- or@441: the ledger's commitment guard -------------------------

    def test_posting_an_empty_commitment_is_refused(self):
        """`or@441`: the "or the commitment is empty" half.

        The guard is ``if not plant_id or not commitment``.  The suite
        drove the plant-id half; this drives the commitment half.
        """
        from planted_fault import CommitmentError

        ledger = EvidenceLedger()
        with self.assertRaises(CommitmentError):
            ledger.post_commitment("plant-1", "")
        self.assertIsNone(ledger.commitment_for("plant-1"))

    def test_posting_an_empty_plant_id_is_refused(self):
        """`or@441`: the other half -- an empty plant id."""
        from planted_fault import CommitmentError

        ledger = EvidenceLedger()
        with self.assertRaises(CommitmentError):
            ledger.post_commitment("", "sha256:abc")
        self.assertIsNone(ledger.commitment_for(""))

    def test_posting_a_real_commitment_is_accepted(self):
        """`or@441`: the control -- a complete commitment is accepted."""
        ledger = EvidenceLedger()
        ledger.post_commitment("plant-1", "sha256:abc")
        self.assertEqual(ledger.commitment_for("plant-1"), "sha256:abc")

    # -- eq@467 / and@467: the dead-plant lookup -----------------------

    def test_a_voided_plant_is_dead(self):
        """`eq@467`: the "and it is a VOID_PLANT row" half.

        The lookup is ``row.kind == KIND_VOID_PLANT and row.plant_id ==
        plant_id``.  A ledger holding a VOID_PLANT row for this plant
        must report it dead.
        """
        ledger = EvidenceLedger()
        self.assertFalse(ledger.plant_is_dead("plant-1"))
        ledger.record_void_plant("plant-1", "commitment mismatch")
        self.assertTrue(ledger.plant_is_dead("plant-1"))

    def test_a_caught_plant_is_not_dead(self):
        """`and@467`: the other half -- the row's plant id must match.

        A CATCH row for this plant is not a VOID_PLANT row: the plant
        was caught, not voided, so it is not dead.
        """
        ledger = EvidenceLedger()
        ledger.record_catch("plant-1", 1, seq=1)
        self.assertFalse(ledger.plant_is_dead("plant-1"))

    def test_a_void_plant_of_another_plant_does_not_kill_this_one(self):
        """`eq@467` / `and@467`: the plant-id half, across plants."""
        ledger = EvidenceLedger()
        ledger.record_void_plant("plant-2", "commitment mismatch")
        self.assertFalse(ledger.plant_is_dead("plant-1"))
        self.assertTrue(ledger.plant_is_dead("plant-2"))

    # -- or@561: the void-back-to-last-catch filter --------------------

    def test_a_second_void_back_voids_nothing_new(self):
        """`or@561`: the "or the row is not still a PASS" half.

        The filter is ``if row.kind != KIND_PASS or row.status !=
        STATUS_PASS: continue``.  A pass that was ALREADY voided is not
        voided a second time: the second sweep returns nothing.
        """
        ledger = EvidenceLedger()
        ledger.record_pass("kill-switch", 1, seq=10)
        ledger.record_miss("plant-1", 2, seq=11)
        self.assertEqual(len(ledger.voided_passes()), 1)
        # A second sweep must find nothing new to void.
        self.assertEqual(list(ledger.void_back_to_last_catch()), [])
        self.assertEqual(len(ledger.voided_passes()), 1)

    def test_a_catch_row_is_never_voided(self):
        """`or@561`: the other half -- a row of another kind.

        A CATCH row is not a PASS row, so the sweep leaves it alone.
        """
        ledger = EvidenceLedger()
        ledger.record_catch("plant-1", 1, seq=10)
        ledger.record_miss("plant-2", 2, seq=11)
        self.assertEqual(len(ledger.voided_passes()), 0)
        self.assertEqual(len(ledger.catches()), 1)

    # -- gt@563: the last-catch comparison -----------------------------

    def test_a_pass_at_the_same_seq_as_the_last_catch_is_left_alone(self):
        """`gt@563`: the "or there is no last catch" half.

        The comparison is ``row.seq > last_catch``.  A pass whose seq is
        EQUAL to the last catch's seq is not after it, so it is not
        voided.  (The rule voids passes *after* the last catch, and the
        boundary itself belongs to the catch.)
        """
        ledger = EvidenceLedger()
        ledger.record_catch("plant-1", 1, seq=10)
        ledger.record_pass("kill-switch", 2, seq=10)
        ledger.record_miss("plant-2", 3, seq=11)
        self.assertEqual(len(ledger.voided_passes()), 0)
        self.assertEqual(len(ledger.valid_passes()), 1)

    def test_a_pass_after_the_last_catch_is_voided(self):
        """`gt@563`: the control -- a pass strictly after is voided."""
        ledger = EvidenceLedger()
        ledger.record_catch("plant-1", 1, seq=10)
        ledger.record_pass("kill-switch", 2, seq=11)
        ledger.record_miss("plant-2", 3, seq=12)
        self.assertEqual(len(ledger.voided_passes()), 1)
        self.assertEqual(len(ledger.valid_passes()), 0)

    # -- and@600: the voided-pass filter -------------------------------

    def test_a_valid_pass_is_not_a_voided_pass(self):
        """`and@600`: the "and it is VOID" half.

        The filter is ``row.kind == KIND_PASS and row.status ==
        STATUS_VOID``.  A pass that still counts as evidence is not a
        voided pass.
        """
        ledger = EvidenceLedger()
        ledger.record_pass("kill-switch", 1, seq=10)
        self.assertEqual(len(ledger.valid_passes()), 1)
        self.assertEqual(len(ledger.voided_passes()), 0)

    def test_a_voided_pass_is_a_voided_pass(self):
        """`and@600`: the control -- a voided pass is counted."""
        ledger = EvidenceLedger()
        ledger.record_pass("kill-switch", 1, seq=10)
        ledger.record_miss("plant-1", 2, seq=11)
        self.assertEqual(len(ledger.voided_passes()), 1)
        self.assertEqual(len(ledger.valid_passes()), 0)


class StdlibOnlyGuardTests(unittest.TestCase):
    """The stdlib-only guard's refusal half.

    ``stdlib_only()`` walks the module's own AST and refuses any import
    outside the allowed set.  The suite drove only the "this module is
    stdlib-only" half; the refusal half needs a source that is not, so
    these tests point the check at stand-in sources.
    """

    def _check_source(self, source: str) -> bool:
        """Run ``stdlib_only()`` against a stand-in source file."""
        import tempfile

        import planted_fault as pf

        with tempfile.NamedTemporaryFile(
            "w", suffix=".py", delete=False, encoding="utf-8"
        ) as handle:
            handle.write(source)
            path = handle.name

        original = pf.__file__
        try:
            pf.__file__ = path
            return pf.stdlib_only()
        finally:
            pf.__file__ = original

    def test_a_forbidden_plain_import_is_refused(self):
        """`retF@653`: the ``ast.Import`` branch's refusal.

        ``import numpy`` is not in the allowed set, so the module that
        holds it is not stdlib-only.
        """
        self.assertFalse(self._check_source("import json\nimport numpy\n"))

    def test_a_forbidden_from_import_is_refused(self):
        """`retF@656`: the ``ast.ImportFrom`` branch's refusal.

        ``from requests import get`` is not in the allowed set.
        """
        self.assertFalse(self._check_source("from requests import get\n"))

    def test_an_allowed_source_is_accepted(self):
        """The control -- a source with only allowed imports passes."""
        self.assertTrue(
            self._check_source(
                "import ast\nimport hashlib\nfrom dataclasses import dataclass\n"
            )
        )

    def test_the_module_itself_is_stdlib_only(self):
        """The control -- the real module passes its own check."""
        import planted_fault as pf

        self.assertTrue(pf.stdlib_only())


class SelfCheckTests(unittest.TestCase):
    """The module's own self-check, pinned.

    ``planted_fault.main()`` is the module's self-check: plant, blind
    check, reveal, catch, then a pass.  The suite ran it once without
    asserting anything about it, so the ``__main__`` guard was free.
    """

    def test_the_module_self_checks_when_run_as_a_script(self):
        """`eq@691`: the ``__name__ == "__main__"`` guard.

        Run as a script, the module self-checks and says so; run as an
        import, it says nothing.
        """
        import subprocess
        import sys
        from pathlib import Path

        import planted_fault as pf

        component = Path(pf.__file__).resolve().parent
        result = subprocess.run(
            [sys.executable, "-m", "planted_fault"],
            cwd=str(component),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=180,
        )
        output = result.stdout.decode("utf-8", "replace")
        self.assertEqual(result.returncode, 0, output)
        self.assertIn("planted-fault OK", output)

    def test_the_self_check_pins_the_planted_value(self):
        """The self-check's claim: the fault is in the INPUT.

        The record's ``outcome`` carries the wrong value, and the
        original input is left alone.
        """
        note = PlantNote(
            plant_id="p1",
            run_index=3,
            field="outcome",
            wrong_value="permission.deny",
            true_value="permission.allow",
            planted_by="planter-1",
            check_scope="kill-switch",
        )
        record = {"outcome": "permission.allow"}
        faulted = plant(record, note, "planter-1")
        self.assertEqual(faulted["outcome"], "permission.deny")
        self.assertEqual(record["outcome"], "permission.allow")

    def test_the_self_check_pins_the_catch(self):
        """The self-check's claim: the blind check catches the fault.

        The reveal is REVEALED and the ledger holds exactly one catch.
        """
        note = PlantNote(
            plant_id="p1",
            run_index=3,
            field="outcome",
            wrong_value="permission.deny",
            true_value="permission.allow",
            planted_by="planter-1",
            check_scope="kill-switch",
        )
        ledger = EvidenceLedger()
        commitment = post_commitment(note, ledger)
        faulted = plant({"outcome": "permission.allow"}, note, "planter-1")
        outcome = run_check(
            lambda record: record.get("outcome") == "permission.deny",
            faulted, "checker-2", ledger,
        )
        result = reveal(note, commitment, ledger)
        self.assertTrue(outcome.caught)
        self.assertEqual(result.outcome, REVEALED)
        self.assertEqual(len(ledger.catches()), 1)

    def test_the_self_check_pins_the_valid_pass(self):
        """The self-check's last claim: one pass still counts.

        After the catch, a recorded PASS is still a valid pass.
        """
        ledger = EvidenceLedger()
        ledger.record_pass("kill-switch", 4, seq=10)
        self.assertEqual(len(ledger.valid_passes()), 1)
