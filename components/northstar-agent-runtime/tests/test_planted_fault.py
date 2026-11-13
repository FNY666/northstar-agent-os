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
