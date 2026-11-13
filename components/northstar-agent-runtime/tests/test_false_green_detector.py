"""Tests for the false-green detector.

The rules under test (from the slice brief's acceptance list):

* GREEN requires a success status *and* every content validator passing;
* a success status with a failing content validator is FALSE_GREEN, and the
  reason names the validator and why it failed (all of them, when several
  fail);
* a success status with no validator registered is UNVALIDATED, never GREEN;
* a FAIL status is never upgraded, and content validators do not run for it;
* the four built-in validators: schema, range, consistency, non-empty.
"""
from __future__ import annotations

import unittest

from false_green_detector import (
    FAILURE_STATUSES,
    SUCCESS_STATUSES,
    ContentValidator,
    SuccessSignal,
    Verdict,
    check,
    consistency_validator,
    is_success_status,
    non_empty_validator,
    range_validator,
    schema_validator,
)


class VerdictVocabularyTests(unittest.TestCase):
    def test_the_verdict_vocabulary_is_exactly_four_states(self):
        self.assertEqual(
            sorted(verdict.value for verdict in Verdict),
            ["fail", "false_green", "green", "unvalidated"],
        )

    def test_the_success_signal_is_frozen(self):
        signal = SuccessSignal(status="200", payload={"a": 1}, source="unit")
        with self.assertRaises(Exception):
            signal.status = "500"  # type: ignore[misc]

    def test_a_success_signal_copies_its_payload(self):
        payload = {"a": 1}
        signal = SuccessSignal(status="200", payload=payload)
        payload["a"] = 2
        self.assertEqual(signal.payload, {"a": 1})


class StatusVocabularyTests(unittest.TestCase):
    def test_a_200_is_a_success_status(self):
        self.assertTrue(is_success_status("200"))
        self.assertTrue(is_success_status("OK"))
        self.assertTrue(is_success_status("pass"))

    def test_a_500_is_not_a_success_status(self):
        self.assertFalse(is_success_status("500"))
        self.assertFalse(is_success_status("FAILED"))
        self.assertIn("500", FAILURE_STATUSES)

    def test_an_unknown_status_is_not_a_success_status(self):
        # Fail-closed: a status nobody declared cannot read as success.
        self.assertFalse(is_success_status("banana"))
        self.assertFalse(is_success_status(""))

    def test_the_success_and_failure_vocabularies_do_not_overlap(self):
        self.assertEqual(SUCCESS_STATUSES & FAILURE_STATUSES, frozenset())


class GreenPathTests(unittest.TestCase):
    """Path (a): a 200 with a complete, valid payload is GREEN."""

    def test_status_200_with_a_valid_payload_is_green(self):
        signal = SuccessSignal(
            status="200",
            payload={"items": [1, 2, 3], "count": 3},
            source="unit",
        )
        verdict, reason = check(signal, [
            schema_validator(["items", "count"]),
            range_validator({"count": (0, 10)}),
            non_empty_validator(["items"]),
        ])
        self.assertEqual(verdict, Verdict.GREEN)
        self.assertIn("200", reason)

    def test_green_requires_the_status_to_be_a_success(self):
        # The same payload and the same validators, but the status says 500.
        signal = SuccessSignal(status="500", payload={"count": 3})
        verdict, _ = check(signal, [schema_validator(["count"])])
        self.assertNotEqual(verdict, Verdict.GREEN)

    def test_green_requires_every_registered_validator_to_pass(self):
        signal = SuccessSignal(status="200", payload={"count": 3})
        verdict, reason = check(signal, [
            schema_validator(["count"]),
            range_validator({"count": (0, 10)}),
            range_validator({"count": (0, 1)}),  # this one fails
        ])
        self.assertEqual(verdict, Verdict.FALSE_GREEN)
        self.assertIn("range", reason)


class FalseGreenPathTests(unittest.TestCase):
    """Paths (b), (c), (d): a 200 whose content is not acceptable."""

    def test_a_200_missing_a_required_key_is_false_green_naming_schema(self):
        signal = SuccessSignal(status="200", payload={"count": 3})
        verdict, reason = check(signal, [schema_validator(["items", "count"])])
        self.assertEqual(verdict, Verdict.FALSE_GREEN)
        self.assertIn("schema", reason)
        self.assertIn("items", reason)

    def test_a_200_with_a_value_out_of_range_is_false_green_naming_range(self):
        signal = SuccessSignal(status="200", payload={"count": 99})
        verdict, reason = check(signal, [range_validator({"count": (0, 10)})])
        self.assertEqual(verdict, Verdict.FALSE_GREEN)
        self.assertIn("range", reason)
        self.assertIn("99", reason)

    def test_a_200_with_a_self_contradicting_payload_is_false_green_naming_consistency(self):
        signal = SuccessSignal(status="200", payload={"start": 10, "end": 3})
        verdict, reason = check(signal, [
            consistency_validator([("end", ">=", "start")]),
        ])
        self.assertEqual(verdict, Verdict.FALSE_GREEN)
        self.assertIn("consistency", reason)

    def test_an_empty_payload_is_false_green_naming_non_empty(self):
        signal = SuccessSignal(status="200", payload={})
        verdict, reason = check(signal, [non_empty_validator()])
        self.assertEqual(verdict, Verdict.FALSE_GREEN)
        self.assertIn("non_empty", reason)

    def test_a_blank_expected_field_is_false_green(self):
        signal = SuccessSignal(status="200", payload={"summary": "   "})
        verdict, reason = check(signal, [non_empty_validator(["summary"])])
        self.assertEqual(verdict, Verdict.FALSE_GREEN)
        self.assertIn("non_empty", reason)

    def test_several_failing_validators_are_all_listed(self):
        signal = SuccessSignal(status="200", payload={"count": 99})
        verdict, reason = check(signal, [
            schema_validator(["items"]),
            range_validator({"count": (0, 10)}),
            consistency_validator([("count", ">=", "items")]),
        ])
        self.assertEqual(verdict, Verdict.FALSE_GREEN)
        self.assertIn("schema", reason)
        self.assertIn("range", reason)
        self.assertIn("consistency", reason)


class UnvalidatedPathTests(unittest.TestCase):
    """Path (e): a 200 with no validator registered is UNVALIDATED."""

    def test_a_200_with_no_validator_registered_is_unvalidated_not_green(self):
        signal = SuccessSignal(status="200", payload={"count": 3})
        verdict, reason = check(signal, [])
        self.assertEqual(verdict, Verdict.UNVALIDATED)
        self.assertNotEqual(verdict, Verdict.GREEN)
        self.assertIn("no content validator", reason)

    def test_a_200_with_no_validators_argument_is_unvalidated(self):
        signal = SuccessSignal(status="200", payload={"count": 3})
        verdict, _ = check(signal, None)
        self.assertEqual(verdict, Verdict.UNVALIDATED)

    def test_a_200_with_an_empty_validator_tuple_is_unvalidated(self):
        signal = SuccessSignal(status="200", payload={"count": 3})
        verdict, _ = check(signal, ())
        self.assertEqual(verdict, Verdict.UNVALIDATED)


class FailPathTests(unittest.TestCase):
    """Path (f): a 500 is FAIL, and a failure is never upgraded."""

    def test_a_500_is_fail_even_when_the_payload_looks_fine(self):
        signal = SuccessSignal(status="500", payload={"items": [1], "count": 1})
        verdict, reason = check(signal, [
            schema_validator(["items", "count"]),
            range_validator({"count": (0, 10)}),
        ])
        self.assertEqual(verdict, Verdict.FAIL)
        self.assertIn("500", reason)

    def test_a_fail_status_is_never_upgraded_to_green(self):
        for status in sorted(FAILURE_STATUSES):
            with self.subTest(status=status):
                signal = SuccessSignal(status=status, payload={"count": 3})
                verdict, _ = check(signal, [
                    schema_validator(["count"]),
                    range_validator({"count": (0, 10)}),
                    non_empty_validator(["count"]),
                ])
                self.assertNotEqual(verdict, Verdict.GREEN)
                self.assertEqual(verdict, Verdict.FAIL)

    def test_content_validators_do_not_run_for_a_failing_status(self):
        calls = []

        def _probe(payload):
            calls.append(payload)
            return True, "should not be consulted"

        signal = SuccessSignal(status="500", payload={"count": 3})
        verdict, _ = check(signal, [_probe])
        self.assertEqual(verdict, Verdict.FAIL)
        self.assertEqual(calls, [])

    def test_an_unknown_status_fails_closed(self):
        signal = SuccessSignal(status="banana", payload={"count": 3})
        verdict, reason = check(signal, [schema_validator(["count"])])
        self.assertEqual(verdict, Verdict.FAIL)
        self.assertIn("banana", reason)


class ValidatorCompositionTests(unittest.TestCase):
    """The four built-in validators, and their composition."""

    def test_the_schema_validator_checks_presence_only(self):
        validator = schema_validator(["a"])
        ok, _ = validator({"a": None})
        self.assertTrue(ok)
        ok, reason = validator({"b": 1})
        self.assertFalse(ok)
        self.assertIn("'a'", reason)

    def test_the_range_validator_rejects_a_non_numeric_value(self):
        validator = range_validator({"n": (0, 10)})
        ok, reason = validator({"n": "seven"})
        self.assertFalse(ok)
        self.assertIn("not numeric", reason)

    def test_the_range_validator_rejects_an_absent_field(self):
        validator = range_validator({"n": (0, 10)})
        ok, reason = validator({})
        self.assertFalse(ok)
        self.assertIn("absent", reason)

    def test_the_range_validator_honours_an_open_bound(self):
        validator = range_validator({"n": (None, 10)})
        self.assertTrue(validator({"n": -5})[0])
        self.assertFalse(validator({"n": 11})[0])

    def test_the_range_validator_includes_the_bounds_itself(self):
        # A value exactly on the boundary is in range, not out of it.
        validator = range_validator({"n": (0, 10)})
        self.assertTrue(validator({"n": 0})[0])
        self.assertTrue(validator({"n": 10})[0])
        self.assertFalse(validator({"n": -1})[0])
        self.assertFalse(validator({"n": 11})[0])

    def test_the_consistency_validator_checks_a_cross_field_invariant(self):
        validator = consistency_validator([("end", ">=", "start")])
        self.assertTrue(validator({"start": 1, "end": 2})[0])
        ok, reason = validator({"start": 5, "end": 2})
        self.assertFalse(ok)
        self.assertIn("invariant violated", reason)

    def test_the_consistency_validator_rejects_an_unknown_comparison(self):
        with self.assertRaises(ValueError):
            consistency_validator([("end", "~~", "start")])

    def test_the_non_empty_validator_checks_the_whole_payload_or_named_fields(self):
        self.assertFalse(non_empty_validator()({})[0])
        self.assertTrue(non_empty_validator()({"a": 1})[0])
        self.assertFalse(non_empty_validator(["a"])({})[0])
        self.assertFalse(non_empty_validator(["a"])({"a": []})[0])
        self.assertTrue(non_empty_validator(["a"])({"a": [1]})[0])

    def test_the_non_empty_validator_treats_a_blank_string_as_empty(self):
        validator = non_empty_validator(["summary"])
        ok, reason = validator({"summary": "   "})
        self.assertFalse(ok)
        self.assertIn("blank", reason)
        self.assertTrue(validator({"summary": "text"})[0])

    def test_the_non_empty_validator_treats_an_empty_container_as_empty(self):
        validator = non_empty_validator(["items"])
        ok, reason = validator({"items": {}})
        self.assertFalse(ok)
        self.assertIn("no content", reason)
        self.assertTrue(validator({"items": {"a": 1}})[0])

    def test_validators_compose_and_all_of_them_must_pass(self):
        validators = [
            schema_validator(["count", "items"]),
            range_validator({"count": (0, 10)}),
            consistency_validator([("end", ">=", "start")]),
            non_empty_validator(["items"]),
        ]
        good = SuccessSignal(status="200", payload={
            "count": 3, "items": [1, 2], "start": 1, "end": 2})
        self.assertEqual(check(good, validators)[0], Verdict.GREEN)
        bad = SuccessSignal(status="200", payload={
            "count": 3, "items": [1, 2], "start": 9, "end": 2})
        self.assertEqual(check(bad, validators)[0], Verdict.FALSE_GREEN)

    def test_a_validator_that_raises_is_treated_as_a_failed_check(self):
        def _boom(payload):
            raise RuntimeError("the checker itself broke")

        signal = SuccessSignal(status="200", payload={"count": 3})
        verdict, reason = check(signal, [_boom])
        self.assertEqual(verdict, Verdict.FALSE_GREEN)
        self.assertIn("RuntimeError", reason)

