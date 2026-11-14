"""Tests for resume_validation."""

from __future__ import annotations

import unittest

from resume_validation import (
    RESUME_VALIDATION_VERSION,
    DuplicateInterruptError,
    InterruptAlreadyResolvedError,
    InterruptExpiredError,
    PayloadNotSerializableError,
    ResumeValidationError,
    SchemaViolationError,
    UnknownInterruptError,
)

APPROVAL_SCHEMA = {
    "fields": {
        "approved": {"type": "bool"},
        "note": {"type": "str", "default": ""},
    },
    "required": ["approved"],
}


class VersionTest(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(RESUME_VALIDATION_VERSION, "resume-validation.v1")


class DeclareTest(unittest.TestCase):
    def setUp(self):
        from resume_validation import ResumeValidator

        self.v = ResumeValidator()

    def test_declare_registers_pending_interrupt(self):
        decl = self.v.declare("a#0", {"q": "approve?"}, APPROVAL_SCHEMA, seq=1)
        self.assertEqual(decl.interrupt_id, "a#0")
        self.assertEqual(decl.payload, {"q": "approve?"})
        self.assertEqual(decl.seq, 1)
        self.assertEqual(len(self.v.pending()), 1)

    def test_declare_rejects_non_json_payload(self):
        with self.assertRaises(PayloadNotSerializableError):
            self.v.declare("a#0", {"q": object()}, None, seq=1)
        self.assertEqual(self.v.pending(), [])

    def test_declare_rejects_duplicate_id(self):
        self.v.declare("a#0", {"q": 1}, None, seq=1)
        with self.assertRaises(DuplicateInterruptError):
            self.v.declare("a#0", {"q": 2}, None, seq=2)
        self.assertEqual(len(self.v.pending()), 1)

    def test_declare_rejects_duplicate_id_after_resolution(self):
        self.v.declare("a#0", {"q": 1}, None, seq=1)
        self.v.resolve("a#0", {"q": 1}, seq=2)
        with self.assertRaises(DuplicateInterruptError):
            self.v.declare("a#0", {"q": 3}, None, seq=3)

    def test_declare_rejects_empty_id(self):
        with self.assertRaises(ResumeValidationError):
            self.v.declare("", {"q": 1}, None, seq=1)

    def test_declare_rejects_bad_seq(self):
        with self.assertRaises(TypeError):
            self.v.declare("a#0", {"q": 1}, None, seq="1")
        with self.assertRaises(ValueError):
            self.v.declare("a#0", {"q": 1}, None, seq=-1)


class PendingTest(unittest.TestCase):
    def setUp(self):
        from resume_validation import ResumeValidator

        self.v = ResumeValidator()

    def test_empty_pending_means_nothing_is_waiting(self):
        self.assertEqual(self.v.pending(), [])

    def test_pending_lists_id_payload_and_schema(self):
        self.v.declare("a#0", {"q": "approve?"}, APPROVAL_SCHEMA, seq=1)
        self.v.declare("b#0", {"q": "retry?"}, None, seq=2)
        pending = self.v.pending()
        self.assertEqual([d.interrupt_id for d in pending], ["a#0", "b#0"])
        self.assertEqual(pending[0].payload, {"q": "approve?"})
        self.assertIsNotNone(pending[0].response_schema)
        self.assertIsNone(pending[1].response_schema)

    def test_pending_is_empty_after_resolution(self):
        self.v.declare("a#0", {"q": 1}, None, seq=1)
        self.v.resolve("a#0", {"q": 1}, seq=2)
        self.assertEqual(self.v.pending(), [])
        self.assertEqual([r.interrupt_id for r in self.v.resolved()], ["a#0"])


class ValidateTest(unittest.TestCase):
    def setUp(self):
        from resume_validation import ResumeValidator

        self.v = ResumeValidator()
        self.v.declare("a#0", {"q": "approve?"}, APPROVAL_SCHEMA, seq=1)

    def test_valid_value_passes_and_fills_default(self):
        validated = self.v.validate_resume({"a#0": {"approved": True}})
        self.assertEqual(validated, {"a#0": {"approved": True, "note": ""}})

    def test_explicit_value_is_kept(self):
        validated = self.v.validate_resume({"a#0": {"approved": False, "note": "no"}})
        self.assertEqual(validated["a#0"], {"approved": False, "note": "no"})

    def test_wrong_type_is_rejected(self):
        with self.assertRaises(SchemaViolationError):
            self.v.validate_resume({"a#0": {"approved": "yes"}})

    def test_missing_required_field_is_rejected(self):
        with self.assertRaises(SchemaViolationError):
            self.v.validate_resume({"a#0": {"note": "no"}})

    def test_rejected_value_consumes_nothing(self):
        with self.assertRaises(SchemaViolationError):
            self.v.validate_resume({"a#0": {"approved": "yes"}})
        self.assertEqual(len(self.v.pending()), 1)
        self.assertEqual(self.v.resolved(), [])

    def test_unknown_id_rejects_the_whole_call(self):
        with self.assertRaises(UnknownInterruptError):
            self.v.validate_resume({"nope#0": {"approved": True}})
        self.assertEqual(len(self.v.pending()), 1)

    def test_unknown_id_alongside_valid_id_rejects_everything(self):
        with self.assertRaises(UnknownInterruptError):
            self.v.validate_resume(
                {"a#0": {"approved": True}, "nope#0": {"approved": True}}
            )
        self.assertEqual(len(self.v.pending()), 1)
        self.assertEqual(self.v.resolved(), [])

    def test_non_mapping_value_is_rejected(self):
        with self.assertRaises(SchemaViolationError):
            self.v.validate_resume({"a#0": "yes"})

    def test_non_mapping_resume_map_is_rejected(self):
        with self.assertRaises(ResumeValidationError):
            self.v.validate_resume([("a#0", {"approved": True})])

    def test_value_out_of_range_is_rejected(self):
        from resume_validation import ResumeValidator

        v = ResumeValidator()
        v.declare(
            "r#0",
            {"q": "score?"},
            {"fields": {"score": {"type": "int", "minimum": 0, "maximum": 10}}},
            seq=1,
        )
        self.assertEqual(v.validate_resume({"r#0": {"score": 10}})["r#0"], {"score": 10})
        with self.assertRaises(SchemaViolationError):
            v.validate_resume({"r#0": {"score": 11}})
        with self.assertRaises(SchemaViolationError):
            v.validate_resume({"r#0": {"score": -1}})
        self.assertEqual(len(v.pending()), 1)

    def test_value_outside_enum_is_rejected(self):
        from resume_validation import ResumeValidator

        v = ResumeValidator()
        v.declare(
            "e#0",
            {"q": "mode?"},
            {"fields": {"mode": {"type": "str", "enum": ["fast", "safe"]}}},
            seq=1,
        )
        self.assertEqual(
            v.validate_resume({"e#0": {"mode": "safe"}})["e#0"], {"mode": "safe"}
        )
        with self.assertRaises(SchemaViolationError):
            v.validate_resume({"e#0": {"mode": "reckless"}})

    def test_value_without_schema_passes_through_unchanged(self):
        from resume_validation import ResumeValidator

        v = ResumeValidator()
        v.declare("f#0", {"q": "anything"}, None, seq=1)
        raw = {"whatever": [1, 2, 3]}
        self.assertEqual(v.validate_resume({"f#0": raw})["f#0"], raw)

    def test_int_schema_rejects_bool(self):
        from resume_validation import ResumeValidator

        v = ResumeValidator()
        v.declare("i#0", {"q": "n?"}, {"fields": {"n": {"type": "int"}}}, seq=1)
        with self.assertRaises(SchemaViolationError):
            v.validate_resume({"i#0": {"n": True}})

    def test_malformed_schema_is_refused_at_declaration(self):
        from resume_validation import InvalidSchemaError, ResumeValidator

        v = ResumeValidator()
        with self.assertRaises(InvalidSchemaError):
            v.declare("m#0", {"q": 1}, {"fields": {"a": {"type": "wat"}}}, seq=1)
        with self.assertRaises(InvalidSchemaError):
            v.declare("m#1", {"q": 1}, {"required": ["ghost"]}, seq=2)

    def test_schema_with_inverted_bounds_is_refused(self):
        from resume_validation import InvalidSchemaError, ResumeValidator

        v = ResumeValidator()
        with self.assertRaises(InvalidSchemaError):
            v.declare(
                "b#0",
                {"q": 1},
                {"fields": {"n": {"type": "int", "minimum": 10, "maximum": 0}}},
                seq=1,
            )

    def test_schema_with_non_numeric_bound_is_refused(self):
        from resume_validation import InvalidSchemaError, ResumeValidator

        v = ResumeValidator()
        with self.assertRaises(InvalidSchemaError):
            v.declare(
                "b#1",
                {"q": 1},
                {"fields": {"n": {"type": "int", "minimum": "zero"}}},
                seq=1,
            )

    def test_schema_with_non_finite_bound_is_refused(self):
        from resume_validation import InvalidSchemaError, ResumeValidator

        v = ResumeValidator()
        with self.assertRaises(InvalidSchemaError):
            v.declare(
                "b#2",
                {"q": 1},
                {"fields": {"n": {"type": "float", "minimum": float("inf")}}},
                seq=1,
            )

    def test_schema_with_nan_bound_is_refused(self):
        from resume_validation import InvalidSchemaError, ResumeValidator

        v = ResumeValidator()
        with self.assertRaises(InvalidSchemaError):
            v.declare(
                "b#4",
                {"q": 1},
                {"fields": {"n": {"type": "float", "maximum": float("nan")}}},
                seq=1,
            )

    def test_schema_with_negative_infinite_bound_is_refused(self):
        from resume_validation import InvalidSchemaError, ResumeValidator

        v = ResumeValidator()
        with self.assertRaises(InvalidSchemaError):
            v.declare(
                "b#5",
                {"q": 1},
                {"fields": {"n": {"type": "float", "minimum": float("-inf")}}},
                seq=1,
            )

    def test_schema_bounds_on_a_non_numeric_field_are_refused(self):
        from resume_validation import InvalidSchemaError, ResumeValidator

        v = ResumeValidator()
        with self.assertRaises(InvalidSchemaError):
            v.declare(
                "b#3",
                {"q": 1},
                {"fields": {"s": {"type": "str", "minimum": 0}}},
                seq=1,
            )

    def test_empty_enum_is_refused(self):
        from resume_validation import InvalidSchemaError, ResumeValidator

        v = ResumeValidator()
        with self.assertRaises(InvalidSchemaError):
            v.declare(
                "e#1",
                {"q": 1},
                {"fields": {"s": {"type": "str", "enum": []}}},
                seq=1,
            )



class ResolveTest(unittest.TestCase):
    def setUp(self):
        from resume_validation import ResumeValidator

        self.v = ResumeValidator()
        self.v.declare("a#0", {"q": "approve?"}, APPROVAL_SCHEMA, seq=1)

    def test_resolve_consumes_the_interrupt(self):
        validated = self.v.validate_resume({"a#0": {"approved": True}})
        record = self.v.resolve("a#0", validated["a#0"], seq=2)
        self.assertEqual(record.interrupt_id, "a#0")
        self.assertEqual(record.value, {"approved": True, "note": ""})
        self.assertEqual(self.v.pending(), [])
        self.assertEqual([r.interrupt_id for r in self.v.resolved()], ["a#0"])

    def test_double_resolve_is_refused(self):
        validated = self.v.validate_resume({"a#0": {"approved": True}})
        self.v.resolve("a#0", validated["a#0"], seq=2)
        with self.assertRaises(InterruptAlreadyResolvedError):
            self.v.resolve("a#0", validated["a#0"], seq=3)

    def test_resolve_unknown_id_is_refused(self):
        with self.assertRaises(UnknownInterruptError):
            self.v.resolve("ghost#0", {"approved": True}, seq=2)

    def test_resolve_expired_interrupt_is_refused(self):
        self.v.mark_expired("a#0")
        with self.assertRaises(InterruptExpiredError):
            self.v.resolve("a#0", {"approved": True}, seq=2)

    def test_expiry_never_auto_approves(self):
        self.v.mark_expired("a#0")
        self.assertEqual(self.v.pending(), [])
        self.assertEqual(self.v.resolved(), [])
        self.assertEqual([d.interrupt_id for d in self.v.expired()], ["a#0"])
        with self.assertRaises(InterruptExpiredError):
            self.v.validate_resume({"a#0": {"approved": True}})

    def test_expired_interrupt_is_not_pending_and_not_resolvable(self):
        self.v.declare("b#0", {"q": 1}, None, seq=2)
        self.v.mark_expired("a#0")
        self.assertEqual([d.interrupt_id for d in self.v.pending()], ["b#0"])

    def test_resolve_re_checks_the_value(self):
        with self.assertRaises(SchemaViolationError):
            self.v.resolve("a#0", {"approved": "yes"}, seq=2)
        self.assertEqual(len(self.v.pending()), 1)

    def test_mark_expired_twice_is_refused(self):
        self.v.mark_expired("a#0")
        with self.assertRaises(InterruptExpiredError):
            self.v.mark_expired("a#0")

    def test_mark_expired_unknown_is_refused(self):
        with self.assertRaises(UnknownInterruptError):
            self.v.mark_expired("ghost#0")


class RealPathTests(unittest.TestCase):
    """The three paths the task book asks to be driven for real.

    (a) an approval interrupt resumed with a well formed value;
    (b) the same interrupt resumed with a wrong-typed value -- the call is
        refused, the interrupt stays pending, and the corrected value is
        retried against the same run;
    (c) two pending interrupts resumed together, one of which is wrong --
        the whole call is refused and *both* stay pending.
    """

    def setUp(self):
        from resume_validation import ResumeValidator

        self.v = ResumeValidator()

    def test_path_a_approval_resume_passes_and_resolves(self):
        self.v.declare("approval#0", {"question": "approve?"}, APPROVAL_SCHEMA, seq=1)
        pending = self.v.pending()
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0].interrupt_id, "approval#0")
        self.assertEqual(pending[0].payload, {"question": "approve?"})
        self.assertIsNotNone(pending[0].response_schema)

        validated = self.v.validate_resume({"approval#0": {"approved": True}})
        self.assertEqual(validated["approval#0"], {"approved": True, "note": ""})

        record = self.v.resolve("approval#0", validated["approval#0"], seq=2)
        self.assertEqual(record.value, {"approved": True, "note": ""})
        self.assertEqual(self.v.pending(), [])
        self.assertEqual([r.interrupt_id for r in self.v.resolved()], ["approval#0"])

    def test_path_b_wrong_type_is_refused_then_corrected(self):
        self.v.declare("approval#0", {"question": "approve?"}, APPROVAL_SCHEMA, seq=1)
        with self.assertRaises(SchemaViolationError):
            self.v.validate_resume({"approval#0": {"approved": "yes"}})
        # Nothing was consumed: the interrupt is still waiting.
        self.assertEqual(len(self.v.pending()), 1)
        self.assertEqual(self.v.resolved(), [])

        # The corrected value is retried against the same run.
        validated = self.v.validate_resume(
            {"approval#0": {"approved": False, "note": "too risky"}}
        )
        self.assertEqual(
            validated["approval#0"], {"approved": False, "note": "too risky"}
        )
        self.v.resolve("approval#0", validated["approval#0"], seq=2)
        self.assertEqual(self.v.pending(), [])
        self.assertEqual(
            self.v.resolved()[0].value, {"approved": False, "note": "too risky"}
        )

    def test_path_c_two_interrupts_one_bad_rejects_the_whole_call(self):
        self.v.declare("a#0", {"question": "approve?"}, APPROVAL_SCHEMA, seq=1)
        self.v.declare(
            "b#0",
            {"question": "score?"},
            {"fields": {"score": {"type": "int", "minimum": 0, "maximum": 10}}},
            seq=2,
        )
        self.assertEqual(len(self.v.pending()), 2)

        with self.assertRaises(SchemaViolationError):
            self.v.validate_resume(
                {"a#0": {"approved": True}, "b#0": {"score": "high"}}
            )
        # Neither interrupt was consumed.
        self.assertEqual(len(self.v.pending()), 2)
        self.assertEqual(self.v.resolved(), [])

        validated = self.v.validate_resume(
            {"a#0": {"approved": True}, "b#0": {"score": 7}}
        )
        self.assertEqual(validated["a#0"], {"approved": True, "note": ""})
        self.assertEqual(validated["b#0"], {"score": 7})
        for interrupt_id in ("a#0", "b#0"):
            self.v.resolve(interrupt_id, validated[interrupt_id], seq=3)
        self.assertEqual(self.v.pending(), [])
        self.assertEqual(len(self.v.resolved()), 2)

    def test_path_c_unknown_id_rejects_the_whole_call(self):
        self.v.declare("a#0", {"question": "approve?"}, APPROVAL_SCHEMA, seq=1)
        self.v.declare("b#0", {"question": "ok?"}, None, seq=2)
        with self.assertRaises(UnknownInterruptError):
            self.v.validate_resume(
                {"a#0": {"approved": True}, "c#0": {"anything": 1}}
            )
        self.assertEqual(len(self.v.pending()), 2)



