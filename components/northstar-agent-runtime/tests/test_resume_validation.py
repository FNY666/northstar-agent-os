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



class ResumeValidationGuardSecondHalfTests(unittest.TestCase):
    """The SECOND half of each surviving guard in ``resume_validation``.

    The slice's own suite drove only one arm of the guards below, so the
    planted faults on the other arm survived.  Every mutant target named in
    each docstring is the line of the module it refers to; the technique
    used to kill it is stated with it.

    The list is the census of the surviving mutants for this slice:

      gt@217   the inverted-bounds comparison
      or@355   the ``bool`` half of the ``seq`` type guard
      lt@357   the non-negative ``seq`` bound
      retT@364 the ``any`` kind shortcut
      and@370  the ``bool`` exclusion of the ``float`` kind
      and@372  the ``bool`` exclusion of the ``number`` kind
      eq@375   the ``list`` kind
      eq@377   the ``dict`` kind
      eq@379   the ``object`` kind
      retF@381 the unknown-kind fallback
      and@560  the numeric-kind half of the bounds check
      lt@561   the inclusive ``minimum`` bound
      eq@647   the first assertion of ``main()``
      eq@649   the second assertion of ``main()``
      eq@651   the third assertion of ``main()``
    """

    def _validator(self, fields, required=(), seq=1):
        from resume_validation import ResumeValidator

        v = ResumeValidator()
        v.declare(
            "a#0",
            {"q": "approve?"},
            {"fields": fields, "required": list(required)},
            seq=seq,
        )
        return v

    # -- gt@217: the inverted-bounds comparison ------------------------
    def test_a_minimum_equal_to_the_maximum_is_a_valid_schema(self):
        """gt@217: the bound is INCLUSIVE, so equal bounds are legal.

        The guard is ``minimum > maximum``.  A schema whose minimum
        EQUALS its maximum describes a single legal value, not an
        inverted range.  Under the mutant (``>`` -> ``>=``) such a schema
        would be refused as inverted, so a schema pinning one exact
        number could never be declared.
        """
        v = self._validator({"n": {"type": "int", "minimum": 5, "maximum": 5}})
        self.assertEqual(v.validate_resume({"a#0": {"n": 5}})["a#0"], {"n": 5})

    def test_a_minimum_above_the_maximum_is_still_refused(self):
        """gt@217: the control -- a genuinely inverted range is refused."""
        from resume_validation import InvalidSchemaError, ResumeValidator

        with self.assertRaises(InvalidSchemaError):
            ResumeValidator().declare(
                "b#0",
                {"q": 1},
                {"fields": {"n": {"type": "int", "minimum": 10, "maximum": 0}}},
                seq=1,
            )

    def test_a_schema_with_only_a_minimum_is_legal(self):
        """gt@217: the other arm of the same conjunction.

        The guard reads ``minimum is not None and maximum is not None and
        minimum > maximum``.  With no maximum at all the comparison never
        runs; under the mutant the schema would be refused as inverted.
        """
        v = self._validator({"n": {"type": "int", "minimum": 0}})
        self.assertEqual(v.validate_resume({"a#0": {"n": 0}})["a#0"], {"n": 0})

    # -- or@355: the ``bool`` half of the seq type guard --------------
    def test_a_boolean_seq_is_refused(self):
        """or@355: **a bool IS an int in Python**.

        The guard is ``isinstance(value, bool) or not isinstance(value,
        int)``.  The "not an int" half never refuses a bool -- only the
        explicit ``bool`` half does.  Under the mutant (``or`` -> ``and``)
        a boolean seq is accepted and used as the integer 0 or 1.
        """
        from resume_validation import ResumeValidator

        with self.assertRaises(TypeError):
            ResumeValidator().declare("a#0", {"q": 1}, None, seq=True)
        with self.assertRaises(TypeError):
            ResumeValidator().declare("a#1", {"q": 1}, None, seq=False)

    def test_a_string_seq_is_refused(self):
        """or@355: the other half, as the control."""
        from resume_validation import ResumeValidator

        with self.assertRaises(TypeError):
            ResumeValidator().declare("a#0", {"q": 1}, None, seq="1")

    # -- lt@357: the non-negative seq bound ----------------------------
    def test_seq_zero_is_legal(self):
        """lt@357: the bound is STRICT.

        ``seq`` is an ordinal, and zero is the first ordinal.  The guard
        is ``value < 0``, so zero is legal.  Under the mutant
        (``<`` -> ``<=``) a seq of zero would be refused, and the first
        interrupt of a run -- whose natural seq is 0 -- could never be
        declared.
        """
        from resume_validation import ResumeValidator

        v = ResumeValidator()
        v.declare("a#0", {"q": 1}, None, seq=0)
        self.assertEqual([d.seq for d in v.pending()], [0])

    def test_a_negative_seq_is_refused(self):
        """lt@357: the control -- a negative ordinal is refused."""
        from resume_validation import ResumeValidator

        with self.assertRaises(ValueError):
            ResumeValidator().declare("a#0", {"q": 1}, None, seq=-1)

    # -- retT@364: the ``any`` kind shortcut --------------------------
    def test_the_any_kind_accepts_a_value_of_any_type(self):
        """retT@364: ``any`` means ANY.

        The shortcut for the ``any`` kind returns True without looking at
        the value.  Under the mutant (``return True`` -> ``return False``)
        every ``any`` field would be refused -- the exact opposite of the
        declared meaning, and the way a caller declares "this interrupt
        takes free-form input".
        """
        v = self._validator({"x": {"type": "any"}})
        self.assertEqual(v.validate_resume({"a#0": {"x": "hello"}})["a#0"], {"x": "hello"})
        self.assertEqual(v.validate_resume({"a#0": {"x": {"k": 1}}})["a#0"], {"x": {"k": 1}})

    # -- and@370 / and@372: the bool exclusion ------------------------
    def test_the_float_kind_rejects_a_bool(self):
        """and@370: a bool is NOT a float.

        The float kind is ``isinstance(value, float) and not
        isinstance(value, bool)``.  Only the ``not isinstance(value,
        bool)`` half refuses a bool -- ``isinstance(True, float)`` is
        False anyway, but the conjunction is what states the intent.
        Under the mutant (``and`` -> ``or``) a bool would satisfy the
        first half... and the whole guard inverts: every non-float would
        pass and every float would fail.
        """
        from resume_validation import SchemaViolationError

        v = self._validator({"f": {"type": "float"}})
        with self.assertRaises(SchemaViolationError):
            v.validate_resume({"a#0": {"f": True}})

    def test_the_float_kind_rejects_an_int(self):
        """and@370: the discriminating case for the float kind.

        The float kind is ``isinstance(value, float) and not
        isinstance(value, bool)``.  A bool is refused by BOTH halves of
        the mutant (``or`` -> ``and``), so a bool does not discriminate.
        An **int** does: the original refuses it because it is not a
        float, while the mutant's second half (``not isinstance(value,
        bool)``) is True for an int, so the mutant would ACCEPT an int
        as a float.
        """
        from resume_validation import SchemaViolationError

        v = self._validator({"f": {"type": "float"}})
        with self.assertRaises(SchemaViolationError):
            v.validate_resume({"a#0": {"f": 3}})

    def test_the_float_kind_accepts_a_real_float(self):
        """and@370: the control -- a real float is accepted."""
        v = self._validator({"f": {"type": "float"}})
        self.assertEqual(v.validate_resume({"a#0": {"f": 1.5}})["a#0"], {"f": 1.5})

    def test_the_number_kind_rejects_a_bool(self):
        """and@372: the same exclusion for the ``number`` kind."""
        from resume_validation import SchemaViolationError

        v = self._validator({"n": {"type": "number"}})
        with self.assertRaises(SchemaViolationError):
            v.validate_resume({"a#0": {"n": True}})

    def test_the_number_kind_accepts_an_int_and_a_float(self):
        """and@372: the control -- a real number is accepted."""
        v = self._validator({"n": {"type": "number"}})
        self.assertEqual(v.validate_resume({"a#0": {"n": 3}})["a#0"], {"n": 3})
        self.assertEqual(v.validate_resume({"a#0": {"n": 3.5}})["a#0"], {"n": 3.5})

    # -- eq@375 / eq@377 / eq@379: the container kinds -----------------
    def test_the_list_kind_rejects_a_non_list(self):
        """eq@375: a ``list`` field must hold a list."""
        from resume_validation import SchemaViolationError

        v = self._validator({"l": {"type": "list"}})
        with self.assertRaises(SchemaViolationError):
            v.validate_resume({"a#0": {"l": "not a list"}})

    def test_the_list_kind_accepts_a_list(self):
        """eq@375: the control -- a real list is accepted."""
        v = self._validator({"l": {"type": "list"}})
        self.assertEqual(v.validate_resume({"a#0": {"l": [1, 2]}})["a#0"], {"l": [1, 2]})

    def test_the_dict_kind_rejects_a_non_dict(self):
        """eq@377: a ``dict`` field must hold a dict."""
        from resume_validation import SchemaViolationError

        v = self._validator({"d": {"type": "dict"}})
        with self.assertRaises(SchemaViolationError):
            v.validate_resume({"a#0": {"d": ["not", "a", "dict"]}})

    def test_the_dict_kind_accepts_a_dict(self):
        """eq@377: the control -- a real dict is accepted."""
        v = self._validator({"d": {"type": "dict"}})
        self.assertEqual(v.validate_resume({"a#0": {"d": {"k": 1}}})["a#0"], {"d": {"k": 1}})

    def test_the_object_kind_rejects_a_non_object(self):
        """eq@379: an ``object`` field must hold a mapping."""
        from resume_validation import SchemaViolationError

        v = self._validator({"o": {"type": "object"}})
        with self.assertRaises(SchemaViolationError):
            v.validate_resume({"a#0": {"o": "not an object"}})

    def test_the_object_kind_accepts_a_mapping(self):
        """eq@379: the control -- a real mapping is accepted."""
        v = self._validator({"o": {"type": "object"}})
        self.assertEqual(v.validate_resume({"a#0": {"o": {"k": 1}}})["a#0"], {"o": {"k": 1}})

    # -- retF@381: the unknown-kind fallback --------------------------
    def test_an_unknown_kind_matches_nothing(self):
        """retF@381: the fallback for a kind this module does not know.

        ``_type_matches`` returns False for a kind outside
        :data:`SUPPORTED_TYPES`.  A schema with such a kind cannot be
        declared (the declaration is refused), so this line is only
        reachable for a kind that was supported at declaration time.
        Under the mutant (``return False`` -> ``return True``) every
        value would match an unknown kind -- the fail-open answer.
        """
        from resume_validation import _type_matches

        self.assertFalse(_type_matches("anything", "wat"))
        self.assertFalse(_type_matches(1, "wat"))
        self.assertFalse(_type_matches(None, "wat"))

    def test_the_unknown_kind_fallback_is_not_reachable_through_a_schema(self):
        """retF@381: the guard that keeps the fallback unreachable.

        A kind outside :data:`SUPPORTED_TYPES` is refused at declaration
        time, so no declared schema can reach the fallback branch.
        """
        from resume_validation import InvalidSchemaError, ResumeValidator

        with self.assertRaises(InvalidSchemaError):
            ResumeValidator().declare(
                "a#0", {"q": 1}, {"fields": {"x": {"type": "wat"}}}, seq=1
            )

    # -- and@560: the numeric-kind half of the bounds check ------------
    def test_a_non_numeric_field_ignores_its_bounds(self):
        """and@560: the bounds only apply to a NUMERIC field.

        The guard is ``spec.type in _NUMERIC_TYPES and candidate is not
        None``.  Under the mutant (``and`` -> ``or``) a non-numeric field
        with a declared bound would be checked against that bound and
        refused.  Here the field is a ``str`` and the bound is a number,
        so the check must not run at all.  The schema is built directly
        (``ResponseSchema``/``FieldSpec``) because the mapping form
        refuses a bound on a non-numeric field one step earlier, in
        ``FieldSpec.from_mapping``.
        """
        from resume_validation import FieldSpec, ResponseSchema, ResumeValidator

        schema = ResponseSchema(
            fields={"s": FieldSpec(type="str", minimum=5, maximum=5)},
            required=("s",),
        )
        v = ResumeValidator()
        v.declare("a#0", {"q": 1}, schema, seq=1)
        self.assertEqual(v.validate_resume({"a#0": {"s": "hi"}})["a#0"], {"s": "hi"})

    def test_a_none_candidate_ignores_its_bounds(self):
        """and@560: the other arm -- a ``None`` candidate is not compared.

        A field of kind ``any`` may legitimately hold ``None``; the
        bounds must not be applied to it.  As above, the schema is built
        directly, because the mapping form refuses a bound on a
        non-numeric field before the check is ever reached.
        """
        from resume_validation import FieldSpec, ResponseSchema, ResumeValidator

        schema = ResponseSchema(
            fields={"n": FieldSpec(type="any", minimum=5, maximum=5)},
            required=("n",),
        )
        v = ResumeValidator()
        v.declare("a#0", {"q": 1}, schema, seq=1)
        self.assertEqual(v.validate_resume({"a#0": {"n": None}})["a#0"], {"n": None})

    # -- lt@561: the inclusive minimum bound ---------------------------
    def test_a_value_exactly_at_the_minimum_is_accepted(self):
        """lt@561: the ``minimum`` bound is INCLUSIVE.

        The guard is ``candidate < spec.minimum``, so a value exactly at
        the minimum is legal.  Under the mutant (``<`` -> ``<=``) the
        minimum value itself would be refused -- the boundary of a legal
        range would not be legal.
        """
        v = self._validator({"n": {"type": "int", "minimum": 5}})
        self.assertEqual(v.validate_resume({"a#0": {"n": 5}})["a#0"], {"n": 5})

    def test_a_value_below_the_minimum_is_refused(self):
        """lt@561: the control -- one below the minimum is refused."""
        from resume_validation import SchemaViolationError

        v = self._validator({"n": {"type": "int", "minimum": 5}})
        with self.assertRaises(SchemaViolationError):
            v.validate_resume({"a#0": {"n": 4}})

    # -- eq@647 / eq@649 / eq@651 / eq@655: the demo -------------------
    def test_the_module_demo_runs_and_asserts_its_own_claims(self):
        """eq@647 / eq@649 / eq@651: ``main()`` is a real check.

        ``main()`` declares one interrupt, validates a resume, resolves
        it and asserts that the pending list held exactly one interrupt,
        that the validated value carried the schema's default, and that
        the pending list was empty afterwards.  Under any of the three
        mutants (``==`` -> ``!=``) the assertion would be inverted and
        the demo would fail -- but only if the demo is actually run.
        Calling it here makes those three assertions observable.
        """
        from resume_validation import main

        self.assertIsNone(main())

    def test_the_module_demo_prints_its_ok_line(self):
        """eq@649: the second assertion -- the validated value.

        The demo's own ``assert`` on the validated value is the only
        place the whole-call contract (a default filled in, one
        interrupt resolved) is stated end to end.  Running it under the
        mutant makes the inverted comparison observable.
        """
        import io
        import contextlib

        from resume_validation import main

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            main()
        self.assertIn("resume-validation OK", buffer.getvalue())

    def test_the_module_runs_as_a_script(self):
        """eq@655: the ``__main__`` guard.

        The module's demo is guarded by ``if __name__ == "__main__":``.
        Under the mutant (``==`` -> ``!=``) the guard is inverted, so
        running the module as a script would NOT run the demo -- and the
        demo's three assertions would never fire.  Running the file as a
        subprocess makes that observable: the demo's OK line must be
        printed, which can only happen if the guard held.
        """
        import subprocess
        import sys

        import resume_validation

        result = subprocess.run(
            [sys.executable, resume_validation.__file__],
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("resume-validation OK", result.stdout)
