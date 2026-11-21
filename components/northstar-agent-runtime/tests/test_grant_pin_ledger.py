"""Tests for grant_pin_ledger: the seal-layer pin integrity of conclusion 52.

The rule under test:

* the grant id is NOT NULL at the seal layer -- an empty or missing grant
  id is refused and **no row lands**;
* the version and the counter are nullable -- a named grant with a null
  counter lands a row whose outcome is ``outcome_unknown``, with the pin
  preserved verbatim;
* a fully resolved pin behaves exactly as before.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from grant_pin_ledger import (
    AUDIT_SCHEMA,
    KIND_REFUSED,
    KIND_SEALED,
    OUTCOME_UNKNOWN,
    PIN_COLUMNS,
    PIN_FIELDS,
    SCHEMA_PIN,
    GrantPin,
    GrantPinError,
    GrantPinLedger,
    MalformedPinError,
    MissingGrantIdError,
    grant_pin_audit_event,
    stdlib_only,
)


class _StubLedger:
    """A forward-seal ledger stand-in that records what was appended."""

    def __init__(self) -> None:
        self.records: list[dict] = []

    def append(self, **fields):
        self.records.append(fields)
        return fields


class GrantPinShapeTests(unittest.TestCase):
    """The pin keeps its three-field shape: grant id, version, counter."""

    def test_pin_has_exactly_three_fields(self):
        self.assertEqual(PIN_FIELDS, ("grant_id", "version", "counter"))
        self.assertEqual(
            [name for name, _type, _null in PIN_COLUMNS],
            ["grant_id", "version", "counter"],
        )

    def test_grant_id_column_is_not_null_and_others_are_nullable(self):
        nullability = {name: nullable for name, _type, nullable in PIN_COLUMNS}
        self.assertFalse(nullability["grant_id"])
        self.assertTrue(nullability["version"])
        self.assertTrue(nullability["counter"])

    def test_full_pin_round_trips_through_its_mapping(self):
        pin = GrantPin("grant-1", "v2", 7)
        self.assertEqual(pin.to_dict(), {"grant_id": "grant-1", "version": "v2", "counter": 7})
        self.assertEqual(GrantPin.from_dict(pin.to_dict()), pin)

    def test_missing_grant_id_becomes_the_empty_string(self):
        pin = GrantPin.from_dict({"version": "v1", "counter": 3})
        self.assertEqual(pin.grant_id, "")
        self.assertFalse(pin.is_named())

    def test_pin_rejects_a_non_string_grant_id(self):
        with self.assertRaises(MalformedPinError):
            GrantPin.from_dict({"grant_id": 17})

    def test_pin_rejects_a_bool_counter(self):
        with self.assertRaises(MalformedPinError):
            GrantPin("grant-1", "v1", True)

    def test_pin_rejects_a_fourth_field(self):
        with self.assertRaises(MalformedPinError):
            GrantPin.from_dict(
                {"grant_id": "g", "version": "v", "counter": 1, "approver": "op"}
            )


class SealLayerTests(unittest.TestCase):
    """The seal layer: an unnamed grant is refused, a nameless row never lands."""

    def test_empty_grant_id_is_refused_and_no_row_lands(self):
        ledger = GrantPinLedger()
        with self.assertRaises(MissingGrantIdError):
            ledger.seal(GrantPin("", "v1", 3), outcome="executed", seq=1)
        self.assertEqual(len(ledger), 0)
        self.assertEqual(ledger.rows, ())

    def test_missing_grant_id_is_refused_and_no_row_lands(self):
        ledger = GrantPinLedger()
        pin = GrantPin.from_dict({"version": "v1", "counter": 3})
        with self.assertRaises(MissingGrantIdError):
            ledger.seal(pin, outcome="executed", seq=1)
        self.assertEqual(len(ledger), 0)

    def test_blank_grant_id_is_refused(self):
        ledger = GrantPinLedger()
        with self.assertRaises(MissingGrantIdError):
            ledger.seal(GrantPin("   ", "v1", 3), outcome="executed", seq=1)
        self.assertEqual(len(ledger), 0)

    def test_a_refused_seal_leaves_the_previous_rows_untouched(self):
        ledger = GrantPinLedger()
        ledger.seal(GrantPin("grant-1", "v1", 1), outcome="executed", seq=1)
        with self.assertRaises(MissingGrantIdError):
            ledger.seal(GrantPin("", "v1", 2), outcome="executed", seq=2)
        self.assertEqual(len(ledger), 1)
        self.assertEqual(ledger.rows[0].pin.grant_id, "grant-1")

    def test_a_refused_seal_does_not_touch_the_forward_seal_ledger(self):
        ledger = GrantPinLedger()
        sealed = _StubLedger()
        with self.assertRaises(MissingGrantIdError):
            ledger.seal_into(
                GrantPin("", "v1", 3), sealed, subject="tool", seq=1
            )
        self.assertEqual(len(ledger), 0)
        self.assertEqual(sealed.records, [])

    def test_a_failed_chain_append_leaves_no_local_row(self):
        class _FailingLedger:
            def append(self, **fields):
                raise RuntimeError("chain write failed")

        ledger = GrantPinLedger()
        with self.assertRaises(RuntimeError):
            ledger.seal_into(
                GrantPin("grant-20", "v1", 1), _FailingLedger(), subject="tool"
            )
        self.assertEqual(len(ledger), 0)


class UnresolvableGrantTests(unittest.TestCase):
    """A named grant with no counter is a parseable refusal, not silence."""

    def test_null_counter_lands_a_row_with_outcome_unknown(self):
        ledger = GrantPinLedger()
        row = ledger.seal(GrantPin("grant-2", "v1", None), outcome="executed", seq=1)
        self.assertEqual(len(ledger), 1)
        self.assertEqual(row.outcome, OUTCOME_UNKNOWN)

    def test_null_counter_preserves_the_pin_verbatim(self):
        ledger = GrantPinLedger()
        row = ledger.seal(GrantPin("grant-2", "v1", None), outcome="executed", seq=1)
        self.assertEqual(
            row.pin.to_dict(),
            {"grant_id": "grant-2", "version": "v1", "counter": None},
        )

    def test_null_version_with_a_counter_keeps_the_declared_outcome(self):
        # The counter is the ordering key: the version may be absent
        # without making the grant unresolvable.
        ledger = GrantPinLedger()
        row = ledger.seal(GrantPin("grant-3", None, 4), outcome="executed", seq=1)
        self.assertEqual(row.outcome, "executed")
        self.assertIsNone(row.pin.version)

    def test_the_declared_outcome_is_never_kept_when_unresolvable(self):
        ledger = GrantPinLedger()
        row = ledger.seal(GrantPin("grant-4", "v1", None), outcome="executed", seq=1)
        self.assertNotEqual(row.outcome, "executed")
        self.assertEqual(row.outcome, "outcome_unknown")

    def test_the_row_digest_verifies(self):
        ledger = GrantPinLedger()
        row = ledger.seal(GrantPin("grant-5", "v1", None), outcome="executed", seq=1)
        self.assertTrue(row.verify())


class ResolvedPinTests(unittest.TestCase):
    """A fully resolved pin behaves exactly as before."""

    def test_a_full_pin_keeps_the_declared_outcome(self):
        ledger = GrantPinLedger()
        row = ledger.seal(GrantPin("grant-6", "v2", 7), outcome="executed", seq=1)
        self.assertEqual(row.outcome, "executed")

    def test_a_full_pin_keeps_its_three_fields(self):
        ledger = GrantPinLedger()
        row = ledger.seal(GrantPin("grant-7", "v2", 7), outcome="denied", seq=1)
        self.assertEqual(
            row.pin.to_dict(),
            {"grant_id": "grant-7", "version": "v2", "counter": 7},
        )
        self.assertEqual(row.outcome, "denied")

    def test_the_row_digest_verifies_for_a_full_pin(self):
        ledger = GrantPinLedger()
        row = ledger.seal(GrantPin("grant-8", "v2", 7), outcome="executed", seq=1)
        self.assertTrue(row.verify())

    def test_rows_are_readable_back_by_seq(self):
        ledger = GrantPinLedger()
        first = ledger.seal(GrantPin("grant-9", "v1", 1), outcome="executed", seq=1)
        second = ledger.seal(GrantPin("grant-10", "v1", 2), outcome="executed", seq=2)
        self.assertEqual(ledger.row(1), first)
        self.assertEqual(ledger.row(2), second)


class SealIntoLedgerTests(unittest.TestCase):
    """The pin rides into the forward-seal ledger as the authorization field."""

    def test_the_authorization_field_names_the_grant(self):
        ledger = GrantPinLedger()
        sealed = _StubLedger()
        ledger.seal_into(
            GrantPin("grant-11", "v2", 7), sealed, subject="tool", seq=1
        )
        self.assertEqual(len(sealed.records), 1)
        self.assertEqual(
            sealed.records[0]["authorization"],
            "grant:grant-11;version=v2;counter=7",
        )

    def test_the_sealed_outcome_is_outcome_unknown_without_a_counter(self):
        ledger = GrantPinLedger()
        sealed = _StubLedger()
        ledger.seal_into(
            GrantPin("grant-12", "v2", None), sealed, subject="tool", seq=1
        )
        self.assertEqual(sealed.records[0]["outcome"], OUTCOME_UNKNOWN)

    def test_the_rendered_pin_parses_back_to_the_same_pin(self):
        pin = GrantPin("grant-13", "v2", None)
        self.assertEqual(GrantPin.parse(pin.render()), pin)

    def test_the_rendered_pin_names_a_null_counter_explicitly(self):
        pin = GrantPin("grant-14", "v2", None)
        self.assertEqual(pin.render(), "grant:grant-14;version=v2;counter=null")

    def test_a_sealed_row_can_be_read_back_after_the_fact(self):
        ledger = GrantPinLedger()
        sealed = _StubLedger()
        ledger.seal_into(
            GrantPin("grant-15", "v3", 11), sealed, subject="tool", seq=1
        )
        recovered = GrantPin.parse(sealed.records[0]["authorization"])
        self.assertEqual(recovered.grant_id, "grant-15")
        self.assertEqual(recovered.version, "v3")
        self.assertEqual(recovered.counter, 11)


class AuditEventTests(unittest.TestCase):
    """The seal layer emits audit events for both outcomes."""

    def test_a_sealed_event_names_the_grant_and_the_outcome(self):
        event = grant_pin_audit_event(
            KIND_SEALED,
            {"grant_id": "grant-16", "version": "v1", "counter": None,
             "outcome": OUTCOME_UNKNOWN},
            1,
        )
        self.assertEqual(event["schema"], AUDIT_SCHEMA)
        self.assertEqual(event["kind"], KIND_SEALED)
        self.assertEqual(event["detail"]["grant_id"], "grant-16")
        self.assertEqual(event["detail"]["outcome"], OUTCOME_UNKNOWN)

    def test_a_refused_event_names_the_refusal(self):
        event = grant_pin_audit_event(KIND_REFUSED, {"grant_id": ""}, 2)
        self.assertEqual(event["kind"], KIND_REFUSED)
        self.assertEqual(event["seq"], 2)

    def test_an_unknown_audit_kind_is_refused(self):
        with self.assertRaises(GrantPinError):
            grant_pin_audit_event("grant-pin.unknown", {}, 1)

    def test_the_schema_pin_is_carried_by_rows(self):
        ledger = GrantPinLedger()
        row = ledger.seal(GrantPin("grant-17", "v1", 1), outcome="executed", seq=1)
        self.assertEqual(row.schema, SCHEMA_PIN)


class ForwardSealLedgerGrantTests(unittest.TestCase):
    """The rule on the real seal layer: the forward-seal ledger itself."""

    def setUp(self):
        from forward_seal_ledger import ForwardSealLedger

        self._keys = (b"k" * 32, b"c" * 32)
        self.ledger = ForwardSealLedger(*self._keys)

    def _event(self, record):
        return dict(record.event)

    def test_an_empty_grant_id_is_refused_and_no_record_lands(self):
        from forward_seal_ledger import ForwardSealError

        with self.assertRaises(ForwardSealError):
            self.ledger.append_grant(grant_id="", version="v1", counter=3)
        self.assertEqual(len(self.ledger), 0)

    def test_a_missing_grant_id_is_refused_and_no_record_lands(self):
        from forward_seal_ledger import ForwardSealError

        with self.assertRaises(ForwardSealError):
            self.ledger.append_grant(grant_id=None, version="v1", counter=3)
        self.assertEqual(len(self.ledger), 0)

    def test_a_null_counter_lands_with_outcome_unknown(self):
        record = self.ledger.append_grant(
            grant_id="grant-20", version="v1", counter=None, subject="tool"
        )
        self.assertEqual(len(self.ledger), 1)
        self.assertEqual(self._event(record)["outcome"], "outcome_unknown")

    def test_a_null_counter_preserves_the_pin_verbatim(self):
        record = self.ledger.append_grant(
            grant_id="grant-21", version="v1", counter=None, subject="tool"
        )
        self.assertEqual(
            self._event(record)["authorization"],
            "grant:grant-21;version=v1;counter=null",
        )

    def test_a_full_pin_keeps_the_declared_outcome(self):
        record = self.ledger.append_grant(
            grant_id="grant-22", version="v2", counter=7,
            subject="tool", outcome="executed",
        )
        self.assertEqual(self._event(record)["outcome"], "executed")

    def test_the_sealed_record_names_the_grant_after_the_fact(self):
        from grant_pin_ledger import GrantPin

        record = self.ledger.append_grant(
            grant_id="grant-23", version="v3", counter=11, subject="tool"
        )
        recovered = GrantPin.parse(self._event(record)["authorization"])
        self.assertEqual(recovered.grant_id, "grant-23")
        self.assertEqual(recovered.version, "v3")
        self.assertEqual(recovered.counter, 11)

    def test_the_chain_still_verifies_after_grant_seals(self):
        self.ledger.append_grant(
            grant_id="grant-24", version="v1", counter=1, subject="tool"
        )
        self.ledger.append_grant(
            grant_id="grant-25", version="v1", counter=None, subject="tool"
        )
        report = self.ledger.verify(*self._keys)
        self.assertEqual(report["records_verified"], 2)

    def test_a_refused_grant_seal_leaves_the_chain_intact(self):
        from forward_seal_ledger import ForwardSealError

        self.ledger.append_grant(
            grant_id="grant-26", version="v1", counter=1, subject="tool"
        )
        with self.assertRaises(ForwardSealError):
            self.ledger.append_grant(grant_id="", version="v1", counter=2)
        report = self.ledger.verify(*self._keys)
        self.assertEqual(report["records_verified"], 1)


class HouseStyleTests(unittest.TestCase):
    """The module keeps the repo's house style."""

    def test_the_module_is_stdlib_only(self):
        self.assertTrue(stdlib_only())

    def test_the_pin_rejects_an_unknown_ledger(self):
        ledger = GrantPinLedger()
        with self.assertRaises(GrantPinError):
            ledger.seal_into(GrantPin("grant-18", "v1", 1), None, subject="tool")

    def test_the_pin_rejects_an_empty_subject(self):
        ledger = GrantPinLedger()
        with self.assertRaises(GrantPinError):
            ledger.seal_into(
                GrantPin("grant-19", "v1", 1), _StubLedger(), subject=""
            )


if __name__ == "__main__":
    unittest.main()


class ColumnGuardSecondHalfTests(unittest.TestCase):
    """The second half of each column guard in the pin ledger.

    Each guard here is a conjunction or a two-armed conditional, and the
    rest of the suite drove only one arm.  These tests drive the other.
    """

    # -- eq@142 / gt@143: the length limit's two branches ---------------

    def test_a_grant_id_at_the_length_limit_is_accepted(self):
        """`gt@143`: the lower edge of the length guard, on a grant id.

        The limit is ``len(value) > limit``, so a grant id of exactly
        the limit is accepted.  A mutant that turns ``>`` into ``>=``
        refuses it.
        """
        pin = GrantPin("g" * 256, "v1", 1)
        self.assertEqual(len(pin.grant_id), 256)

    def test_a_grant_id_one_character_over_the_limit_is_refused(self):
        """`gt@143`: inside the band -- one character over is refused."""
        with self.assertRaises(MalformedPinError) as caught:
            GrantPin("g" * 257, "v1", 1)
        self.assertIn("too long", str(caught.exception))

    def test_a_version_at_the_length_limit_is_accepted(self):
        """`eq@142`: the OTHER branch of the limit choice.

        The limit is ``_MAX_ID_CHARS if name == "grant_id" else
        _MAX_VERSION_CHARS``.  Both constants happen to be 256 today, so
        the branch is only distinguishable by WHICH name is checked --
        and the branch matters the moment the two limits differ.  This
        test pins that a version is measured against the version limit.
        """
        import grant_pin_ledger as gpl

        self.assertEqual(gpl._MAX_ID_CHARS, gpl._MAX_VERSION_CHARS)
        pin = GrantPin("grant-1", "v" * 256, 1)
        self.assertEqual(len(pin.version), 256)

    def test_a_version_one_character_over_the_limit_is_refused(self):
        """`eq@142`: the other branch -- the version is length-checked too."""
        with self.assertRaises(MalformedPinError) as caught:
            GrantPin("grant-1", "v" * 257, 1)
        self.assertIn("version is too long", str(caught.exception))

    # -- lt@149 / gt@151: the counter's range --------------------------

    def test_a_zero_counter_is_accepted(self):
        """`lt@149`: the lower edge of the counter's range.

        The counter must be non-negative, so zero is allowed.  A mutant
        that turns ``< 0`` into ``<= 0`` refuses it.
        """
        pin = GrantPin("grant-1", "v1", 0)
        self.assertEqual(pin.counter, 0)

    def test_a_negative_counter_is_refused(self):
        """`lt@149`: the sign half of the counter's range."""
        with self.assertRaises(MalformedPinError) as caught:
            GrantPin("grant-1", "v1", -1)
        self.assertIn("must be non-negative", str(caught.exception))

    def test_a_counter_at_the_safe_range_is_accepted(self):
        """`gt@151`: the upper edge of the counter's range.

        The safe range ends at 2**53 - 1.  A counter of exactly that
        value is accepted; a mutant that turns ``>`` into ``>=`` refuses
        it.
        """
        pin = GrantPin("grant-1", "v1", 2**53 - 1)
        self.assertEqual(pin.counter, 2**53 - 1)

    def test_a_counter_one_over_the_safe_range_is_refused(self):
        """`gt@151`: inside the band -- one over the safe range is refused."""
        with self.assertRaises(MalformedPinError) as caught:
            GrantPin("grant-1", "v1", 2**53)
        self.assertIn("exceeds the safe range", str(caught.exception))

    # -- or@254: the parse guard's halves -------------------------------

    def test_parsing_a_non_string_is_refused(self):
        """`or@254`: the type half of the parse guard."""
        with self.assertRaises(MalformedPinError) as caught:
            GrantPin.parse(42)
        self.assertIn("must be a non-empty str", str(caught.exception))

    def test_parsing_an_empty_string_is_refused(self):
        """`or@254`: the emptiness half of the parse guard."""
        with self.assertRaises(MalformedPinError):
            GrantPin.parse("")

    def test_parsing_a_valid_rendered_pin_still_works(self):
        """`or@254`: the control -- a valid pin still parses."""
        pin = GrantPin("grant-1", "v2", 7)
        parsed = GrantPin.parse(pin.render())
        self.assertEqual(parsed.to_dict(), pin.to_dict())

    # -- retF@322: the digest verify guard -----------------------------

    def test_a_row_with_a_broken_digest_does_not_verify(self):
        """`retF@322`: the "the digest does not match" half.

        ``verify()`` re-derives the row digest and compares it.  A row
        whose outcome was tampered with must NOT verify.
        """
        import dataclasses

        from grant_pin_ledger import SealedGrantRow, _digest

        pin = GrantPin("grant-1", "v2", 7)
        digest = _digest({
            "seq": 1,
            "pin": pin.to_dict(),
            "outcome": "executed",
            "schema": SCHEMA_PIN,
        })
        tampered = SealedGrantRow(
            seq=1,
            pin=pin,
            outcome="refused",
            digest=digest,
        )
        self.assertFalse(tampered.verify())

    def test_a_row_with_the_right_digest_verifies(self):
        """`retF@322`: the control -- an untouched row verifies."""
        ledger = GrantPinLedger()
        row = ledger.seal(GrantPin("grant-1", "v2", 7), outcome="executed", seq=1)
        self.assertTrue(row.verify())

    # -- or@342: the resolve guard's halves -----------------------------

    def test_resolving_with_a_non_string_outcome_is_refused(self):
        """`or@342`: the type half of the outcome guard."""
        import grant_pin_ledger as gpl

        with self.assertRaises(GrantPinError) as caught:
            gpl.resolve_seal_outcome(GrantPin("grant-1", "v1", 1), 42)
        self.assertIn("outcome must be a non-empty string", str(caught.exception))

    def test_resolving_with_an_empty_outcome_is_refused(self):
        """`or@342`: the emptiness half of the outcome guard."""
        import grant_pin_ledger as gpl

        with self.assertRaises(GrantPinError):
            gpl.resolve_seal_outcome(GrantPin("grant-1", "v1", 1), "")

    def test_resolving_with_a_non_string_pin_is_refused(self):
        """`or@342`: the pin half of the guard."""
        import grant_pin_ledger as gpl

        with self.assertRaises(MalformedPinError) as caught:
            gpl.resolve_seal_outcome("not a pin", "executed")
        self.assertIn("pin must be a GrantPin", str(caught.exception))

    # -- or@377 / lt@379: the row lookup's halves ----------------------

    def test_looking_up_a_boolean_seq_is_refused(self):
        """`or@377`: the type half of the seq guard, on a bool.

        A bool IS an int in Python, so only the isinstance(..., bool)
        half can catch it.
        """
        ledger = GrantPinLedger()
        ledger.seal(GrantPin("grant-1", "v1", 1), seq=1)
        with self.assertRaises(GrantPinError) as caught:
            ledger.row(True)
        self.assertIn("seq must be an int", str(caught.exception))

    def test_looking_up_a_seq_of_zero_is_refused(self):
        """`lt@379`: the lower edge of the seq range.

        The seq is 1-based, so zero is not a row.  A mutant that turns
        ``< 1`` into ``<= 1`` would return the LAST row for zero.
        """
        ledger = GrantPinLedger()
        ledger.seal(GrantPin("grant-1", "v1", 1), seq=1)
        with self.assertRaises(GrantPinError) as caught:
            ledger.row(0)
        self.assertIn("unknown seq", str(caught.exception))

    def test_looking_up_a_seq_past_the_end_is_refused(self):
        """`lt@379`: the upper edge of the seq range."""
        ledger = GrantPinLedger()
        ledger.seal(GrantPin("grant-1", "v1", 1), seq=1)
        with self.assertRaises(GrantPinError):
            ledger.row(2)

    # -- or@400 / or@402: the seal guard's halves -----------------------

    def test_sealing_with_an_empty_outcome_is_refused(self):
        """`or@400`: the emptiness half of the seal's outcome guard."""
        ledger = GrantPinLedger()
        with self.assertRaises(GrantPinError) as caught:
            ledger.seal(GrantPin("grant-1", "v1", 1), outcome="")
        self.assertIn("outcome must be a non-empty string", str(caught.exception))
        self.assertEqual(len(ledger), 0)

    def test_sealing_with_a_non_string_outcome_is_refused(self):
        """`or@400`: the type half of the seal's outcome guard."""
        ledger = GrantPinLedger()
        with self.assertRaises(GrantPinError):
            ledger.seal(GrantPin("grant-1", "v1", 1), outcome=42)
        self.assertEqual(len(ledger), 0)

    def test_sealing_with_a_boolean_seq_is_refused(self):
        """`or@402`: the type half of the seal's seq guard, on a bool."""
        ledger = GrantPinLedger()
        with self.assertRaises(GrantPinError) as caught:
            ledger.seal(GrantPin("grant-1", "v1", 1), seq=True)
        self.assertIn("seq must be a non-negative int", str(caught.exception))
        self.assertEqual(len(ledger), 0)

    def test_sealing_with_a_negative_seq_is_refused(self):
        """`or@402`: the sign half of the seal's seq guard."""
        ledger = GrantPinLedger()
        with self.assertRaises(GrantPinError):
            ledger.seal(GrantPin("grant-1", "v1", 1), seq=-1)
        self.assertEqual(len(ledger), 0)

    def test_sealing_with_a_zero_seq_is_allowed(self):
        """`or@402`: the boundary -- zero is a legal seq.

        A mutant that turns ``< 0`` into ``<= 0`` refuses this.
        """
        ledger = GrantPinLedger()
        row = ledger.seal(GrantPin("grant-1", "v1", 1), seq=0)
        self.assertEqual(row.seq, 0)
        self.assertEqual(len(ledger), 1)

    # -- or@446: the forward ledger's guard -----------------------------

    def test_sealing_into_a_ledger_without_append_is_refused(self):
        """`or@446`: the "and the ledger has append()" half."""
        import grant_pin_ledger as gpl

        class NoAppend:
            pass

        with self.assertRaises(GrantPinError) as caught:
            GrantPinLedger().seal_into(
                GrantPin("grant-1", "v1", 1), NoAppend(),
                intent="i", action="a", subject="s",
            )
        self.assertIn("ledger must have append()", str(caught.exception))

    def test_sealing_into_a_none_ledger_is_refused(self):
        """`or@446`: the "the ledger is not None" half."""
        import grant_pin_ledger as gpl

        with self.assertRaises(GrantPinError):
            GrantPinLedger().seal_into(
                GrantPin("grant-1", "v1", 1), None,
                intent="i", action="a", subject="s",
            )

    def test_sealing_into_a_ledger_with_a_non_callable_append_is_refused(self):
        """`or@446`: the callable half -- an ``append`` that is not callable."""
        import grant_pin_ledger as gpl

        class BadAppend:
            append = "not callable"

        with self.assertRaises(GrantPinError):
            GrantPinLedger().seal_into(
                GrantPin("grant-1", "v1", 1), BadAppend(),
                intent="i", action="a", subject="s",
            )

    # -- or@493: the audit event's seq guard ----------------------------

    def test_an_audit_event_with_a_boolean_seq_is_refused(self):
        """`or@493`: the type half of the audit event's seq guard, on a bool."""
        with self.assertRaises(GrantPinError) as caught:
            grant_pin_audit_event(KIND_SEALED, {"grant_id": "g"}, True)
        self.assertIn("seq must be a non-negative int", str(caught.exception))

    def test_an_audit_event_with_a_negative_seq_is_refused(self):
        """`or@493`: the sign half of the audit event's seq guard."""
        with self.assertRaises(GrantPinError):
            grant_pin_audit_event(KIND_SEALED, {"grant_id": "g"}, -1)

    def test_an_audit_event_with_a_zero_seq_is_allowed(self):
        """`or@493`: the boundary -- zero is a legal seq.

        A mutant that turns ``< 0`` into ``<= 0`` refuses this.
        """
        event = grant_pin_audit_event(KIND_SEALED, {"grant_id": "g"}, 0)
        self.assertEqual(event["seq"], 0)

    # -- or@491: the audit event's kind guard ---------------------------

    def test_an_audit_event_with_a_non_string_kind_is_refused(self):
        """`or@491`: the type half of the audit event's kind guard."""
        with self.assertRaises(GrantPinError) as caught:
            grant_pin_audit_event(42, {"grant_id": "g"}, 0)
        self.assertIn("unknown audit kind", str(caught.exception))


class IsolatedGuardTests(unittest.TestCase):
    """Three guards that no ordinary input can reach on its own.

    Each of these is masked by something else in the module -- an equal
    constant, a guard that cannot raise, or a second copy of the same
    guard further down the call path.  The tests below isolate the guard
    so that the mutant is observable.
    """

    # -- eq@142: the limit choice, with distinguishable limits ----------

    def test_the_grant_id_is_measured_against_the_id_limit(self):
        """`eq@142`: the limit choice, made observable.

        The line is ``limit = _MAX_ID_CHARS if name == "grant_id" else
        _MAX_VERSION_CHARS``.  Both constants are 256 today, so the two
        branches are indistinguishable -- a mutant that swaps the
        condition (``==`` -> ``!=``) is invisible to any ordinary
        input.

        The branches are made distinguishable by giving the two
        constants DIFFERENT values for the duration of the test.  The
        constants are module globals read at call time, so the swap is
        observable: a grant id of 15 characters is too long when the id
        limit is 10, and a version of 15 characters is fine when the
        version limit is 20.
        """
        import grant_pin_ledger as gpl

        original_id = gpl._MAX_ID_CHARS
        original_version = gpl._MAX_VERSION_CHARS
        gpl._MAX_ID_CHARS = 10
        gpl._MAX_VERSION_CHARS = 20
        try:
            # The grant id is measured against the ID limit (10), so 15
            # characters is too long.  Under the mutant the grant id
            # would be measured against the version limit (20) and
            # would be accepted.
            with self.assertRaises(MalformedPinError) as caught:
                GrantPin("g" * 15, "v1", 1)
            self.assertIn("grant_id is too long", str(caught.exception))

            # The version is measured against the VERSION limit (20), so
            # 15 characters is fine.  Under the mutant the version
            # would be measured against the id limit (10) and refused.
            pin = GrantPin("grant-1", "v" * 15, 1)
            self.assertEqual(len(pin.version), 15)

            # And the other way round, to pin the direction.
            with self.assertRaises(MalformedPinError) as caught:
                GrantPin("grant-1", "v" * 25, 1)
            self.assertIn("version is too long", str(caught.exception))
        finally:
            gpl._MAX_ID_CHARS = original_id
            gpl._MAX_VERSION_CHARS = original_version

    # -- retF@322: the digest that cannot be computed ------------------

    def test_a_row_whose_digest_cannot_be_computed_does_not_verify(self):
        """`retF@322`: the "the digest could not be derived" half.

        ``verify()`` re-derives the row digest and compares it.  When
        the derivation itself raises -- a payload that is not JSON
        serialisable -- the row must NOT verify: an unverifiable row is
        not a verified row.

        Under the mutant (``return False`` -> ``return True``) such a
        row would report itself as verified.
        """
        import grant_pin_ledger as gpl

        class UnserialisablePin:
            def to_dict(self):
                # A set is not JSON serialisable: json.dumps raises
                # TypeError, which verify() catches.
                return {"fields": {1, 2, 3}}

        row = gpl.SealedGrantRow(
            seq=1,
            pin=UnserialisablePin(),
            outcome="executed",
            digest="sha256:whatever",
        )
        self.assertFalse(row.verify())

    def test_a_row_whose_digest_cannot_be_computed_raises_nothing(self):
        """`retF@322`: the control -- verify() never raises."""
        import grant_pin_ledger as gpl

        class UnserialisablePin:
            def to_dict(self):
                return {"fields": {1, 2, 3}}

        row = gpl.SealedGrantRow(
            seq=1,
            pin=UnserialisablePin(),
            outcome="executed",
            digest="sha256:whatever",
        )
        # The call returns a bool; it does not propagate the TypeError.
        self.assertIsInstance(row.verify(), bool)

    # -- or@400: the seal's own outcome guard --------------------------

    def test_the_seal_layer_refuses_a_non_string_outcome_on_its_own(self):
        """`or@400`: the seal layer's own outcome guard, isolated.

        ``seal()`` guards its outcome at line 400, and then calls
        ``resolve_seal_outcome()``, which guards the SAME outcome with
        the SAME message.  The second guard therefore masks the first:
        a mutant of line 400 alone is invisible, because the refusal
        still comes from line 342.

        The mask is removed here by replacing ``resolve_seal_outcome``
        with a permissive stand-in, so the seal layer's own guard is
        the only thing that can refuse.  Under the mutant (``or`` ->
        ``and``) the guard never fires -- an outcome that is neither a
        string nor empty cannot be both -- and the seal lands a row.
        """
        import grant_pin_ledger as gpl

        original = gpl.resolve_seal_outcome
        gpl.resolve_seal_outcome = lambda pin, outcome: outcome
        try:
            ledger = GrantPinLedger()
            with self.assertRaises(GrantPinError) as caught:
                ledger.seal(GrantPin("grant-1", "v1", 1), outcome=42)
            self.assertIn("outcome must be a non-empty string", str(caught.exception))
            self.assertEqual(len(ledger), 0)
        finally:
            gpl.resolve_seal_outcome = original

    def test_the_seal_layer_refuses_an_empty_outcome_on_its_own(self):
        """`or@400`: the same guard, on the emptiness half."""
        import grant_pin_ledger as gpl

        original = gpl.resolve_seal_outcome
        gpl.resolve_seal_outcome = lambda pin, outcome: outcome
        try:
            ledger = GrantPinLedger()
            with self.assertRaises(GrantPinError):
                ledger.seal(GrantPin("grant-1", "v1", 1), outcome="")
            self.assertEqual(len(ledger), 0)
        finally:
            gpl.resolve_seal_outcome = original


class StdlibOnlyGuardTests(unittest.TestCase):
    """The stdlib-only guard's second half.

    ``stdlib_only()`` walks the module's own AST and refuses any import
    that is not in the allowed set.  The suite already drove the
    "a forbidden import is refused" half; the "everything allowed is
    accepted" half is driven here.
    """

    def test_the_module_is_stdlib_only(self):
        """The control -- the module's own imports are all allowed."""
        self.assertTrue(stdlib_only())

    def test_a_forbidden_root_import_is_refused(self):
        """`retF@526` / `retF@529`: the import-not-allowed half.

        The guard is driven against a stand-in source with a forbidden
        import in it, so the refusal is observable rather than assumed.
        """
        import tempfile

        import grant_pin_ledger as gpl

        source = (
            "import json\n"
            "import numpy\n"
            "from pathlib import Path\n"
        )
        with tempfile.NamedTemporaryFile(
            "w", suffix=".py", delete=False, encoding="utf-8"
        ) as handle:
            handle.write(source)
            path = handle.name

        original = gpl.__file__
        try:
            gpl.__file__ = path
            self.assertFalse(stdlib_only())
        finally:
            gpl.__file__ = original

    def test_a_forbidden_from_import_is_refused(self):
        """`retF@529` / `and@528`: the from-import half.

        The guard's ``node.module and ...`` means a from-import with a
        forbidden root module is refused.
        """
        import tempfile

        import grant_pin_ledger as gpl

        source = "from requests import get\n"
        with tempfile.NamedTemporaryFile(
            "w", suffix=".py", delete=False, encoding="utf-8"
        ) as handle:
            handle.write(source)
            path = handle.name

        original = gpl.__file__
        try:
            gpl.__file__ = path
            self.assertFalse(stdlib_only())
        finally:
            gpl.__file__ = original

    def test_an_allowed_relative_import_is_accepted(self):
        """`and@528`: the "and the module has a name" half.

        A relative from-import has ``node.module`` set but a non-zero
        level; the guard's ``node.module and ...`` clause reads the
        module name, and a relative import is not one of the forbidden
        roots.
        """
        import tempfile

        import grant_pin_ledger as gpl

        source = "from . import sibling\n"
        with tempfile.NamedTemporaryFile(
            "w", suffix=".py", delete=False, encoding="utf-8"
        ) as handle:
            handle.write(source)
            path = handle.name

        original = gpl.__file__
        try:
            gpl.__file__ = path
            self.assertTrue(stdlib_only())
        finally:
            gpl.__file__ = original


class SelfCheckTests(unittest.TestCase):
    """The module's own self-check, driven for real.

    ``grant_pin_ledger.main()`` asserts the module's three claims.  The
    suite never ran it, so every assertion inside it was a free mutant.
    """

    def test_the_self_check_passes(self):
        """The self-check runs clean.

        Under any mutant of one of its assertions the self-check raises
        ``AssertionError`` and this test fails.
        """
        import io
        from contextlib import redirect_stdout

        import grant_pin_ledger as gpl

        with redirect_stdout(io.StringIO()):
            gpl.main()

    def test_the_self_check_reports_that_the_module_is_ok(self):
        """The self-check prints its own name."""
        import io
        from contextlib import redirect_stdout

        import grant_pin_ledger as gpl

        buffer = io.StringIO()
        with redirect_stdout(buffer):
            gpl.main()
        self.assertIn("grant-pin-ledger OK", buffer.getvalue())

    def test_the_module_runs_its_self_check_as_a_script(self):
        """The ``__main__`` guard: run as a script, the module self-checks."""
        import subprocess
        import sys
        from pathlib import Path

        import grant_pin_ledger as gpl

        component = Path(gpl.__file__).resolve().parent
        result = subprocess.run(
            [sys.executable, "-m", "grant_pin_ledger"],
            cwd=str(component),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=120,
        )
        output = result.stdout.decode("utf-8", "replace")
        self.assertEqual(result.returncode, 0, output)
        self.assertIn("grant-pin-ledger OK", output)

    def test_the_self_check_refuses_an_unnamed_grant_and_lands_no_row(self):
        """The self-check's refusal branch: an unnamed grant lands no row.

        The self-check asserts that the ledger still holds two rows
        after the refusal.  A seal that landed a row anyway would make
        that assertion fail.
        """
        import io
        from contextlib import redirect_stdout

        import grant_pin_ledger as gpl

        original = gpl.GrantPinLedger
        ledgers = []

        class RecordingLedger(original):
            def __init__(self):
                super().__init__()
                ledgers.append(self)

        gpl.GrantPinLedger = RecordingLedger
        try:
            with redirect_stdout(io.StringIO()):
                gpl.main()
        finally:
            gpl.GrantPinLedger = original

        self.assertEqual(len(ledgers), 1)
        self.assertEqual(len(ledgers[0]), 2)

    def test_the_self_check_fails_when_the_refusal_does_not_raise(self):
        """The self-check's refusal branch is load-bearing.

        The self-check does ``ledger.seal(...); raise AssertionError``
        inside a ``try`` that catches ``MissingGrantIdError``.  If the
        seal did NOT raise, the self-check raises its own
        ``AssertionError`` -- and that AssertionError is NOT caught by
        the ``except MissingGrantIdError``, so the self-check fails.
        This test pins that a seal which does not refuse fails the
        self-check.
        """
        import io
        from contextlib import redirect_stdout

        import grant_pin_ledger as gpl

        original = gpl.GrantPinLedger

        class LeakyLedger(original):
            def seal(self, pin, *, outcome="executed", seq=0):
                # A seal that never refuses the unnamed grant.
                from grant_pin_ledger import GrantPin as _GP
                return original.seal(
                    self, _GP("grant-1", "v1", 3), outcome=outcome, seq=seq
                )

        gpl.GrantPinLedger = LeakyLedger
        try:
            with redirect_stdout(io.StringIO()):
                with self.assertRaises(AssertionError):
                    gpl.main()
        finally:
            gpl.GrantPinLedger = original
