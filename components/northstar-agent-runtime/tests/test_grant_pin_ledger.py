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
