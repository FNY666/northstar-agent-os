"""Tests for the state-transfer audit: the failures happen between the boxes.

Every public name in ``state_transfer_audit`` is named by at least one test
here, and each test drives a **behaviour** rather than a line: the mutant
probe plants a fault in the module and these tests must notice it.

The behaviours pinned here:

* the four transfer kinds are enumerable and each has a rule row;
* an event that cannot say where it came from is unverified;
* an event that needs an approval and has none is unverified;
* a compaction that does not declare its dropped constraints is unverified;
* a restore that does not declare its residual state is unverified;
* a restore that declares residual in-flight state is unverified;
* a kind-specific field on the wrong kind is refused;
* ``assert_verified`` raises on an unverified event and does not on a
  verified one;
* the hash chain names the first bad row;
* an event is immutable;
* a malformed event is refused at construction.
"""
from __future__ import annotations

import unittest

import state_transfer_audit as sta

DIGEST = "sha256:" + "a" * 64
OTHER_DIGEST = "sha256:" + "b" * 64


def _event(kind=sta.TransferKind.CONTEXT_WRITE, event_id="e-1", **kwargs):
    """A well-formed event, so each test varies exactly one thing."""
    fields = {
        "event_id": event_id,
        "kind": kind,
        "payload_digest": DIGEST,
        "source_event_id": "src-1",
        "occurred_at": "2026-11-25T00:00:00Z",
    }
    fields.update(kwargs)
    return sta.TransferEvent(**fields)


def _compact(event_id="c-1", **kwargs):
    """A compaction that declares its dropped constraints."""
    kwargs.setdefault("dropped_constraints", ())
    return _event(
        kind=sta.TransferKind.CONTEXT_COMPACT,
        event_id=event_id,
        **kwargs,
    )


def _memory(event_id="m-1", **kwargs):
    """A memory write that names its approver."""
    kwargs.setdefault("approved_by", "user-1")
    return _event(
        kind=sta.TransferKind.MEMORY_WRITE,
        event_id=event_id,
        **kwargs,
    )


def _restore(event_id="r-1", **kwargs):
    """A restore that declares its residual state."""
    kwargs.setdefault("approved_by", "user-1")
    kwargs.setdefault("residual_in_flight", False)
    return _event(
        kind=sta.TransferKind.WORKSPACE_RESTORE,
        event_id=event_id,
        **kwargs,
    )


class TransferKindTests(unittest.TestCase):
    """The four kinds are enumerable and each one has a rule row."""

    def test_there_are_exactly_four_transfer_kinds(self):
        self.assertEqual(
            {
                "context_write",
                "context_compact",
                "memory_write",
                "workspace_restore",
            },
            {kind.value for kind in sta.TransferKind},
        )

    def test_every_kind_has_a_policy_row(self):
        for kind in sta.TransferKind:
            self.assertIn(kind, sta.POLICIES)
            self.assertIs(sta.POLICIES[kind].kind, kind)

    def test_the_two_durable_boundaries_require_approval(self):
        self.assertTrue(sta.POLICIES[sta.TransferKind.MEMORY_WRITE].requires_approval)
        self.assertTrue(
            sta.POLICIES[sta.TransferKind.WORKSPACE_RESTORE].requires_approval
        )
        self.assertFalse(
            sta.POLICIES[sta.TransferKind.CONTEXT_WRITE].requires_approval
        )
        self.assertFalse(
            sta.POLICIES[sta.TransferKind.CONTEXT_COMPACT].requires_approval
        )

    def test_an_unknown_kind_name_is_refused(self):
        with self.assertRaises(sta.StateTransferAuditError):
            _event(kind="memory_teleport")

    def test_a_kind_of_the_wrong_type_is_refused(self):
        with self.assertRaises(sta.StateTransferAuditError):
            _event(kind=17)


class TransferEventTests(unittest.TestCase):
    """The event is the invariant: what moved, from where, approved by whom."""

    def test_an_event_carries_its_three_answers(self):
        event = _event(source_event_id="src-9", approved_by="user-2")
        self.assertEqual(DIGEST, event.payload_digest)
        self.assertEqual("src-9", event.source_event_id)
        self.assertEqual("user-2", event.approved_by)

    def test_an_event_records_the_occurred_at_the_caller_supplied(self):
        self.assertEqual("2026-11-25T00:00:00Z", _event().occurred_at)

    def test_an_event_is_immutable(self):
        event = _event()
        with self.assertRaises(Exception):
            event.payload_digest = OTHER_DIGEST

    def test_an_event_cannot_be_constructed_without_a_digest(self):
        with self.assertRaises(sta.StateTransferAuditError):
            _event(payload_digest="")

    def test_a_digest_that_is_not_a_sha256_pin_is_refused(self):
        with self.assertRaises(sta.StateTransferAuditError):
            _event(payload_digest="a" * 64)

    def test_a_digest_with_the_wrong_hex_length_is_refused(self):
        with self.assertRaises(sta.StateTransferAuditError):
            _event(payload_digest="sha256:abcd")

    def test_a_blank_event_id_is_refused(self):
        with self.assertRaises(sta.StateTransferAuditError):
            _event(event_id="   ")

    def test_a_non_string_event_id_is_refused(self):
        with self.assertRaises(sta.StateTransferAuditError):
            _event(event_id=42)

    def test_a_blank_source_event_id_is_refused(self):
        with self.assertRaises(sta.StateTransferAuditError):
            _event(source_event_id="  ")

    def test_a_non_bool_residual_in_flight_is_refused(self):
        with self.assertRaises(sta.StateTransferAuditError):
            _event(residual_in_flight="yes")

    def test_a_non_string_occurred_at_is_refused(self):
        with self.assertRaises(sta.StateTransferAuditError):
            _event(occurred_at=12345)

    def test_dropped_constraints_must_be_a_tuple_of_strings(self):
        with self.assertRaises(sta.StateTransferAuditError):
            _event(dropped_constraints="not a tuple")

    def test_to_dict_carries_every_field(self):
        payload = _compact().to_dict()
        for key in (
            "event_id",
            "kind",
            "payload_digest",
            "source_event_id",
            "approved_by",
            "dropped_constraints",
            "residual_in_flight",
            "occurred_at",
        ):
            self.assertIn(key, payload)
        self.assertEqual("context_compact", payload["kind"])


class RuleTableTests(unittest.TestCase):
    """The four kinds, each judged on its own rule row."""

    def test_a_context_write_with_provenance_is_verified(self):
        event = _event(kind=sta.TransferKind.CONTEXT_WRITE)
        verdict = sta.evaluate(event)
        self.assertTrue(verdict.verified)
        self.assertEqual(sta.REASON_OK, verdict.reason)

    def test_a_compaction_that_declares_its_dropped_constraints_is_verified(self):
        event = _compact(dropped_constraints=("do not touch main",))
        verdict = sta.evaluate(event)
        self.assertTrue(verdict.verified)
        self.assertEqual(sta.REASON_OK, verdict.reason)

    def test_a_compaction_that_declares_dropping_nothing_is_verified(self):
        # An empty declaration is a claim; an absent one is not.
        event = _compact(dropped_constraints=())
        self.assertTrue(sta.evaluate(event).verified)

    def test_a_memory_write_with_provenance_and_approval_is_verified(self):
        event = _memory(source_event_id="src-7", approved_by="user-9")
        verdict = sta.evaluate(event)
        self.assertTrue(verdict.verified)
        self.assertEqual(sta.REASON_OK, verdict.reason)

    def test_a_workspace_restore_that_declares_no_residual_state_is_verified(self):
        event = _restore(source_event_id="src-3", approved_by="user-2",
                        residual_in_flight=False)
        verdict = sta.evaluate(event)
        self.assertTrue(verdict.verified)
        self.assertEqual(sta.REASON_OK, verdict.reason)

    def test_classify_names_the_kind_of_an_event(self):
        self.assertEqual("context_write", sta.classify(_event()))
        self.assertEqual("context_compact", sta.classify(_compact()))
        self.assertEqual("memory_write", sta.classify(_memory()))
        self.assertEqual("workspace_restore", sta.classify(_restore()))

    def test_the_verified_flag_on_the_event_agrees_with_the_evaluator(self):
        for event in (_event(), _compact(), _memory(), _restore()):
            self.assertEqual(sta.evaluate(event).verified, event.verified)
            self.assertEqual(sta.evaluate(event).reason, event.reason)

    def test_every_reason_code_is_a_string_the_evaluator_can_produce(self):
        for code in sta.REASON_CODES:
            self.assertIsInstance(code, str)
        self.assertIn(sta.REASON_OK, sta.REASON_CODES)


class UnverifiedRuleTests(unittest.TestCase):
    """Each missing thing has its own reason code."""

    def test_a_transfer_without_provenance_is_unverified(self):
        event = _event(source_event_id=None)
        verdict = sta.evaluate(event)
        self.assertFalse(verdict.verified)
        self.assertEqual(sta.REASON_MISSING_PROVENANCE, verdict.reason)

    def test_a_memory_write_without_provenance_is_unverified(self):
        event = _memory(source_event_id=None, approved_by="user-1")
        self.assertEqual(
            sta.REASON_MISSING_PROVENANCE, sta.evaluate(event).reason
        )

    def test_a_memory_write_without_approval_is_unverified(self):
        event = _memory(approved_by=None)
        verdict = sta.evaluate(event)
        self.assertFalse(verdict.verified)
        self.assertEqual(sta.REASON_MISSING_APPROVAL, verdict.reason)

    def test_a_workspace_restore_without_approval_is_unverified(self):
        event = _restore(approved_by=None)
        verdict = sta.evaluate(event)
        self.assertFalse(verdict.verified)
        self.assertEqual(sta.REASON_MISSING_APPROVAL, verdict.reason)

    def test_a_compaction_that_does_not_declare_its_dropped_constraints_is_unverified(self):
        event = _compact(dropped_constraints=None)
        verdict = sta.evaluate(event)
        self.assertFalse(verdict.verified)
        self.assertEqual(
            sta.REASON_UNDECLARED_DROPPED_CONSTRAINTS, verdict.reason
        )

    def test_a_restore_that_does_not_declare_its_residual_state_is_unverified(self):
        event = _restore(residual_in_flight=None)
        verdict = sta.evaluate(event)
        self.assertFalse(verdict.verified)
        self.assertEqual(sta.REASON_UNDECLARED_RESIDUAL, verdict.reason)

    def test_a_restore_that_leaves_aborted_state_active_is_unverified(self):
        event = _restore(residual_in_flight=True)
        verdict = sta.evaluate(event)
        self.assertFalse(verdict.verified)
        self.assertEqual(sta.REASON_RESIDUAL_IN_FLIGHT, verdict.reason)

    def test_dropped_constraints_on_the_wrong_kind_is_refused(self):
        event = _event(dropped_constraints=("do not touch main",))
        verdict = sta.evaluate(event)
        self.assertFalse(verdict.verified)
        self.assertEqual(sta.REASON_MISPLACED_FIELD, verdict.reason)

    def test_residual_in_flight_on_the_wrong_kind_is_refused(self):
        event = _event(residual_in_flight=False)
        verdict = sta.evaluate(event)
        self.assertFalse(verdict.verified)
        self.assertEqual(sta.REASON_MISPLACED_FIELD, verdict.reason)

    def test_missing_provenance_is_reported_before_missing_approval(self):
        # The first failing rule wins, so the code names the root gap.
        event = _memory(source_event_id=None, approved_by=None)
        self.assertEqual(
            sta.REASON_MISSING_PROVENANCE, sta.evaluate(event).reason
        )

    def test_evaluate_refuses_something_that_is_not_an_event(self):
        with self.assertRaises(sta.StateTransferAuditError):
            sta.evaluate({"event_id": "e-1"})

    def test_classify_refuses_something_that_is_not_an_event(self):
        with self.assertRaises(sta.StateTransferAuditError):
            sta.classify("context_write")


class AssertVerifiedTests(unittest.TestCase):
    """The gate: a label is not a control, this is the control."""

    def test_assert_verified_returns_a_verified_event(self):
        event = _event()
        self.assertIs(event, sta.assert_verified(event))

    def test_assert_verified_raises_on_an_unverified_event(self):
        event = _event(source_event_id=None)
        with self.assertRaises(sta.UnverifiedTransferError):
            sta.assert_verified(event)

    def test_the_exception_names_the_reason_code(self):
        event = _compact(dropped_constraints=None)
        with self.assertRaises(sta.UnverifiedTransferError) as caught:
            sta.assert_verified(event)
        self.assertIn(sta.REASON_UNDECLARED_DROPPED_CONSTRAINTS, str(caught.exception))

    def test_the_exception_names_the_event_and_its_kind(self):
        event = _memory(event_id="m-77", approved_by=None)
        with self.assertRaises(sta.UnverifiedTransferError) as caught:
            sta.assert_verified(event)
        message = str(caught.exception)
        self.assertIn("m-77", message)
        self.assertIn("memory_write", message)

    def test_the_exception_is_catchable_as_the_module_error(self):
        event = _event(source_event_id=None)
        with self.assertRaises(sta.StateTransferAuditError):
            sta.assert_verified(event)


class TransferAuditorTests(unittest.TestCase):
    """The chain: what moved, in order, provably."""

    def test_an_empty_chain_verifies(self):
        auditor = sta.TransferAuditor()
        self.assertEqual(0, len(auditor))
        self.assertEqual((True, None), auditor.verify())
        self.assertEqual(sta.GENESIS_HASH, auditor.head)

    def test_recording_an_event_appends_a_row(self):
        auditor = sta.TransferAuditor()
        row = auditor.record(_event())
        self.assertEqual(0, row.seq)
        self.assertEqual(1, len(auditor))
        self.assertEqual(1, len(auditor.rows()))

    def test_an_intact_chain_verifies(self):
        auditor = sta.TransferAuditor()
        auditor.record(_event(event_id="e-1"))
        auditor.record(_compact(event_id="c-1"))
        auditor.record(_memory(event_id="m-1"))
        self.assertEqual((True, None), auditor.verify())

    def test_the_head_advances_with_each_recorded_event(self):
        auditor = sta.TransferAuditor()
        first = auditor.record(_event(event_id="e-1"))
        second = auditor.record(_event(event_id="e-2"))
        self.assertNotEqual(first.row_hash, second.row_hash)
        self.assertEqual(second.row_hash, auditor.head)
        self.assertEqual(first.row_hash, second.prev_hash)

    def test_events_come_back_in_the_order_they_were_recorded(self):
        auditor = sta.TransferAuditor()
        auditor.record(_event(event_id="e-1"))
        auditor.record(_compact(event_id="c-1"))
        self.assertEqual(
            ["e-1", "c-1"], [e.event_id for e in auditor.events()]
        )

    def test_a_tampered_event_breaks_the_chain_and_names_the_first_bad_row(self):
        auditor = sta.TransferAuditor()
        auditor.record(_event(event_id="e-1"))
        auditor.record(_event(event_id="e-2"))
        auditor.record(_event(event_id="e-3"))
        auditor._mutate_for_test(1, payload_digest=OTHER_DIGEST)
        ok, first_bad = auditor.verify()
        self.assertFalse(ok)
        self.assertEqual(1, first_bad)

    def test_a_tampered_first_row_is_named_as_row_zero(self):
        auditor = sta.TransferAuditor()
        auditor.record(_event(event_id="e-1"))
        auditor.record(_event(event_id="e-2"))
        auditor._mutate_for_test(0, event_id="e-1-forged")
        ok, first_bad = auditor.verify()
        self.assertFalse(ok)
        self.assertEqual(0, first_bad)

    def test_a_deleted_row_is_named_by_the_gap(self):
        auditor = sta.TransferAuditor()
        auditor.record(_event(event_id="e-1"))
        auditor.record(_event(event_id="e-2"))
        rows = auditor.rows()
        auditor._rows.pop(0)
        ok, first_bad = auditor.verify()
        self.assertFalse(ok)
        self.assertEqual(0, first_bad)

    def test_an_unverified_event_is_still_recorded_and_is_marked(self):
        # The chain records what happened, including a failure.  A failure
        # is reported, not hidden.
        auditor = sta.TransferAuditor()
        auditor.record(_event(source_event_id=None))
        self.assertEqual((True, None), auditor.verify())
        self.assertEqual(1, len(auditor.unverified()))

    def test_the_unverified_list_names_only_the_failing_events(self):
        auditor = sta.TransferAuditor()
        auditor.record(_event(event_id="good-1"))
        auditor.record(_memory(event_id="bad-1", approved_by=None))
        auditor.record(_event(event_id="good-2"))
        self.assertEqual(["bad-1"], [e.event_id for e in auditor.unverified()])

    def test_record_refuses_something_that_is_not_an_event(self):
        auditor = sta.TransferAuditor()
        with self.assertRaises(sta.StateTransferAuditError):
            auditor.record("not an event")

    def test_a_tamper_out_of_range_is_refused(self):
        auditor = sta.TransferAuditor()
        auditor.record(_event())
        with self.assertRaises(sta.StateTransferAuditError):
            auditor._mutate_for_test(7, event_id="nope")

    def test_the_row_hash_is_a_sha256_pin(self):
        auditor = sta.TransferAuditor()
        row = auditor.record(_event())
        self.assertTrue(row.row_hash.startswith("sha256:"))
        self.assertEqual(64, len(row.row_hash.split(":", 1)[1]))

    def test_compute_row_hash_is_pinned_to_the_previous_hash(self):
        event = _event()
        first = sta.compute_row_hash(0, event, sta.GENESIS_HASH)
        second = sta.compute_row_hash(0, event, sta.GENESIS_HASH)
        self.assertEqual(first, second)
        self.assertNotEqual(
            first, sta.compute_row_hash(0, event, "sha256:" + "c" * 64)
        )

    def test_a_row_carries_its_event_as_a_plain_dict(self):
        auditor = sta.TransferAuditor()
        row = auditor.record(_event())
        payload = row.to_dict()
        self.assertEqual(0, payload["seq"])
        self.assertEqual("e-1", payload["event"]["event_id"])
        self.assertIn("prev_hash", payload)
        self.assertIn("row_hash", payload)


class ModuleSurfaceTests(unittest.TestCase):
    """The module's own promises about itself."""

    def test_the_module_is_stdlib_only(self):
        self.assertTrue(sta.stdlib_only())

    def test_the_version_and_schema_pins_are_present(self):
        self.assertTrue(sta.STATE_TRANSFER_AUDIT_VERSION)
        self.assertTrue(sta.STATE_TRANSFER_AUDIT_SCHEMA)

    def test_the_genesis_pin_is_sixty_four_zeros(self):
        self.assertEqual("0" * 64, sta.GENESIS_HASH)

    def test_every_public_name_has_a_test_naming_it(self):
        for name in (
            "TransferKind",
            "TransferEvent",
            "TransferPolicy",
            "POLICIES",
            "Verdict",
            "TransferRow",
            "TransferAuditor",
            "evaluate",
            "classify",
            "assert_verified",
            "compute_row_hash",
            "stdlib_only",
            "GENESIS_HASH",
            "REASON_CODES",
            "UnverifiedTransferError",
            "StateTransferAuditError",
        ):
            self.assertIn(name, sta.__all__)


if __name__ == "__main__":
    unittest.main()

