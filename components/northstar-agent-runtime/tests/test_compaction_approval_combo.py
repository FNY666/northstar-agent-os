"""Tests for the compaction+approval integration guard."""
from __future__ import annotations

import dataclasses
import json
import unittest

import support  # noqa: F401

import ed25519
import signed_receipt_reflux as srr
from compaction_approval_combo import (
    COMPACTION_APPROVAL_VERSION,
    SCHEMA_PIN,
    CompactionApprovalGuard,
    CompactionGuardError,
    GuardAuditEvent,
    GuardedCompaction,
    HistoryEntry,
    serialize_receipt,
    verify_output,
)

SECRET = bytes(range(32))
PUBKEY = ed25519.public_key(SECRET)
WRONG_SECRET = bytes([255 - b for b in range(32)])
WRONG_PUBKEY = ed25519.public_key(WRONG_SECRET)


def make_guard(**kwargs):
    return CompactionApprovalGuard(PUBKEY, **kwargs)


def make_receipt(request_id="req-1", action="tool:delete:/tmp/x",
                 approver="human:alice", seq=7, secret=SECRET):
    return srr.issue_receipt(request_id, action, approver, seq, secret)


class VersionTests(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(COMPACTION_APPROVAL_VERSION, "compaction-approval-combo.v1")
        self.assertEqual(SCHEMA_PIN, "northstar.compaction-approval-combo.v1")

    def test_guard_output_carries_version(self):
        guard = make_guard()
        out = guard.compact([])
        self.assertEqual(out.guard_version, COMPACTION_APPROVAL_VERSION)


class EntryValidationTests(unittest.TestCase):
    def test_bad_kind_rejected(self):
        with self.assertRaises(CompactionGuardError):
            HistoryEntry(kind="evidence", payload="x")

    def test_non_str_payload_rejected(self):
        with self.assertRaises(TypeError):
            HistoryEntry(kind="narrative", payload=123)

    def test_receipt_without_request_id_rejected(self):
        with self.assertRaises(CompactionGuardError):
            HistoryEntry(kind="receipt", payload="x")

    def test_narrative_with_request_id_rejected(self):
        with self.assertRaises(CompactionGuardError):
            HistoryEntry(kind="narrative", payload="x", request_id="req-1")

    def test_entry_is_frozen(self):
        entry = HistoryEntry(kind="narrative", payload="x")
        with self.assertRaises(dataclasses.FrozenInstanceError):
            entry.payload = "y"

    def test_bad_pubkey_rejected(self):
        with self.assertRaises(srr.ReceiptError):
            CompactionApprovalGuard(b"too-short")


class RegistrationTests(unittest.TestCase):
    def test_register_verifies_and_returns_digest(self):
        guard = make_guard()
        receipt = make_receipt()
        digest = guard.register_receipt(receipt)
        self.assertEqual(digest, srr.receipt_digest(receipt))
        self.assertEqual(guard.registered(), ("req-1",))

    def test_tampered_receipt_refused(self):
        guard = make_guard()
        bad = make_receipt(secret=WRONG_SECRET)
        with self.assertRaises(CompactionGuardError):
            guard.register_receipt(bad)
        self.assertEqual(guard.registered(), ())
        # refusal is audited
        kinds = [e.kind for e in guard.audit_events()]
        self.assertIn("receipt-refused", kinds)

    def test_register_non_receipt_rejected(self):
        guard = make_guard()
        with self.assertRaises(CompactionGuardError):
            guard.register_receipt("not-a-receipt")

    def test_duplicate_registration_refused(self):
        guard = make_guard()
        guard.register_receipt(make_receipt())
        with self.assertRaises(CompactionGuardError):
            guard.register_receipt(make_receipt())


class CompactionTests(unittest.TestCase):
    def test_receipt_survives_verbatim_despite_maskable_shapes(self):
        guard = make_guard()
        receipt = make_receipt(request_id="req-sk-1234567890abcdef",
                               approver="human:alice@example.com")
        guard.register_receipt(receipt)
        history = [
            HistoryEntry(kind="narrative",
                         payload="the api key is sk-abcDEF1234567890 ok"),
            HistoryEntry(kind="receipt", payload="smuggled",
                         request_id="req-sk-1234567890abcdef"),
        ]
        out = guard.compact(history)
        # narrative masked
        self.assertIn("[REDACTED:api_key]", out.entries[0].payload)
        self.assertNotIn("sk-abcDEF1234567890", out.entries[0].payload)
        # receipt verbatim: email approver and sk-like request id untouched
        self.assertIn("human:alice@example.com", out.entries[1].payload)
        self.assertIn("req-sk-1234567890abcdef", out.entries[1].payload)
        self.assertNotIn("[REDACTED", out.entries[1].payload)

    def test_receipt_payload_comes_from_registry_not_caller(self):
        guard = make_guard()
        guard.register_receipt(make_receipt())
        out = guard.compact([
            HistoryEntry(kind="receipt", payload="forged-payload", request_id="req-1"),
        ])
        self.assertEqual(out.entries[0].payload,
                         serialize_receipt(make_receipt()))

    def test_unregistered_receipt_refused(self):
        guard = make_guard()
        with self.assertRaises(CompactionGuardError):
            guard.compact([
                HistoryEntry(kind="receipt", payload="x", request_id="req-ghost"),
            ])

    def test_empty_history(self):
        guard = make_guard()
        out = guard.compact([])
        self.assertEqual(out.entries, ())
        self.assertFalse(out.masked_any)
        self.assertEqual(out.receipt_request_ids, ())

    def test_non_entry_rejected(self):
        guard = make_guard()
        with self.assertRaises(TypeError):
            guard.compact(["not-an-entry"])

    def test_masking_disabled_still_protects_receipts(self):
        guard = make_guard(masking_enabled=False)
        receipt = make_receipt(approver="human:bob@example.com")
        guard.register_receipt(receipt)
        out = guard.compact([
            HistoryEntry(kind="narrative", payload="key sk-abcDEF1234567890 here"),
            HistoryEntry(kind="receipt", payload="x", request_id="req-1"),
        ])
        # narrative untouched when masking disabled
        self.assertIn("sk-abcDEF1234567890", out.entries[0].payload)
        self.assertFalse(out.masked_any)
        # receipt still present and verifiable
        self.assertTrue(verify_output(out, PUBKEY))

    def test_output_digests_match_registry(self):
        guard = make_guard()
        r1 = make_receipt(request_id="req-1")
        r2 = make_receipt(request_id="req-2", seq=8)
        guard.register_receipt(r1)
        guard.register_receipt(r2)
        out = guard.compact([
            HistoryEntry(kind="receipt", payload="x", request_id="req-2"),
            HistoryEntry(kind="receipt", payload="y", request_id="req-1"),
        ])
        self.assertEqual(out.receipt_request_ids, ("req-2", "req-1"))
        self.assertEqual(out.receipt_digests,
                         (srr.receipt_digest(r2), srr.receipt_digest(r1)))

    def test_deterministic(self):
        def run():
            guard = make_guard()
            guard.register_receipt(make_receipt())
            return guard.compact([
                HistoryEntry(kind="narrative", payload="call 555-123-4567 now"),
                HistoryEntry(kind="receipt", payload="x", request_id="req-1"),
            ])
        a, b = run(), run()
        self.assertEqual(a.entries, b.entries)
        self.assertEqual(a.as_dict(), b.as_dict())

    def test_as_dict_shape(self):
        guard = make_guard()
        guard.register_receipt(make_receipt())
        out = guard.compact([
            HistoryEntry(kind="receipt", payload="x", request_id="req-1"),
        ])
        d = out.as_dict()
        self.assertEqual(d["entries"], 1)
        self.assertEqual(d["receipt_request_ids"], ["req-1"])
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertEqual(d["guard_version"], COMPACTION_APPROVAL_VERSION)


class VerificationTests(unittest.TestCase):
    def test_verify_output_true(self):
        guard = make_guard()
        guard.register_receipt(make_receipt())
        out = guard.compact([
            HistoryEntry(kind="receipt", payload="x", request_id="req-1"),
        ])
        self.assertTrue(verify_output(out, PUBKEY))

    def test_verify_output_wrong_key_false(self):
        guard = make_guard()
        guard.register_receipt(make_receipt())
        out = guard.compact([
            HistoryEntry(kind="receipt", payload="x", request_id="req-1"),
        ])
        self.assertFalse(verify_output(out, WRONG_PUBKEY))

    def test_verify_output_tampered_entry_false(self):
        guard = make_guard()
        guard.register_receipt(make_receipt())
        out = guard.compact([
            HistoryEntry(kind="receipt", payload="x", request_id="req-1"),
        ])
        tampered = dataclasses.replace(
            out,
            entries=(HistoryEntry(kind="receipt", payload="tampered",
                                  request_id="req-1"),),
        )
        self.assertFalse(verify_output(tampered, PUBKEY))

    def test_verify_output_bad_input_type(self):
        with self.assertRaises(TypeError):
            verify_output("not-a-compaction", PUBKEY)

    def test_verify_output_no_receipts_true(self):
        guard = make_guard()
        out = guard.compact([HistoryEntry(kind="narrative", payload="hello")])
        self.assertTrue(verify_output(out, PUBKEY))


class AuditTrailTests(unittest.TestCase):
    def test_audit_trail_records_decisions(self):
        guard = make_guard()
        guard.register_receipt(make_receipt())
        guard.compact([HistoryEntry(kind="narrative", payload="hello")])
        events = guard.audit_events()
        self.assertEqual([e.kind for e in events],
                         ["receipt-registered", "compaction-completed"])
        self.assertEqual([e.seq for e in events], [0, 1])
        # structured, never masked
        self.assertEqual(events[0].request_id, "req-1")
        self.assertTrue(events[0].detail.startswith("sha256:"))

    def test_audit_event_shape(self):
        guard = make_guard()
        guard.register_receipt(make_receipt())
        d = guard.audit_events()[0].as_dict()
        self.assertEqual(d["schema"], SCHEMA_PIN)
        self.assertEqual(d["version"], COMPACTION_APPROVAL_VERSION)

    def test_audit_event_validation(self):
        with self.assertRaises(CompactionGuardError):
            GuardAuditEvent(seq=-1, kind="x", request_id="r", detail="d")
        with self.assertRaises(CompactionGuardError):
            GuardAuditEvent(seq=True, kind="x", request_id="r", detail="d")

    def test_audit_trail_append_only(self):
        guard = make_guard()
        first = guard.audit_events()
        guard.register_receipt(make_receipt())
        second = guard.audit_events()
        self.assertEqual(len(first), 0)
        self.assertEqual(len(second), 1)


class MainTests(unittest.TestCase):
    def test_main_selfcheck(self):
        from compaction_approval_combo import main
        main()  # raises on failure


if __name__ == "__main__":
    unittest.main()
