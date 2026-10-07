"""Tests for identity_approval_combo: disclosure-before-approval wiring."""
from __future__ import annotations

import unittest

from approval_sla import (
    ApprovalQueue,
    STATUS_APPROVED,
    STATUS_EXPIRED,
    STATUS_PENDING,
)
from identity_disclosure import (
    DisclosureError,
    DisclosureLog,
    DisclosureRequirement,
    IdentityCard,
)
from identity_approval_combo import (
    IDENTITY_APPROVAL_SCHEMA,
    IDENTITY_APPROVAL_VERSION,
    IdentityApproval,
    IdentityApprovalGate,
    identity_approval_audit_events,
)


def _card() -> IdentityCard:
    return IdentityCard(
        agent_name="northstar-ops",
        operator="ops-team",
        capabilities_summary="run approved maintenance actions",
        limitations="cannot approve its own actions",
    )


def _gate(requirement=DisclosureRequirement.ALWAYS):
    return IdentityApprovalGate(DisclosureLog(), ApprovalQueue(), requirement)


class VersionPinTest(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(IDENTITY_APPROVAL_VERSION, "identity-approval-combo.v1")

    def test_schema_pin(self):
        self.assertEqual(IDENTITY_APPROVAL_SCHEMA, "northstar.identity-approval-combo.v1")


class DiscloseThenRequestTest(unittest.TestCase):
    def test_user_facing_discloses_before_request(self):
        gate = _gate()
        approval = gate.request_approval(
            "restart worker-3", "abstain: disruptive", _card(), "chat", 10, 100
        )
        self.assertTrue(approval.disclosed)
        self.assertIsNotNone(approval.disclosure_digest)
        self.assertIsNotNone(approval.disclosure_text)
        # Disclosure was recorded: log has exactly one record.
        self.assertEqual(len(gate._log), 1)

    def test_reason_carries_identity_line(self):
        gate = _gate()
        approval = gate.request_approval(
            "restart worker-3", "abstain: disruptive", _card(), "chat", 10, 100
        )
        queued = gate._queue.get(approval.request_id)
        self.assertIn("northstar-ops", queued.reason)
        self.assertIn("ops-team", queued.reason)
        self.assertIn("abstain: disruptive", queued.reason)

    def test_disclosure_seq_matches_request_seq(self):
        gate = _gate()
        approval = gate.request_approval(
            "restart worker-3", "abstain", _card(), "chat", 10, 100
        )
        record = gate.disclosure_for(approval.request_id)
        self.assertIsNotNone(record)
        assert record is not None
        queued = gate._queue.get(approval.request_id)
        # Disclosure happened at the same seq the request was parked.
        self.assertEqual(record.seq, 100)
        self.assertEqual(queued.requested_seq, 100)
        self.assertEqual(approval.disclosure_digest, record.record_digest())

    def test_disclosure_text_names_agent(self):
        gate = _gate()
        approval = gate.request_approval(
            "restart worker-3", "abstain", _card(), "email", 10, 100
        )
        assert approval.disclosure_text is not None
        self.assertIn("northstar-ops", approval.disclosure_text)
        self.assertIn("AI agent", approval.disclosure_text)

    def test_context_floor_under_never_policy(self):
        gate = _gate(DisclosureRequirement.NEVER)
        approval = gate.request_approval(
            "restart worker-3", "abstain", _card(), "chat", 10, 100
        )
        # User-facing channel discloses even under NEVER.
        self.assertTrue(approval.disclosed)
        self.assertEqual(len(gate._log), 1)


class InternalContextTest(unittest.TestCase):
    def test_internal_never_skips_disclosure(self):
        gate = _gate(DisclosureRequirement.NEVER)
        approval = gate.request_approval(
            "gc cache", "routine", _card(), "internal", 10, 100
        )
        self.assertFalse(approval.disclosed)
        self.assertIsNone(approval.disclosure_digest)
        self.assertIsNone(approval.disclosure_text)
        self.assertEqual(len(gate._log), 0)
        # Request still parked; identity still pinned on the reason.
        queued = gate._queue.get(approval.request_id)
        self.assertIn("northstar-ops", queued.reason)

    def test_internal_always_discloses(self):
        gate = _gate(DisclosureRequirement.ALWAYS)
        approval = gate.request_approval(
            "gc cache", "routine", _card(), "internal", 10, 100
        )
        self.assertTrue(approval.disclosed)
        self.assertEqual(len(gate._log), 1)

    def test_on_request_policy(self):
        gate = _gate(DisclosureRequirement.ON_REQUEST)
        quiet = gate.request_approval(
            "gc cache", "routine", _card(), "internal", 10, 100
        )
        self.assertFalse(quiet.disclosed)
        asked = gate.request_approval(
            "gc cache", "routine", _card(), "internal", 10, 101, on_request=True
        )
        self.assertTrue(asked.disclosed)

    def test_disclosure_for_returns_none_when_undisclosed(self):
        gate = _gate(DisclosureRequirement.NEVER)
        approval = gate.request_approval(
            "gc cache", "routine", _card(), "internal", 10, 100
        )
        self.assertIsNone(gate.disclosure_for(approval.request_id))

    def test_unknown_channel_fails_closed_toward_disclosure(self):
        gate = _gate(DisclosureRequirement.NEVER)
        approval = gate.request_approval(
            "gc cache", "routine", _card(), "quantum-entanglement", 10, 100
        )
        self.assertTrue(approval.disclosed)


class FailClosedTest(unittest.TestCase):
    def test_no_card_refuses(self):
        gate = _gate()
        with self.assertRaises(DisclosureError):
            gate.request_approval(
                "restart worker-3", "abstain", None, "chat", 10, 100  # type: ignore[arg-type]
            )

    def test_wrong_card_type_refuses(self):
        gate = _gate()
        with self.assertRaises(DisclosureError):
            gate.request_approval(
                "restart worker-3", "abstain", "not-a-card", "chat", 10, 100  # type: ignore[arg-type]
            )

    def test_broken_log_chain_refuses(self):
        gate = _gate()
        gate._log.verify_chain = lambda: False  # type: ignore[method-assign]
        with self.assertRaises(DisclosureError):
            gate.request_approval(
                "restart worker-3", "abstain", _card(), "chat", 10, 100
            )

    def test_bad_inputs_refuse_before_disclosure(self):
        gate = _gate()
        with self.assertRaises(ValueError):
            gate.request_approval("", "abstain", _card(), "chat", 10, 100)
        with self.assertRaises(ValueError):
            gate.request_approval("x", "abstain", _card(), "chat", 0, 100)
        with self.assertRaises(ValueError):
            gate.request_approval("x", "abstain", _card(), "chat", 10, -1)
        # Nothing was disclosed or queued on refusal.
        self.assertEqual(len(gate._log), 0)
        self.assertEqual(len(gate._queue), 0)


class SlaDoctrinePreservedTest(unittest.TestCase):
    def test_poll_and_decide_delegate(self):
        gate = _gate()
        approval = gate.request_approval(
            "restart worker-3", "abstain", _card(), "chat", 10, 100
        )
        self.assertEqual(gate.poll(approval.request_id, 105), STATUS_PENDING)
        gate.decide(approval.request_id, True, "op-1")
        self.assertEqual(gate.poll(approval.request_id, 106), STATUS_APPROVED)

    def test_expiry_fails_closed(self):
        gate = _gate()
        approval = gate.request_approval(
            "restart worker-3", "abstain", _card(), "chat", 5, 100
        )
        self.assertEqual(gate.poll(approval.request_id, 106), STATUS_EXPIRED)
        with self.assertRaises(ValueError):
            gate.decide(approval.request_id, True, "op-1")

    def test_unknown_request_raises_keyerror(self):
        gate = _gate()
        with self.assertRaises(KeyError):
            gate.poll("apr-nope", 100)

    def test_views_delegate(self):
        gate = _gate()
        a1 = gate.request_approval("x", "r", _card(), "chat", 5, 100)
        a2 = gate.request_approval("y", "r", _card(), "chat", 100, 100)
        self.assertEqual(len(gate.pending()), 2)
        gate.decide(a2.request_id, False, "op-1")
        self.assertEqual(len(gate.decided()), 1)
        self.assertEqual(gate.poll(a1.request_id, 106), STATUS_EXPIRED)
        self.assertEqual(len(gate.expired()), 1)


class AuditEventTest(unittest.TestCase):
    def test_audit_event_shape(self):
        gate = _gate()
        approval = gate.request_approval(
            "restart worker-3", "abstain", _card(), "chat", 10, 100
        )
        events = identity_approval_audit_events(approval)
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event["event"], "identity_approval.requested")
        self.assertEqual(event["request_id"], approval.request_id)
        self.assertEqual(event["agent_name"], "northstar-ops")
        self.assertTrue(event["disclosed"])
        self.assertEqual(event["disclosure_digest"], approval.disclosure_digest)
        self.assertEqual(event["schema"], IDENTITY_APPROVAL_SCHEMA)

    def test_audit_event_undisclosed(self):
        gate = _gate(DisclosureRequirement.NEVER)
        approval = gate.request_approval(
            "gc cache", "routine", _card(), "internal", 10, 100
        )
        event = identity_approval_audit_events(approval)[0]
        self.assertFalse(event["disclosed"])
        self.assertIsNone(event["disclosure_digest"])

    def test_audit_event_bad_input(self):
        with self.assertRaises(DisclosureError):
            identity_approval_audit_events("nope")  # type: ignore[arg-type]


class MainTest(unittest.TestCase):
    def test_main(self):
        from identity_approval_combo import main

        main()


if __name__ == "__main__":
    unittest.main()
