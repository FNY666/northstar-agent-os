"""Tests for endpoint_identity.py.

Destination identity by state epoch: the identity of a destination is the
state it serves (an epoch), not the address it is reached at.  These tests
cover the equality rule, the fail-closed construction, the bound key, the
three replay verdicts, the acceptance ledger, and one end-to-end path that
drives an endpoint switch and a mixed replay.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from endpoint_identity import (  # noqa: E402
    ACCEPTED,
    CONFLICT,
    ENDPOINT_IDENTITY_VERSION,
    NEW_DESTINATION,
    PENDING,
    REPLAY,
    SCHEMA_PIN,
    AcceptanceLedger,
    DestinationIdentity,
    UnprovenIdentityError,
    bind_key,
    classify_replay,
    payload_fingerprint,
    prove_at_effect,
)

EPOCH_A = "sha256:" + "a" * 64
EPOCH_B = "sha256:" + "b" * 64
FP_X = "sha256:" + "c" * 64
FP_Y = "sha256:" + "d" * 64


class TestPins(unittest.TestCase):
    def test_version_pin(self):
        self.assertEqual(ENDPOINT_IDENTITY_VERSION, "endpoint-identity.v1")

    def test_schema_pin(self):
        self.assertEqual(SCHEMA_PIN, "northstar.endpoint-identity.v1")


class TestDestinationIdentityEquality(unittest.TestCase):
    """Equality looks at the epoch alone -- never at the address."""

    def test_same_address_different_epoch_is_a_different_identity(self):
        a1 = DestinationIdentity(epoch=EPOCH_A, address="https://api.example")
        a2 = DestinationIdentity(epoch=EPOCH_B, address="https://api.example")
        self.assertNotEqual(a1, a2)
        self.assertFalse(a1.same_state_as(a2))

    def test_same_epoch_different_address_is_the_same_identity(self):
        a1 = DestinationIdentity(epoch=EPOCH_A, address="https://api.example")
        a2 = DestinationIdentity(epoch=EPOCH_A, address="https://alias.example")
        self.assertEqual(a1, a2)
        self.assertTrue(a1.same_state_as(a2))

    def test_the_address_alone_is_never_an_identity(self):
        """A hostname re-pointed at a brand-new store is a new destination."""
        before = DestinationIdentity(epoch=EPOCH_A, address="https://api.example")
        after = DestinationIdentity(epoch=EPOCH_B, address="https://api.example")
        self.assertEqual(before.address, after.address)
        self.assertNotEqual(before, after)

    def test_identity_is_hashable_by_epoch(self):
        a1 = DestinationIdentity(epoch=EPOCH_A, address="https://api.example")
        a2 = DestinationIdentity(epoch=EPOCH_A, address="https://alias.example")
        self.assertEqual(len({a1, a2}), 1)


class TestDestinationIdentityConstruction(unittest.TestCase):
    def test_from_dict_refuses_a_missing_epoch(self):
        with self.assertRaises(UnprovenIdentityError):
            DestinationIdentity.from_dict({"address": "https://api.example"})

    def test_from_dict_refuses_an_empty_epoch(self):
        with self.assertRaises(UnprovenIdentityError):
            DestinationIdentity.from_dict({"epoch": "", "address": "https://x"})
        with self.assertRaises(UnprovenIdentityError):
            DestinationIdentity.from_dict({"epoch": "   "})

    def test_from_dict_round_trips(self):
        d = DestinationIdentity(epoch=EPOCH_A, address="https://api.example")
        back = DestinationIdentity.from_dict(d.to_dict())
        self.assertEqual(back, d)
        self.assertEqual(back.address, "https://api.example")

    def test_an_unproven_identity_is_not_provable(self):
        with self.assertRaises(UnprovenIdentityError):
            prove_at_effect(DestinationIdentity(epoch=EPOCH_A), None)
        with self.assertRaises(UnprovenIdentityError):
            prove_at_effect(DestinationIdentity(epoch=EPOCH_A), EPOCH_B)


class TestBindKey(unittest.TestCase):
    def setUp(self):
        self.a = DestinationIdentity(epoch=EPOCH_A, address="https://api.example")
        self.b = DestinationIdentity(epoch=EPOCH_B, address="https://api.example")
        self.alias = DestinationIdentity(epoch=EPOCH_A, address="https://alias")

    def test_bind_key_is_deterministic(self):
        first = bind_key("op-1", self.a, {"x": 1, "y": [2, 3]})
        second = bind_key("op-1", self.a, {"y": [2, 3], "x": 1})
        self.assertEqual(first, second)
        self.assertTrue(first.startswith("sha256:"))

    def test_bind_key_changes_when_the_operation_key_changes(self):
        self.assertNotEqual(
            bind_key("op-1", self.a, {"x": 1}), bind_key("op-2", self.a, {"x": 1})
        )

    def test_bind_key_changes_when_the_destination_epoch_changes(self):
        self.assertNotEqual(
            bind_key("op-1", self.a, {"x": 1}), bind_key("op-1", self.b, {"x": 1})
        )

    def test_bind_key_changes_when_the_payload_changes(self):
        self.assertNotEqual(
            bind_key("op-1", self.a, {"x": 1}), bind_key("op-1", self.a, {"x": 2})
        )

    def test_bind_key_ignores_the_address(self):
        self.assertEqual(
            bind_key("op-1", self.a, {"x": 1}), bind_key("op-1", self.alias, {"x": 1})
        )

    def test_the_payload_enters_as_a_fingerprint_not_as_text(self):
        digest = bind_key("op-1", self.a, {"x": 1})
        self.assertNotIn("x", digest)
        self.assertEqual(payload_fingerprint({"x": 1}), payload_fingerprint({"x": 1}))
        self.assertNotEqual(payload_fingerprint({"x": 1}), payload_fingerprint({"x": 2}))


class TestClassifyReplay(unittest.TestCase):
    def setUp(self):
        self.a = DestinationIdentity(epoch=EPOCH_A, address="https://api.example")
        self.b = DestinationIdentity(epoch=EPOCH_B, address="https://api.example")

    def test_same_destination_same_payload_is_a_replay(self):
        self.assertEqual(
            classify_replay(self.a, self.a, FP_X, FP_X), REPLAY
        )

    def test_same_destination_different_payload_is_a_conflict(self):
        self.assertEqual(
            classify_replay(self.a, self.a, FP_X, FP_Y), CONFLICT
        )

    def test_a_destination_change_is_a_new_destination(self):
        verdict = classify_replay(self.a, self.b, FP_X, FP_X)
        self.assertEqual(verdict, NEW_DESTINATION)
        self.assertNotEqual(verdict, REPLAY)
        self.assertNotEqual(verdict, CONFLICT)

    def test_a_destination_change_outranks_a_payload_change(self):
        """A new destination is not merely a payload conflict."""
        self.assertEqual(
            classify_replay(self.a, self.b, FP_X, FP_Y), NEW_DESTINATION
        )

    def test_the_address_alone_does_not_change_the_verdict(self):
        alias = DestinationIdentity(epoch=EPOCH_A, address="https://other.example")
        self.assertEqual(classify_replay(self.a, alias, FP_X, FP_X), REPLAY)


class TestAcceptanceLedger(unittest.TestCase):
    def setUp(self):
        self.a = DestinationIdentity(epoch=EPOCH_A, address="https://api.example")
        self.b = DestinationIdentity(epoch=EPOCH_B, address="https://api.example")
        self.ledger = AcceptanceLedger()

    def test_the_ledger_records_who_accepted_what(self):
        self.ledger.record_acceptance(
            "op-1", self.a, outcome=ACCEPTED, bound_digest=bind_key("op-1", self.a, {"x": 1})
        )
        found = self.ledger.accepted_by("op-1")
        self.assertIsNotNone(found)
        self.assertEqual(found.destination, self.a)
        self.assertEqual(found.outcome, ACCEPTED)
        self.assertEqual(self.ledger.acceptance_count(), 1)

    def test_an_operation_nobody_accepted_is_not_in_the_ledger(self):
        self.assertIsNone(self.ledger.accepted_by("op-2"))
        self.assertEqual(self.ledger.accepted_operations(), ())

    def test_a_pending_operation_is_visible_separately_from_an_acceptance(self):
        self.ledger.record_pending("op-2", self.a)
        self.assertEqual(self.ledger.pending_at("op-2"), self.a)
        self.assertIsNone(self.ledger.accepted_by("op-2"))
        self.assertEqual(self.ledger.pending_operations(), ("op-2",))

    def test_a_mixed_replay_can_be_explained(self):
        self.ledger.record_acceptance("op-1", self.a, bound_digest=bind_key("op-1", self.a, {}))
        self.ledger.record_pending("op-2", self.a)
        self.assertEqual(self.ledger.accepted_by("op-1").destination, self.a)
        self.assertIsNone(self.ledger.accepted_by("op-2"))
        self.assertEqual(self.ledger.pending_at("op-2"), self.a)


class TestEndToEndPaths(unittest.TestCase):
    """The whole mechanism, driven: replay, endpoint switch, conflict, mixed."""

    def setUp(self):
        self.a = DestinationIdentity(epoch=EPOCH_A, address="https://api.example")
        self.b = DestinationIdentity(epoch=EPOCH_B, address="https://api.example")
        self.ledger = AcceptanceLedger()
        self.effects = []

    def _send(self, op_key, destination, payload, outcome_unknown=False):
        """Model of one dispatch: an effect that happens exactly once."""
        fingerprint = payload_fingerprint(payload)
        bound = bind_key(op_key, destination, payload)
        if outcome_unknown:
            self.ledger.record_pending(op_key, destination)
            return bound, None
        self.effects.append((op_key, destination.epoch))
        self.ledger.record_acceptance(
            op_key,
            destination,
            outcome=ACCEPTED,
            bound_digest=bound,
            payload_fingerprint=fingerprint,
        )
        return bound, fingerprint

    def _replay(self, op_key, destination, payload, recorded_destination, recorded_fp):
        """Model of a retry: the destination may ratify the key or not."""
        fingerprint = payload_fingerprint(payload)
        bound = bind_key(op_key, destination, payload)
        verdict = classify_replay(
            recorded_destination, destination, recorded_fp, fingerprint
        )
        if verdict == REPLAY:
            # The destination already accepted this exact operation: the
            # effect must NOT happen again.
            return bound, verdict, fingerprint
        if verdict == CONFLICT:
            # Same key, different arguments: refuse, never return the first
            # result.
            return bound, verdict, fingerprint
        # NEW_DESTINATION: the new destination cannot ratify the old key.
        # The operation stays outcome_unknown; nothing is executed silently.
        self.ledger.record_pending(op_key, destination)
        return bound, verdict, None

    def test_a_replay_to_the_same_destination_does_not_apply_the_effect_twice(self):
        bound, fingerprint = self._send("op-1", self.a, {"amount": 10})
        _, verdict, _ = self._replay(
            "op-1", self.a, {"amount": 10}, self.a, fingerprint
        )
        self.assertEqual(verdict, REPLAY)
        self.assertEqual(len(self.effects), 1)
        self.assertEqual(self.ledger.acceptance_count(), 1)

    def test_an_endpoint_switch_makes_the_replay_a_new_destination(self):
        """Sent to A, outcome unknown; the endpoint switches to B."""
        bound, _ = self._send("op-1", self.a, {"amount": 10}, outcome_unknown=True)
        _, verdict, fingerprint = self._replay(
            "op-1", self.b, {"amount": 10}, self.a, payload_fingerprint({"amount": 10})
        )
        self.assertEqual(verdict, NEW_DESTINATION)
        self.assertIsNone(fingerprint)
        # No effect was applied at B, silently or otherwise.
        self.assertEqual(self.effects, [])
        # The operation is still pending at A and was not accepted anywhere.
        self.assertIsNone(self.ledger.accepted_by("op-1"))
        self.assertEqual(self.ledger.pending_at("op-1"), self.b)

    def test_the_same_key_with_a_different_payload_is_a_conflict(self):
        bound, fingerprint = self._send("op-1", self.a, {"amount": 10})
        _, verdict, _ = self._replay(
            "op-1", self.a, {"amount": 11}, self.a, fingerprint
        )
        self.assertEqual(verdict, CONFLICT)
        # The first effect stands; no second effect was applied.
        self.assertEqual(len(self.effects), 1)

    def test_a_mixed_replay_is_explainable_after_an_endpoint_switch(self):
        """op-1 landed at A; op-2 was still pending when the endpoint moved."""
        _, fingerprint = self._send("op-1", self.a, {"amount": 10})
        self._send("op-2", self.a, {"amount": 20}, outcome_unknown=True)
        # The endpoint switches to B.
        _, verdict, _ = self._replay(
            "op-2", self.b, {"amount": 20}, self.a, payload_fingerprint({"amount": 20})
        )
        self.assertEqual(verdict, NEW_DESTINATION)
        # op-1 landed at A; op-2 was accepted by nobody.
        self.assertEqual(self.ledger.accepted_by("op-1").destination, self.a)
        self.assertIsNone(self.ledger.accepted_by("op-2"))
        self.assertEqual(len(self.effects), 1)

    def test_the_effect_time_proof_requires_the_attested_epoch(self):
        """A destination that offers only an address has proven nothing."""
        self.assertEqual(
            prove_at_effect(self.a, EPOCH_A).epoch, EPOCH_A
        )
        with self.assertRaises(UnprovenIdentityError):
            prove_at_effect(self.b, EPOCH_A)  # the caller presents a new epoch
        with self.assertRaises(UnprovenIdentityError):
            prove_at_effect(self.a, None)  # the destination attested nothing
