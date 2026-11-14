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

import endpoint_identity  # noqa: E402
from endpoint_identity import (  # noqa: E402
    ACCEPTED,
    CONFLICT,
    ENDPOINT_IDENTITY_VERSION,
    NEW_DESTINATION,
    OUTCOME_UNKNOWN,
    REPLAY,
    SCHEMA_PIN,
    AcceptanceLedger,
    DestinationIdentity,
    EndpointIdentityError,
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

    def test_is_proven_reports_whether_an_epoch_is_present(self):
        self.assertTrue(DestinationIdentity(epoch=EPOCH_A).is_proven())
        with self.assertRaises(UnprovenIdentityError):
            DestinationIdentity(epoch="")

    def test_the_error_taxonomy_is_rooted_in_endpoint_identity_error(self):
        self.assertTrue(issubclass(UnprovenIdentityError, EndpointIdentityError))
        self.assertTrue(issubclass(UnprovenIdentityError, ValueError))

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
        # Fail closed: the outcome stays outcome_unknown, awaiting
        # reconciliation.  It is never silently upgraded to "done".
        self.assertEqual(self.ledger.outcome_of("op-1"), OUTCOME_UNKNOWN)

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
        self.assertEqual(self.ledger.outcome_of("op-2"), OUTCOME_UNKNOWN)
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


class MutantOrAt81CanonicalNoneBoolTests(unittest.TestCase):
    """Kills the ``or@81`` mutant in ``_canonical``.

    The guard is::

        if value is None or isinstance(value, bool):
            pass

    Mutating ``or`` to ``and`` makes the guard fire only when the value is
    *both* ``None`` *and* a bool -- never.  The ``None``/``bool`` branch
    stops being taken and those values fall through to the final ``else``,
    which raises ``TypeError``.

    Two wrong ways are needed, because ``or`` -> ``and`` only differs from
    the original when exactly one side is true:

    * ``None`` -- format right (not a bool) but type wrong.  The original
      canonicalizes it to ``b"null"``; the mutant raises ``TypeError``.
    * ``True``/``False`` -- type right (a bool) but format wrong.  The
      original canonicalizes them to ``b"true"``/``b"false"``; the mutant
      raises ``TypeError``.
    """

    def test_or_at_81_none_is_canonicalized_as_null(self):
        # Format right (not a bool) but type wrong.
        self.assertEqual(endpoint_identity._canonical(None), b"null")

    def test_or_at_81_true_is_canonicalized_as_true(self):
        # Type right (a bool) but format wrong.
        self.assertEqual(endpoint_identity._canonical(True), b"true")

    def test_or_at_81_false_is_canonicalized_as_false(self):
        self.assertEqual(endpoint_identity._canonical(False), b"false")

    def test_or_at_81_a_none_inside_a_structure_is_still_canonicalized(self):
        # The nested path must survive the guard being pinned.
        self.assertEqual(
            endpoint_identity._canonical({"a": None, "b": True}),
            b'{"a":null,"b":true}',
        )


class MutantOrAt86CanonicalNanInfTests(unittest.TestCase):
    """Kills the ``or@86`` mutant in ``_canonical``.

    The guard is::

        if math.isnan(value) or math.isinf(value):
            raise TypeError("value must not contain NaN or infinity")

    Mutating ``or`` to ``and`` makes the guard fire only when the value is
    *both* NaN *and* infinite -- never, because no float is both.  The
    guard stops firing and NaN/Inf are canonicalized into the digest.

    Two wrong ways are needed:

    * a **NaN** -- format right (not infinite) but type wrong.  The original
      raises ``TypeError``; the mutant writes ``"NaN"`` into the digest.
    * an **infinity** -- type right (not NaN) but format wrong.  The
      original raises ``TypeError``; the mutant writes ``"Infinity"`` into
      the digest.
    """

    def test_or_at_86_a_nan_is_refused(self):
        # Format right (not infinite) but type wrong.
        with self.assertRaises(TypeError) as caught:
            endpoint_identity._canonical(float("nan"))
        self.assertIn("NaN", str(caught.exception))

    def test_or_at_86_a_positive_infinity_is_refused(self):
        # Type right (not NaN) but format wrong.
        with self.assertRaises(TypeError) as caught:
            endpoint_identity._canonical(float("inf"))
        self.assertIn("infinity", str(caught.exception))

    def test_or_at_86_a_negative_infinity_is_refused(self):
        with self.assertRaises(TypeError):
            endpoint_identity._canonical(float("-inf"))

    def test_or_at_86_a_nan_inside_a_structure_is_still_refused(self):
        with self.assertRaises(TypeError):
            endpoint_identity._canonical([1.0, float("nan")])

    def test_or_at_86_an_ordinary_float_is_still_canonicalized(self):
        # The control: the happy path must survive the guard being pinned.
        self.assertEqual(endpoint_identity._canonical(1.5), b"1.5")


class MutantGtAt131RequireAddressTests(unittest.TestCase):
    """Kills the ``gt@131`` mutant in ``_require_address``.

    The guard is::

        if len(address) > _MAX_LABEL_LEN:

    Mutating ``>`` to ``>=`` rejects an address of *exactly* the limit,
    which the rule allows.  Only the exact-boundary value distinguishes
    the two, so the tests feed the limit itself and the limit +/- 1.

    ``_require_address`` is a private helper, so the tests reach it
    directly: the boundary is not observable through
    ``DestinationIdentity``'s public constructor in the same shape.
    """

    def test_gt_at_131_an_address_of_exactly_the_limit_is_accepted(self):
        address = "a" * endpoint_identity._MAX_LABEL_LEN
        self.assertEqual(
            endpoint_identity._require_address(address), address
        )

    def test_gt_at_131_an_address_one_over_the_limit_is_refused(self):
        address = "a" * (endpoint_identity._MAX_LABEL_LEN + 1)
        with self.assertRaises(ValueError) as caught:
            endpoint_identity._require_address(address)
        self.assertIn("at most", str(caught.exception))

    def test_gt_at_131_an_address_one_under_the_limit_is_accepted(self):
        address = "a" * (endpoint_identity._MAX_LABEL_LEN - 1)
        self.assertEqual(
            endpoint_identity._require_address(address), address
        )

    def test_gt_at_131_a_none_address_is_still_the_empty_string(self):
        # The control: the None short-circuit must survive.
        self.assertEqual(endpoint_identity._require_address(None), "")
