"""Tests for endpoint_identity.py.

Destination identity by state epoch: the identity of a destination is the
state it serves (an epoch), not the address it is reached at.  These tests
cover the equality rule, the fail-closed construction, the bound key, the
three replay verdicts, the acceptance ledger, and one end-to-end path that
drives an endpoint switch and a mixed replay.
"""

import os
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

class MutantSecondHalfGuardTests(unittest.TestCase):
    """The missing arm of every surviving guard in ``endpoint_identity``.

    A planted fault survives this slice's suite when only one arm of a
    two-armed guard was ever driven.  Each guard below is written as
    ``A or B`` (or ``A and B``); the mutant flips the connective, so the
    mutant and the original differ only when exactly one side of the
    connective holds.  The tests therefore feed BOTH kinds of bad input:
    the one that trips arm A only, and the one that trips arm B only.

    The guards driven here, and the arm each test exercises:

    ``or@192``  ``epoch is None or (isinstance(epoch, str) and not
                epoch.strip())`` in ``DestinationIdentity.from_dict``.
    ``or@196``  ``value.get("address", "") or ""`` in ``from_dict``.
    ``and@200`` ``bool(self.epoch and self.epoch.strip())`` in
                ``is_proven``.
    ``or@220``  ``not isinstance(operation_key, str) or not
                operation_key`` in ``bind_key``.
    ``or@263``  ``not isinstance(value, str) or not value`` in
                ``classify_replay``.
    ``or@284``  ``attested_epoch is None or not isinstance(attested_epoch,
                str) or not attested_epoch.strip()`` in ``prove_at_effect``.
    ``or@341``  the ``operation_key`` guard of ``record_acceptance``.
    ``or@345``  the ``outcome`` guard of ``record_acceptance``.
    ``or@347``  the ``bound_digest`` guard of ``record_acceptance``.
    ``or@349``  the ``payload_fingerprint`` guard of ``record_acceptance``.
    ``or@374``  the ``operation_key`` guard of ``record_pending``.
    ``or@396``  the ``operation_key`` guard of ``accepted_by``.
    ``or@402``  the ``operation_key`` guard of ``pending_at``.

    The ``main()`` self-check and the ``__main__`` guard are driven by
    :class:`MutantSelfCheckTests`.
    """

    def setUp(self):
        self.a = DestinationIdentity(epoch=EPOCH_A, address="https://api.example")

    # --- or@192: from_dict's missing/empty epoch -----------------------
    def test_or_at_192_a_missing_epoch_is_refused_as_missing(self):
        """`or@192`: the MISSING half -- the key is absent entirely.

        The guard is ``epoch is None or (isinstance(epoch, str) and not
        epoch.strip())``.  Under the mutant (``or`` -> ``and``) it fires
        only when the epoch is both ``None`` *and* a blank string --
        never -- so a missing epoch slips past this check and is
        refused further down, by ``_require_epoch``, with a *different*
        reason.  The refusal still happens, so the exception type is
        not the discriminator; the **message** is: the fail-closed
        reason the caller is told must not change.
        """
        with self.assertRaises(UnprovenIdentityError) as caught:
            DestinationIdentity.from_dict({"address": "https://api.example"})
        self.assertIn("missing or empty", str(caught.exception))

    def test_or_at_192_an_empty_epoch_is_refused_as_missing(self):
        """`or@192`: the EMPTY half -- the key is present but blank."""
        with self.assertRaises(UnprovenIdentityError) as caught:
            DestinationIdentity.from_dict({"epoch": "   ", "address": "https://x"})
        self.assertIn("missing or empty", str(caught.exception))

    def test_or_at_192_a_present_epoch_is_accepted(self):
        # The control: a real epoch must still build.
        built = DestinationIdentity.from_dict(
            {"epoch": EPOCH_A, "address": "https://api.example"}
        )
        self.assertEqual(built.epoch, EPOCH_A)

    # --- or@196: from_dict's address fallback -------------------------
    def test_or_at_196_a_present_address_is_kept(self):
        """`or@196`: the PRESENT half -- the address is a real string.

        The guard is ``value.get("address", "") or ""``.  Under the
        mutant (``or`` -> ``and``) it evaluates to the *left* operand
        only, so a present, non-empty address is replaced by the empty
        string: the identity silently loses the label it was given.
        """
        built = DestinationIdentity.from_dict(
            {"epoch": EPOCH_A, "address": "https://api.example"}
        )
        self.assertEqual(built.address, "https://api.example")

    def test_or_at_196_an_absent_address_becomes_the_empty_string(self):
        """`or@196`: the ABSENT half -- no ``address`` key at all.

        With no ``address`` key the ``.get`` default already yields
        ``""``; the ``or`` is what normalises a *present but falsy*
        address.  Both halves are pinned so the fallback is visible.
        """
        built = DestinationIdentity.from_dict({"epoch": EPOCH_A})
        self.assertEqual(built.address, "")

    def test_or_at_196_a_falsy_address_becomes_the_empty_string(self):
        """`or@196`: the falsy-but-present address the ``or`` exists for.

        ``None`` and ``""`` are both falsy, so both are normalised to
        the empty string by the ``or``.  Under the mutant the ``None``
        is handed to ``_require_address``, which also returns ``""`` --
        so the *address* is masked -- but the ``or`` is what makes that
        true, and the empty-string case pins it directly.
        """
        built = DestinationIdentity.from_dict({"epoch": EPOCH_A, "address": None})
        self.assertEqual(built.address, "")
        built = DestinationIdentity.from_dict({"epoch": EPOCH_A, "address": ""})
        self.assertEqual(built.address, "")

    # --- and@200: is_proven --------------------------------------------
    def test_and_at_200_an_untruthful_epoch_is_not_proven(self):
        """`and@200`: the SECOND half -- the epoch is not truthy.

        The guard is ``bool(self.epoch and self.epoch.strip())``.
        Under the mutant (``and`` -> ``or``) the second operand is
        enough, so an epoch whose ``strip()`` is non-empty reads as
        proven even when the epoch itself is falsy.  A ``str``
        subclass that lies about its truth value is the only way to
        reach that state: the plain ``""`` is refused by the
        constructor, and a non-empty epoch is truthy.

        The identity is therefore *unproven* -- the constructor let it
        through only because ``"".strip()`` is non-empty, and the
        guard's second half is what notices the epoch is falsy.
        """
        class UntruthfulEpoch(str):
            """A str that is falsy but does not strip to nothing."""

            def __bool__(self) -> bool:
                return False

        identity = DestinationIdentity(epoch=UntruthfulEpoch(EPOCH_A))
        self.assertFalse(identity.is_proven())

    def test_and_at_200_a_present_epoch_is_proven(self):
        # The control: a real epoch is proven.
        self.assertTrue(DestinationIdentity(epoch=EPOCH_A).is_proven())

    # --- or@220: bind_key's operation_key -----------------------------
    def test_or_at_220_a_non_string_operation_key_is_refused(self):
        """`or@220`: the WRONG-TYPE half.

        The guard is ``not isinstance(operation_key, str) or not
        operation_key``.  Under the mutant (``or`` -> ``and``) it fires
        only when the key is both a non-str *and* falsy -- so a
        non-empty non-string key slips past and is silently hashed into
        the bound digest.  The refusal is the discriminator.
        """
        with self.assertRaises(ValueError):
            bind_key(123, self.a, {"x": 1})

    def test_or_at_220_an_empty_operation_key_is_refused(self):
        """`or@220`: the EMPTY half."""
        with self.assertRaises(ValueError):
            bind_key("", self.a, {"x": 1})

    # --- or@263: classify_replay's fingerprint guard -------------------
    def test_or_at_263_a_non_string_fingerprint_is_refused(self):
        """`or@263`: the WRONG-TYPE half.

        The guard is ``not isinstance(value, str) or not value``.  Under
        the mutant (``or`` -> ``and``) a non-empty non-string
        fingerprint slips past and is compared with ``==`` against the
        other fingerprint -- a non-string compares unequal, so the
        replay would be reported as ``CONFLICT`` instead of being
        refused.  The refusal is the discriminator.
        """
        with self.assertRaises(ValueError):
            classify_replay(self.a, self.a, 123, FP_X)
        with self.assertRaises(ValueError):
            classify_replay(self.a, self.a, FP_X, 123)

    def test_or_at_263_an_empty_fingerprint_is_refused(self):
        """`or@263`: the EMPTY half."""
        with self.assertRaises(ValueError):
            classify_replay(self.a, self.a, "", FP_X)
        with self.assertRaises(ValueError):
            classify_replay(self.a, self.a, FP_X, "")

    # --- or@284: prove_at_effect's attestation guard ------------------
    def test_or_at_284_a_none_attestation_is_refused(self):
        """`or@284`: the ABSENT half -- the destination attested nothing."""
        with self.assertRaises(UnprovenIdentityError) as caught:
            prove_at_effect(self.a, None)
        self.assertIn("attested no epoch", str(caught.exception))

    def test_or_at_284_a_non_string_attestation_is_refused(self):
        """`or@284`: the WRONG-TYPE half -- a non-str attestation.

        The guard is ``attested_epoch is None or not isinstance(
        attested_epoch, str) or not attested_epoch.strip()``.  Under the
        mutant (``or`` -> ``and``) the middle arm never fires, and the
        guard's third arm calls ``.strip()`` on the non-string -- the
        refusal turns into an ``AttributeError``, and the caller is no
        longer told *why* the identity is unproven.  The refusal is
        still a refusal, so the exception type is not the
        discriminator; the **exception type and message** are.
        """
        with self.assertRaises(UnprovenIdentityError) as caught:
            prove_at_effect(self.a, 123)
        self.assertIn("attested no epoch", str(caught.exception))

    def test_or_at_284_a_blank_attestation_is_refused(self):
        """`or@284`: the BLANK half -- a whitespace-only attestation."""
        with self.assertRaises(UnprovenIdentityError) as caught:
            prove_at_effect(self.a, "   ")
        self.assertIn("attested no epoch", str(caught.exception))

    # --- or@341 / or@345 / or@347 / or@349: record_acceptance ----------
    def test_or_at_341_a_non_string_operation_key_is_refused(self):
        """`or@341`: the WRONG-TYPE half of the ledger's key guard.

        Under the mutant (``or`` -> ``and``) a non-empty non-string key
        slips past and is recorded in the ledger under a key the caller
        can never look up with a string.
        """
        ledger = AcceptanceLedger()
        with self.assertRaises(ValueError):
            ledger.record_acceptance(123, self.a)

    def test_or_at_341_an_empty_operation_key_is_refused(self):
        """`or@341`: the EMPTY half of the ledger's key guard."""
        ledger = AcceptanceLedger()
        with self.assertRaises(ValueError):
            ledger.record_acceptance("", self.a)

    def test_or_at_345_a_non_string_outcome_is_refused(self):
        """`or@345`: the WRONG-TYPE half of the outcome guard.

        Under the mutant (``or`` -> ``and``) a non-empty non-string
        outcome slips past and is recorded in the ledger -- the ledger
        would then hand a caller an outcome it cannot compare against
        ``ACCEPTED`` or ``OUTCOME_UNKNOWN``.
        """
        ledger = AcceptanceLedger()
        with self.assertRaises(ValueError):
            ledger.record_acceptance("op-1", self.a, outcome=123)

    def test_or_at_345_an_empty_outcome_is_refused(self):
        """`or@345`: the EMPTY half of the outcome guard."""
        ledger = AcceptanceLedger()
        with self.assertRaises(ValueError):
            ledger.record_acceptance("op-1", self.a, outcome="")

    def test_or_at_347_a_bound_digest_without_the_prefix_is_refused(self):
        """`or@347`: the WRONG-FORMAT half of the bound-digest guard.

        Under the mutant (``or`` -> ``and``) the guard fires only when
        the digest is both non-empty *and* missing the ``sha256:``
        prefix -- never -- so a malformed digest is recorded and the
        ledger hands a caller a digest that is not a digest.
        """
        ledger = AcceptanceLedger()
        with self.assertRaises(ValueError):
            ledger.record_acceptance("op-1", self.a, bound_digest="not-a-digest")

    def test_or_at_349_a_payload_fingerprint_without_the_prefix_is_refused(self):
        """`or@349`: the WRONG-FORMAT half of the fingerprint guard."""
        ledger = AcceptanceLedger()
        with self.assertRaises(ValueError):
            ledger.record_acceptance(
                "op-1", self.a, payload_fingerprint="not-a-fingerprint"
            )

    def test_or_at_347_and_349_the_prefixed_forms_are_accepted(self):
        # The control: the prefixed forms must still be accepted.
        ledger = AcceptanceLedger()
        acceptance = ledger.record_acceptance(
            "op-1",
            self.a,
            bound_digest=bind_key("op-1", self.a, {"x": 1}),
            payload_fingerprint=payload_fingerprint({"x": 1}),
        )
        self.assertTrue(acceptance.bound_digest.startswith("sha256:"))
        self.assertTrue(acceptance.payload_fingerprint.startswith("sha256:"))

    # --- or@374 / or@396 / or@402: the ledger's key guards -------------
    def test_or_at_374_a_non_string_operation_key_is_refused(self):
        """`or@374`: the WRONG-TYPE half of ``record_pending``'s guard."""
        ledger = AcceptanceLedger()
        with self.assertRaises(ValueError):
            ledger.record_pending(123, self.a)

    def test_or_at_374_an_empty_operation_key_is_refused(self):
        """`or@374`: the EMPTY half of ``record_pending``'s guard."""
        ledger = AcceptanceLedger()
        with self.assertRaises(ValueError):
            ledger.record_pending("", self.a)

    def test_or_at_396_a_non_string_operation_key_is_refused(self):
        """`or@396`: the WRONG-TYPE half of ``accepted_by``'s guard."""
        ledger = AcceptanceLedger()
        with self.assertRaises(ValueError):
            ledger.accepted_by(123)

    def test_or_at_396_an_empty_operation_key_is_refused(self):
        """`or@396`: the EMPTY half of ``accepted_by``'s guard."""
        ledger = AcceptanceLedger()
        with self.assertRaises(ValueError):
            ledger.accepted_by("")

    def test_or_at_402_a_non_string_operation_key_is_refused(self):
        """`or@402`: the WRONG-TYPE half of ``pending_at``'s guard."""
        ledger = AcceptanceLedger()
        with self.assertRaises(ValueError):
            ledger.pending_at(123)

    def test_or_at_402_an_empty_operation_key_is_refused(self):
        """`or@402`: the EMPTY half of ``pending_at``'s guard."""
        ledger = AcceptanceLedger()
        with self.assertRaises(ValueError):
            ledger.pending_at("")

    def test_the_ledger_guards_reject_the_same_ways_everywhere(self):
        """The key guard is one rule, applied in four places.

        ``operation_key`` must be a non-empty str and ``outcome`` must
        be a non-empty str.  Driving all four sites with all the wrong
        ways keeps the rule uniform -- a caller must not be able to get
        further at one site than at another.
        """
        ledger = AcceptanceLedger()
        for key in (123, "", None):
            with self.assertRaises(ValueError):
                ledger.record_acceptance(key, self.a)
            with self.assertRaises(ValueError):
                ledger.record_pending(key, self.a)
            with self.assertRaises(ValueError):
                ledger.accepted_by(key)
            with self.assertRaises(ValueError):
                ledger.pending_at(key)
        for outcome in (123, "", None):
            with self.assertRaises(ValueError):
                ledger.record_acceptance("op-1", self.a, outcome=outcome)


class MutantSelfCheckTests(unittest.TestCase):
    """The module's own ``main()`` self-check and its ``__main__`` guard.

    The self-check at the bottom of ``endpoint_identity.py`` is the
    module's only executable statement that the test suite did not
    reach, so every planted fault inside it survived.  It is a real
    part of the module -- ``python endpoint_identity.py`` runs it -- and
    it must be driven.

    The five ``assert`` lines are the module's summary of its own
    invariants: same state means same identity, the three replay
    verdicts, and the determinism of the bound key.  Each is driven
    here.

    ``eq@446`` is the ``__name__ == "__main__"`` guard.  Under the
    mutant (``==`` -> ``!=``) *importing* the module runs the
    self-check: the module prints its banner in the middle of somebody
    else's import.  A library module must be silent on import.
    """

    def test_the_self_check_passes(self):
        """The module's own self-check runs clean."""
        endpoint_identity.main()

    def test_the_self_check_covers_the_identity_invariant(self):
        """`eq@427`: the "same state, different address" invariant.

        Under the mutant (``==`` -> ``!=``) the self-check's own
        assertion about a re-pointed address fails, so the module's
        self-check raises ``AssertionError`` instead of confirming the
        invariant it exists to confirm.
        """
        a = DestinationIdentity(epoch=EPOCH_A, address="https://a.example")
        a_again = DestinationIdentity(epoch=EPOCH_A, address="https://alias.example")
        self.assertEqual(a, a_again)

    def test_the_self_check_covers_the_three_replay_verdicts(self):
        """`eq@428`, `eq@429`, `eq@430`: the three replay verdicts.

        Under each mutant the corresponding assertion in the self-check
        fails, so the self-check raises ``AssertionError`` instead of
        confirming the verdict it exists to confirm.
        """
        a = DestinationIdentity(epoch=EPOCH_A, address="https://a.example")
        b = DestinationIdentity(epoch=EPOCH_B, address="https://b.example")
        self.assertEqual(classify_replay(a, a, FP_X, FP_X), REPLAY)
        self.assertEqual(classify_replay(a, a, FP_X, FP_Y), CONFLICT)
        self.assertEqual(classify_replay(a, b, FP_X, FP_X), NEW_DESTINATION)

    def test_the_self_check_covers_the_bound_key_determinism(self):
        """`eq@431`: the bound key is deterministic.

        Under the mutant (``==`` -> ``!=``) the self-check's assertion
        that the same operation bound twice gives the same digest
        fails.
        """
        a = DestinationIdentity(epoch=EPOCH_A, address="https://a.example")
        self.assertEqual(bind_key("op-1", a, {"x": 1}), bind_key("op-1", a, {"x": 1}))

    def test_importing_the_module_is_silent(self):
        """`eq@446`: the ``__name__ == "__main__"`` guard.

        Under the mutant (``==`` -> ``!=``) importing the module runs
        the self-check and prints the banner.  A library module must be
        silent on import, or every caller that imports it inherits a
        stray line on stdout.
        """
        import subprocess

        component = Path(__file__).resolve().parents[1]
        result = subprocess.run(
            [sys.executable, "-c", "import endpoint_identity"],
            cwd=str(component),
            env={
                **os.environ,
                "PYTHONPATH": str(component),
                "PYTHONDONTWRITEBYTECODE": "1",
            },
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")
