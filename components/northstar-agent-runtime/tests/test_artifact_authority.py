"""Tests for artifact_authority: the artifact carries the authority it was granted.

The rules under test:

* the receipt travels with the bytes -- a sealed artifact carries the
  grant that permitted it, the epoch it was read at, and the seq it was
  permitted at;
* the receipt's text is **past tense** -- "permitted at T" and "check the
  list for now" -- and never claims present-tense authorization;
* an unnamed grant is refused and **nothing lands**;
* the epoch's clock must not be the issuer's own clock;
* the epoch is bound to the **grant**, not to a grant id string: a grant
  that was re-issued (its counter advanced) makes an old receipt stale;
* the tombstone check is a **read-time** check: a cancellation declared
  after the seal still catches the receipt;
* a STALE or REVOKED receipt never silently becomes VALID again.
"""

from __future__ import annotations

import contextlib
import sys
import unittest
from unittest import mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import artifact_authority
from artifact_authority import (
    CHECK_THE_LIST_FOR_NOW,
    FORBIDDEN_NOW_TENSE,
    SCHEMA_PIN,
    STALE,
    REVOKED,
    UNBOUND,
    UNNAMED,
    VALID,
    ArtifactAuthorityError,
    ArtifactReceipt,
    ArtifactAuthorityLedger,
    ClockNotIndependentError,
    MalformedReceiptError,
    PresentTenseClaimError,
    UnnamedGrantError,
    bind,
    open_sealed,
    seal_bytes,
    stdlib_only,
    verify,
)
from cancellation_tombstone import Tombstone, TombstoneSet
from grant_pin_ledger import OUTCOME_UNKNOWN, GrantPin, resolve_seal_outcome


def _pin(grant_id: str = "grant-1", version: str = "v2", counter: int = 7) -> GrantPin:
    return GrantPin(grant_id=grant_id, version=version, counter=counter)


def _bind(payload: bytes = b"artifact-bytes", **kwargs):
    args = dict(
        permitted_at_seq=3,
        epoch=3,
        clock_id="host-clock",
        issuer_id="issuer-a",
    )
    args.update(kwargs)
    return bind(payload, _pin(), **args)


class ReceiptTextTests(unittest.TestCase):
    """The receipt's own text: past tense, and round-trippable."""

    def test_receipt_render_is_past_tense_and_points_at_the_list(self):
        receipt = _bind()
        text = receipt.render()
        self.assertIn("permitted at 3", text)
        self.assertIn(CHECK_THE_LIST_FOR_NOW, text)
        self.assertTrue(text.endswith(CHECK_THE_LIST_FOR_NOW))

    def test_receipt_text_contains_no_present_tense_authorization_claim(self):
        text = _bind().render().lower()
        for token in FORBIDDEN_NOW_TENSE:
            self.assertNotIn(token, text, f"the receipt claims {token!r}")

    def test_receipt_render_parse_round_trips(self):
        receipt = _bind()
        parsed = ArtifactReceipt.parse(receipt.render())
        self.assertEqual(parsed, receipt)
        self.assertEqual(parsed.grant.to_dict(), receipt.grant.to_dict())
        self.assertEqual(parsed.permitted_at, 3)
        self.assertEqual(parsed.revocation_epoch, 3)
        self.assertEqual(parsed.clock_id, "host-clock")
        self.assertEqual(parsed.issuer_id, "issuer-a")
        self.assertEqual(parsed.artifact_digest, receipt.artifact_digest)

    def test_receipt_digest_is_a_sha256_pin_of_the_artifact_bytes(self):
        payload = b"artifact-bytes"
        receipt = _bind(payload)
        self.assertTrue(receipt.artifact_digest.startswith("sha256:"))
        self.assertTrue(receipt.is_bound_to(payload))
        self.assertFalse(receipt.is_bound_to(b"other-bytes"))

    def test_a_receipt_that_claims_present_tense_authorization_is_refused(self):
        text = _bind().render()
        tampered = text.replace("check the list for now", "valid")
        with self.assertRaises(PresentTenseClaimError):
            ArtifactReceipt.parse(tampered)

    def test_an_identifier_containing_a_word_is_not_mistaken_for_a_claim(self):
        # The refusal matches on word boundaries: "validation-clock" is an
        # identifier, not a present-tense authorization claim.
        receipt = _bind(clock_id="validation-clock")
        self.assertIn("clock=validation-clock", receipt.render())
        self.assertEqual(ArtifactReceipt.parse(receipt.render()), receipt)

    def test_receipt_parse_refuses_a_text_without_the_check_clause(self):
        text = _bind().render()
        with self.assertRaises(MalformedReceiptError):
            ArtifactReceipt.parse(text.replace(CHECK_THE_LIST_FOR_NOW, "gone"))


class BindRuleTests(unittest.TestCase):
    """The rules bind applies: unnamed grant, foreign clock, verbatim pin."""

    def test_unnamed_grant_is_refused_and_nothing_lands(self):
        ledger = ArtifactAuthorityLedger()
        with self.assertRaises(UnnamedGrantError):
            ledger.bind_and_seal(
                b"artifact-bytes",
                GrantPin("", "v1", 3),
                permitted_at_seq=3,
                epoch=3,
                clock_id="host-clock",
                issuer_id="issuer-a",
            )
        self.assertEqual(len(ledger), 0)
        self.assertEqual(ledger.artifacts, ())

    def test_clock_must_not_be_the_issuers_own_clock(self):
        with self.assertRaises(ClockNotIndependentError):
            _bind(clock_id="issuer-a", issuer_id="issuer-a")
        ledger = ArtifactAuthorityLedger()
        with self.assertRaises(ClockNotIndependentError):
            ledger.bind_and_seal(
                b"artifact-bytes",
                _pin(),
                permitted_at_seq=3,
                epoch=3,
                clock_id="issuer-a",
                issuer_id="issuer-a",
            )
        self.assertEqual(len(ledger), 0)

    def test_unresolved_pin_is_carried_verbatim_nulls_included(self):
        pin = GrantPin("grant-9", "v1", None)
        # This pin is exactly the one the seal layer records as
        # outcome_unknown: the grant is named but not resolvable.
        self.assertEqual(resolve_seal_outcome(pin, "executed"), OUTCOME_UNKNOWN)
        receipt = bind(
            b"artifact-bytes",
            pin,
            permitted_at_seq=3,
            epoch=3,
            clock_id="host-clock",
            issuer_id="issuer-a",
        )
        self.assertIsNone(receipt.grant.counter)
        self.assertEqual(receipt.grant.version, "v1")
        # The null survives the round trip: the receipt never rewrites the
        # pin to hide the absence.
        parsed = ArtifactReceipt.parse(receipt.render())
        self.assertIsNone(parsed.grant.counter)
        self.assertEqual(parsed.grant.to_dict(), receipt.grant.to_dict())
        self.assertIn("counter=null", receipt.render())

    def test_bind_refuses_a_non_bytes_artifact(self):
        with self.assertRaises(ArtifactAuthorityError):
            bind("not-bytes", _pin(), 3, 3, "host-clock", "issuer-a")

    def test_module_is_stdlib_only(self):
        self.assertTrue(stdlib_only())


class VerifyTests(unittest.TestCase):
    """The read-time check: epoch, tombstone, bytes, counter."""

    def test_a_fresh_receipt_at_its_own_epoch_is_valid(self):
        receipt = _bind()
        verdict = verify(receipt, epoch_now=3, tombstone_set=None)
        self.assertEqual(verdict.state, VALID)
        self.assertTrue(verdict.is_valid)

    def test_epoch_advance_makes_the_receipt_stale(self):
        receipt = _bind(epoch=3)
        verdict = verify(receipt, epoch_now=4, tombstone_set=None)
        self.assertEqual(verdict.state, STALE)
        self.assertNotEqual(verdict.state, VALID)

    def test_tombstone_is_checked_at_read_time_not_only_at_seal_time(self):
        receipt = _bind()
        # The tombstone set is empty at seal time: the seal saw nothing.
        empty = TombstoneSet()
        self.assertEqual(verify(receipt, 3, empty).state, VALID)
        # A cancellation is declared afterwards -- the read-time check
        # must still catch it.
        live = TombstoneSet(
            [Tombstone(grant_id="grant-1", action="dispatch", declarer="operator",
                       declarer_channel="chat")]
        )
        verdict = verify(receipt, 3, live)
        self.assertEqual(verdict.state, REVOKED)
        self.assertNotEqual(verdict.state, VALID)

    def test_tombstone_for_another_action_does_not_revoke(self):
        receipt = _bind()
        other = TombstoneSet(
            [Tombstone(grant_id="grant-1", action="publish", declarer="operator",
                       declarer_channel="chat")]
        )
        self.assertEqual(verify(receipt, 3, other).state, VALID)

    def test_changed_bytes_make_the_receipt_unbound(self):
        payload = b"artifact-bytes"
        receipt = _bind(payload)
        verdict = verify(receipt, 3, None, artifact_bytes=b"artifact-byteS")
        self.assertEqual(verdict.state, UNBOUND)
        self.assertNotEqual(verdict.state, VALID)

    def test_a_grant_whose_counter_advanced_makes_the_old_receipt_stale(self):
        receipt = _bind()
        self.assertEqual(verify(receipt, 3, None).state, VALID)
        # The epoch has not moved -- but the grant was re-issued: the epoch
        # is bound to the grant, not to the grant id string.
        reissued = GrantPin("grant-1", "v2", 8)
        verdict = verify(receipt, 3, None, current_grant=reissued)
        self.assertEqual(verdict.state, STALE)

    def test_the_ledger_verify_consults_the_current_grant(self):
        ledger = ArtifactAuthorityLedger()
        ledger.bind_and_seal(
            b"artifact-bytes",
            _pin(counter=5),
            permitted_at_seq=3,
            epoch=3,
            clock_id="host-clock",
            issuer_id="issuer-a",
        )
        self.assertEqual(ledger.verify(1, epoch_now=3).state, VALID)
        # A re-issued grant makes the sealed artifact stale even though
        # the epoch has not moved.
        verdict = ledger.verify(
            1, epoch_now=3, current_grant=GrantPin("grant-1", "v2", 6)
        )
        self.assertEqual(verdict.state, STALE)

    def test_an_unnamed_receipt_verifies_as_unnamed(self):
        # bind() refuses an unnamed grant, so the receipt is built
        # directly here: an unnamed receipt must never verify as valid.
        receipt = ArtifactReceipt(
            artifact_digest="sha256:" + "0" * 64,
            grant=GrantPin("", "v1", 3),
            permitted_at=3,
            revocation_epoch=3,
            clock_id="host-clock",
            issuer_id="issuer-a",
        )
        self.assertEqual(verify(receipt, 3, None).state, UNNAMED)

    def test_stale_and_revoked_never_silently_become_valid_again(self):
        receipt = _bind(epoch=3)
        stale = verify(receipt, epoch_now=4, tombstone_set=None)
        self.assertEqual(stale.state, STALE)
        # Reading again at the same epoch still says STALE: the verdict
        # is derived from the receipt and the present, never cached as a
        # past "valid".
        self.assertEqual(verify(receipt, epoch_now=4, tombstone_set=None).state, STALE)
        revoked = verify(
            receipt,
            epoch_now=4,
            tombstone_set=TombstoneSet(
                [Tombstone(grant_id="grant-1", action="dispatch", declarer="operator",
                           declarer_channel="chat")]
            ),
        )
        self.assertEqual(revoked.state, REVOKED)
        self.assertEqual(
            verify(
                receipt,
                epoch_now=4,
                tombstone_set=TombstoneSet(
                    [Tombstone(grant_id="grant-1", action="dispatch", declarer="operator",
                               declarer_channel="chat")]
                ),
            ).state,
            REVOKED,
        )

    def test_epoch_monotonicity_is_a_caller_precondition_not_a_guarantee(self):
        # The module does NOT enforce that the epoch only moves forward:
        # epoch_now is caller-supplied. A caller that hands back a lower
        # epoch gets VALID, and that is the caller's error. The design
        # doc states this as a precondition; this test pins the actual
        # behaviour so the doc cannot drift away from the code.
        receipt = _bind(epoch=3)
        self.assertEqual(verify(receipt, epoch_now=3).state, VALID)
        self.assertEqual(verify(receipt, epoch_now=2).state, VALID)
        # The tombstone check does not depend on the epoch at all.
        live = TombstoneSet(
            [Tombstone(grant_id="grant-1", action="dispatch", declarer="operator",
                       declarer_channel="chat")]
        )
        self.assertEqual(verify(receipt, epoch_now=2, tombstone_set=live).state, REVOKED)


class DrivenPathTests(unittest.TestCase):
    """One real path, driven end to end.

    Seal bytes under a named grant at epoch 3 -> read the receipt back
    (VALID) -> revoke (the epoch advances, and a tombstone names the
    action) -> read again (STALE / REVOKED) -> change one byte and read
    again (UNBOUND).
    """

    def test_seal_then_revoke_then_tamper_is_driven_end_to_end(self):
        ledger = ArtifactAuthorityLedger()
        payload = b"the artifact that was permitted"

        # 1. Seal: a named grant, a foreign clock, epoch 3.
        artifact = ledger.bind_and_seal(
            payload,
            GrantPin("grant-42", "v1", 5),
            permitted_at_seq=11,
            epoch=3,
            clock_id="host-clock",
            issuer_id="issuer-a",
            action="publish",
            subject="post-7",
        )
        self.assertEqual(len(ledger), 1)

        # 2. The receipt travels with the bytes: a reader who has only the
        #    container still sees what permitted it and when.
        opened_payload, receipt = open_sealed(artifact.container)
        self.assertEqual(opened_payload, payload)
        self.assertEqual(receipt.grant.grant_id, "grant-42")
        self.assertIn("permitted at 11", receipt.render())
        self.assertIn(CHECK_THE_LIST_FOR_NOW, receipt.render())

        # 3. Read it back at the epoch it was sealed under: VALID.
        self.assertEqual(ledger.verify(1, epoch_now=3).state, VALID)

        # 4a. Revoke by advancing the epoch: the receipt goes STALE.
        self.assertEqual(ledger.verify(1, epoch_now=4).state, STALE)

        # 4b. Revoke by naming the action in a tombstone: READ-TIME, so it
        #     catches the receipt that was sealed before the cancellation.
        tombstones = TombstoneSet(
            [Tombstone(grant_id="grant-42", action="publish", subject="post-7",
                       declarer="operator", declarer_channel="chat")]
        )
        self.assertEqual(ledger.verify(1, epoch_now=3, tombstone_set=tombstones).state,
                         REVOKED)

        # 5. Tamper one byte: the artifact no longer matches its receipt.
        tampered = bytearray(artifact.container)
        tampered[-1] = tampered[-1] ^ 0x01
        with self.assertRaises(MalformedReceiptError):
            open_sealed(bytes(tampered))
        # ... and the UNBOUND verdict is driven off the tampered container
        # itself, not off a separately typed payload: the payload the
        # container carries is what the receipt no longer describes.
        tampered_payload = bytes(tampered)[len(bytes(tampered)) - len(payload):]
        verdict = verify(receipt, 3, None, artifact_bytes=tampered_payload)
        self.assertEqual(verdict.state, UNBOUND)
        self.assertNotEqual(verdict.state, VALID)

    def test_sealing_bytes_with_a_foreign_receipt_is_refused(self):
        receipt = _bind(b"artifact-bytes")
        with self.assertRaises(MalformedReceiptError):
            seal_bytes(b"other-bytes", receipt)

    def test_opening_a_container_that_is_not_one_is_refused(self):
        with self.assertRaises(MalformedReceiptError):
            open_sealed(b"not-a-container")

    def test_the_ledger_refuses_an_unknown_seq(self):
        ledger = ArtifactAuthorityLedger()
        with self.assertRaises(ArtifactAuthorityError):
            ledger.verify(1, epoch_now=3)

    def test_the_receipt_dict_carries_the_pin_verbatim(self):
        receipt = bind(
            b"artifact-bytes",
            GrantPin("grant-9", "v1", None),
            permitted_at_seq=3,
            epoch=3,
            clock_id="host-clock",
            issuer_id="issuer-a",
        )
        data = receipt.to_dict()
        self.assertEqual(data["schema_version"], SCHEMA_PIN)
        self.assertEqual(
            data["grant"], {"grant_id": "grant-9", "version": "v1", "counter": None}
        )

    def test_is_superseded_by_reports_a_re_issued_grant(self):
        old = _bind()
        newer = bind(
            b"artifact-bytes",
            _pin(counter=8),
            permitted_at_seq=4,
            epoch=4,
            clock_id="host-clock",
            issuer_id="issuer-a",
        )
        self.assertTrue(old.is_superseded_by(newer))
        self.assertFalse(newer.is_superseded_by(old))
        # A different grant is not a supersession of this one.
        other = bind(
            b"artifact-bytes",
            _pin(grant_id="grant-2", counter=9),
            permitted_at_seq=4,
            epoch=4,
            clock_id="host-clock",
            issuer_id="issuer-a",
        )
        self.assertFalse(old.is_superseded_by(other))

    def test_the_sealed_artifact_opens_to_its_own_bytes(self):
        ledger = ArtifactAuthorityLedger()
        payload = b"the artifact that was permitted"
        artifact = ledger.bind_and_seal(
            payload,
            _pin(),
            permitted_at_seq=3,
            epoch=3,
            clock_id="host-clock",
            issuer_id="issuer-a",
        )
        self.assertEqual(artifact.open(), payload)
        self.assertIs(ledger.artifact(1), artifact)

    def test_the_verdict_dict_carries_its_state_and_reason(self):
        receipt = _bind()
        verdict = verify(receipt, epoch_now=3, tombstone_set=None)
        data = verdict.to_dict()
        self.assertEqual(data["state"], VALID)
        self.assertTrue(data["reason"])
        stale = verify(receipt, epoch_now=4, tombstone_set=None)
        self.assertEqual(stale.to_dict()["state"], STALE)


@contextlib.contextmanager
def _ledger_not_in_sys_modules():
    """Run with ``grant_pin_ledger`` absent from ``sys.modules``.

    ``_load_grant_pin_ledger`` short-circuits on a cached module, so the
    loader path can only be reached when the cache entry is removed.
    """
    saved = sys.modules.pop("grant_pin_ledger", None)
    try:
        yield
    finally:
        sys.modules.pop("grant_pin_ledger", None)
        if saved is not None:
            sys.modules["grant_pin_ledger"] = saved


class MutantOrAt150LoaderTests(unittest.TestCase):
    """Kills the ``or@150`` mutant in ``_load_grant_pin_ledger``.

    The guard is ``if spec is None or spec.loader is None:``.  Mutating
    ``or`` to ``and`` makes the guard fire only when *both* halves are
    ``None``, so a ``None`` spec or a loader-less spec slips past the
    ``ImportError`` and fails later (or loads a broken spec).
    """

    def test_or150_a_none_spec_is_refused_with_an_import_error(self):
        with _ledger_not_in_sys_modules():
            with mock.patch.object(
                artifact_authority.importlib.util,
                "spec_from_file_location",
                return_value=None,
            ):
                with self.assertRaises(ImportError):
                    artifact_authority._load_grant_pin_ledger()

    def test_or150_a_spec_without_a_loader_is_refused_with_an_import_error(self):
        spec = mock.MagicMock()
        spec.loader = None
        with _ledger_not_in_sys_modules():
            with mock.patch.object(
                artifact_authority.importlib.util,
                "spec_from_file_location",
                return_value=spec,
            ):
                with self.assertRaises(ImportError):
                    artifact_authority._load_grant_pin_ledger()

    def test_or150_a_loadable_spec_still_loads_the_module(self):
        """Control for the two cases above: the happy path must survive."""
        with _ledger_not_in_sys_modules():
            module = artifact_authority._load_grant_pin_ledger()
        self.assertTrue(hasattr(module, "GrantPin"))
        self.assertTrue(hasattr(module, "resolve_seal_outcome"))


class MutantOrAt184RequireTextTests(unittest.TestCase):
    """Kills the ``or@184`` mutant in ``_require_text``.

    The guard is ``if not isinstance(value, str) or not value.strip():``.
    Mutating ``or`` to ``and`` lets an empty (or whitespace-only) string
    through, and turns a non-string into an ``AttributeError`` instead of
    the module's own ``ArtifactAuthorityError``.
    """

    def test_or184_an_empty_string_is_refused(self):
        with self.assertRaises(ArtifactAuthorityError):
            artifact_authority._require_text("", "grant_id")

    def test_or184_a_whitespace_only_string_is_refused(self):
        with self.assertRaises(ArtifactAuthorityError):
            artifact_authority._require_text("   ", "grant_id")

    def test_or184_a_non_string_is_refused_with_the_module_error(self):
        for bad in (123, None, ["x"]):
            with self.subTest(value=bad):
                with self.assertRaises(ArtifactAuthorityError):
                    artifact_authority._require_text(bad, "grant_id")


class MutantGtAt186RequireTextTests(unittest.TestCase):
    """Kills the ``gt@186`` mutant in ``_require_text``.

    The guard is ``if len(value) > limit:`` with ``limit`` defaulting to
    ``_MAX_ID_CHARS`` (256).  Mutating ``>`` to ``>=`` rejects a value of
    exactly the limit, which the rule allows.
    """

    def test_gt186_a_value_of_exactly_the_limit_is_accepted(self):
        value = "a" * artifact_authority._MAX_ID_CHARS
        self.assertEqual(artifact_authority._require_text(value, "grant_id"), value)

    def test_gt186_a_value_one_over_the_limit_is_refused(self):
        value = "a" * (artifact_authority._MAX_ID_CHARS + 1)
        with self.assertRaises(ArtifactAuthorityError):
            artifact_authority._require_text(value, "grant_id")

    def test_gt186_a_value_one_under_the_limit_is_accepted(self):
        value = "a" * (artifact_authority._MAX_ID_CHARS - 1)
        self.assertEqual(artifact_authority._require_text(value, "grant_id"), value)




