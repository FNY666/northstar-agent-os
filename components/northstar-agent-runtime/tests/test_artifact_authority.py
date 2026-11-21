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
import io
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


class MutantOrAt188SeparatorTests(unittest.TestCase):
    """Kills the ``or@188`` mutant in ``_require_text``.

    The guard is ``if ";" in value or "\\n" in value:`` -- the receipt
    format uses ``;`` and newline as its field separators, so a text
    field that carries either would break the receipt's own grammar.
    Mutating ``or`` to ``and`` makes the guard fire only when *both*
    separators are present, so a field carrying exactly one of them is
    accepted and the receipt it produces cannot be parsed back.
    """

    def test_or188_a_field_carrying_the_semicolon_is_refused(self):
        with self.assertRaises(ArtifactAuthorityError):
            artifact_authority._require_text("a;b", "grant_id")

    def test_or188_a_field_carrying_the_newline_is_refused(self):
        with self.assertRaises(ArtifactAuthorityError):
            artifact_authority._require_text("a\nb", "grant_id")

    def test_or188_a_field_carrying_both_separators_is_refused(self):
        # The control: the case the mutant still catches, so the fix
        # cannot be "refuse only the both-at-once case".
        with self.assertRaises(ArtifactAuthorityError):
            artifact_authority._require_text("a;b\nc", "grant_id")

    def test_or188_a_field_carrying_neither_separator_is_accepted(self):
        value = "a;b".replace(";", ",")
        self.assertEqual(artifact_authority._require_text(value, "grant_id"), value)


class MutantOrAt197RequireSeqTests(unittest.TestCase):
    """Kills the ``or@197`` mutant in ``_require_seq``.

    The guard is ``if isinstance(value, bool) or not isinstance(value, int):``.
    ``bool`` IS a subclass of ``int`` in Python, so the *explicit* bool
    half is the only half that refuses a boolean -- the "not an int"
    half never refuses one.  Mutating ``or`` to ``and`` lets a boolean
    through as the integer 0 or 1, and a boolean seq is exactly what the
    guard exists to refuse.
    """

    def test_or197_a_boolean_seq_is_refused(self):
        for value in (True, False):
            with self.subTest(value=value):
                with self.assertRaises(ArtifactAuthorityError):
                    artifact_authority._require_seq(value, "permitted_at")

    def test_or197_a_non_integer_seq_is_refused(self):
        # The other half, as the control.
        for value in ("3", 3.0, None):
            with self.subTest(value=value):
                with self.assertRaises(ArtifactAuthorityError):
                    artifact_authority._require_seq(value, "permitted_at")

    def test_or197_a_real_integer_seq_is_accepted(self):
        self.assertEqual(artifact_authority._require_seq(3, "permitted_at"), 3)


class MutantLtAt199RequireSeqTests(unittest.TestCase):
    """Kills the ``lt@199`` mutant in ``_require_seq``.

    The guard is ``if value < 0:`` -- a seq is a *non-negative* integer.
    Mutating ``<`` to ``<=`` refuses a seq of exactly zero, which the
    rule allows: zero is a legal seq (the first ledger position).
    """

    def test_lt199_a_seq_of_exactly_zero_is_accepted(self):
        self.assertEqual(artifact_authority._require_seq(0, "permitted_at"), 0)

    def test_lt199_a_negative_seq_is_refused(self):
        with self.assertRaises(ArtifactAuthorityError):
            artifact_authority._require_seq(-1, "permitted_at")

    def test_lt199_a_seq_of_one_is_accepted(self):
        self.assertEqual(artifact_authority._require_seq(1, "permitted_at"), 1)


class MutantOrAt272DigestTests(unittest.TestCase):
    """Kills the ``or@272`` mutant in ``ArtifactReceipt.__post_init__``.

    The guard is ``if not isinstance(self.artifact_digest, str) or not
    self.artifact_digest.startswith("sha256:"):`` -- the digest must be
    a string *and* a ``sha256:`` pin.  Mutating ``or`` to ``and`` refuses
    only a value that fails both halves at once, so a non-string digest
    (which then raises ``AttributeError`` on ``.startswith``) or a string
    that is not a ``sha256:`` pin slips through.
    """

    def _receipt(self, digest):
        return ArtifactReceipt(
            artifact_digest=digest,
            grant=GrantPin("grant-1", "v2", 7),
            permitted_at=3,
            revocation_epoch=3,
            clock_id="host-clock",
            issuer_id="issuer-a",
        )

    def test_or272_a_digest_that_is_not_a_sha256_pin_is_refused(self):
        with self.assertRaises(MalformedReceiptError):
            self._receipt("md5:" + "0" * 32)

    def test_or272_a_non_string_digest_is_refused(self):
        with self.assertRaises(MalformedReceiptError):
            self._receipt(None)

    def test_or272_a_digest_that_is_both_not_a_string_and_not_a_pin_is_refused(self):
        # The control: the case the mutant still catches.
        with self.assertRaises(MalformedReceiptError):
            self._receipt(123)

    def test_or272_a_sha256_pin_is_accepted(self):
        receipt = self._receipt("sha256:" + "0" * 64)
        self.assertTrue(receipt.artifact_digest.startswith("sha256:"))


class MutantOrAt323ParseTests(unittest.TestCase):
    """Kills the ``or@323`` mutant in ``ArtifactReceipt.parse``.

    The guard is ``if not isinstance(rendered, str) or not rendered:`` --
    a rendered receipt must be a string *and* non-empty.  Mutating
    ``or`` to ``and`` refuses only a value that fails both halves at
    once, so a non-string reaches ``rendered.split(";")`` (an
    ``AttributeError``, not the module's own refusal) and the empty
    string reaches the field-count check with a different message.
    """

    def test_or323_a_non_string_is_refused(self):
        for value in (123, None, ["receipt"]):
            with self.subTest(value=value):
                with self.assertRaises(MalformedReceiptError):
                    ArtifactReceipt.parse(value)

    def test_or323_the_empty_string_is_refused(self):
        with self.assertRaises(MalformedReceiptError):
            ArtifactReceipt.parse("")

    def test_or323_a_non_string_that_is_also_empty_is_refused(self):
        # The control: the case the mutant still catches.
        with self.assertRaises(MalformedReceiptError):
            ArtifactReceipt.parse(None)

    def test_or323_a_well_formed_receipt_still_parses(self):
        receipt = _bind()
        self.assertEqual(ArtifactReceipt.parse(receipt.render()), receipt)


class MutantRetFAt393IsBoundToTests(unittest.TestCase):
    """Kills the ``retF@393`` mutant in ``ArtifactReceipt.is_bound_to``.

    The method returns ``False`` for a value that is not bytes -- the
    bytes are simply not the ones the receipt was written for.  Mutating
    ``return False`` to ``return True`` says the opposite: a receipt
    would claim to describe a payload that is not bytes at all.
    """

    def test_retF393_a_non_bytes_value_is_not_bound(self):
        receipt = _bind(b"artifact-bytes")
        for value in ("artifact-bytes", None, 123, ["artifact-bytes"]):
            with self.subTest(value=value):
                self.assertIs(receipt.is_bound_to(value), False)

    def test_retF393_the_real_bytes_are_bound(self):
        receipt = _bind(b"artifact-bytes")
        self.assertIs(receipt.is_bound_to(b"artifact-bytes"), True)
        self.assertIs(receipt.is_bound_to(bytearray(b"artifact-bytes")), True)

    def test_retF393_other_bytes_are_not_bound(self):
        # The control: the case the mutant still catches.
        receipt = _bind(b"artifact-bytes")
        self.assertIs(receipt.is_bound_to(b"other-bytes"), False)


class MutantSupersessionTests(unittest.TestCase):
    """Kills the ``or@408``, ``gt@409`` and ``gt@410`` mutants.

    ``is_superseded_by`` has two arms:

    * ``or@408`` -- ``if self.grant.counter is None or
      other.grant.counter is None:`` -- when either pin is unresolved
      the comparison falls back to the *epoch*.  Mutating ``or`` to
      ``and`` fires the fallback only when *both* counters are null, so
      a receipt whose own counter is null and whose counterpart's is
      not falls through to the counter comparison and answers wrongly.
    * ``gt@409`` -- ``other.revocation_epoch > self.revocation_epoch`` --
      mutating ``>`` to ``>=`` makes a *later* state at the *same* epoch
      look like a supersession.
    * ``gt@410`` -- ``other.grant.counter > self.grant.counter`` --
      mutating ``>`` to ``>=`` makes two states at the *same* counter
      look like a supersession.
    """

    def test_or408_an_unresolved_receipt_is_superseded_by_a_resolved_later_epoch(self):
        unresolved = bind(
            b"artifact-bytes", _pin(counter=None),
            permitted_at_seq=3, epoch=3, clock_id="host-clock", issuer_id="issuer-a",
        )
        later = bind(
            b"artifact-bytes", _pin(counter=None),
            permitted_at_seq=4, epoch=4, clock_id="host-clock", issuer_id="issuer-a",
        )
        self.assertTrue(unresolved.is_superseded_by(later))

    def test_or408_an_unresolved_receipt_is_not_superseded_at_the_same_epoch(self):
        # The boundary of the epoch arm: the two states share an epoch,
        # so neither supersedes the other.
        first = bind(
            b"artifact-bytes", _pin(counter=None),
            permitted_at_seq=3, epoch=3, clock_id="host-clock", issuer_id="issuer-a",
        )
        second = bind(
            b"artifact-bytes", _pin(counter=None),
            permitted_at_seq=3, epoch=3, clock_id="host-clock", issuer_id="issuer-a",
        )
        self.assertFalse(first.is_superseded_by(second))

    def test_or408_a_resolved_receipt_is_superseded_by_a_later_unresolved_epoch(self):
        # The other direction of the same guard: the *other* pin's
        # counter is the null one, so the epoch arm applies too.
        resolved = bind(
            b"artifact-bytes", _pin(counter=5),
            permitted_at_seq=3, epoch=3, clock_id="host-clock", issuer_id="issuer-a",
        )
        later = bind(
            b"artifact-bytes", _pin(counter=None),
            permitted_at_seq=4, epoch=4, clock_id="host-clock", issuer_id="issuer-a",
        )
        self.assertTrue(resolved.is_superseded_by(later))

    def test_gt409_two_states_at_the_same_epoch_do_not_supersede(self):
        # The epoch arm's boundary: equal epochs are not "later".
        first = bind(
            b"artifact-bytes", _pin(counter=None),
            permitted_at_seq=3, epoch=3, clock_id="host-clock", issuer_id="issuer-a",
        )
        second = bind(
            b"artifact-bytes", _pin(counter=None),
            permitted_at_seq=3, epoch=3, clock_id="host-clock", issuer_id="issuer-a",
        )
        self.assertFalse(first.is_superseded_by(second))

    def test_gt410_two_states_at_the_same_counter_do_not_supersede(self):
        # The counter arm's boundary: equal counters are not "later".
        first = bind(
            b"artifact-bytes", _pin(counter=5),
            permitted_at_seq=3, epoch=3, clock_id="host-clock", issuer_id="issuer-a",
        )
        second = bind(
            b"artifact-bytes", _pin(counter=5),
            permitted_at_seq=4, epoch=4, clock_id="host-clock", issuer_id="issuer-a",
        )
        self.assertFalse(first.is_superseded_by(second))

    def test_gt410_a_later_counter_supersedes(self):
        # The control: the case the mutant still catches.
        first = bind(
            b"artifact-bytes", _pin(counter=5),
            permitted_at_seq=3, epoch=3, clock_id="host-clock", issuer_id="issuer-a",
        )
        second = bind(
            b"artifact-bytes", _pin(counter=6),
            permitted_at_seq=4, epoch=4, clock_id="host-clock", issuer_id="issuer-a",
        )
        self.assertTrue(first.is_superseded_by(second))


class MutantOrAt474BindSubjectTests(unittest.TestCase):
    """Kills the ``or@474`` mutant in ``bind``.

    The subject is carried through as ``subject=subject or ""``: a
    subject that is absent (or empty) becomes the empty string.  Mutating
    ``or`` to ``and`` produces the empty string only when the subject
    is *also* empty -- so a subject that is present but falsy (the
    integer ``0``, say) is carried through as that integer, and the
    receipt renders a subject that is not a text field at all.
    """

    def test_or474_a_falsy_but_present_subject_becomes_the_empty_string(self):
        receipt = bind(
            b"artifact-bytes", _pin(),
            permitted_at_seq=3, epoch=3, clock_id="host-clock", issuer_id="issuer-a",
            subject=0,
        )
        self.assertEqual(receipt.subject, "")

    def test_or474_a_none_subject_becomes_the_empty_string(self):
        receipt = bind(
            b"artifact-bytes", _pin(),
            permitted_at_seq=3, epoch=3, clock_id="host-clock", issuer_id="issuer-a",
            subject=None,
        )
        self.assertEqual(receipt.subject, "")

    def test_or474_a_present_subject_is_carried_through(self):
        receipt = bind(
            b"artifact-bytes", _pin(),
            permitted_at_seq=3, epoch=3, clock_id="host-clock", issuer_id="issuer-a",
            subject="post-42",
        )
        self.assertEqual(receipt.subject, "post-42")
        self.assertIn("subject=post-42", receipt.render())

    def test_or474_the_empty_subject_is_carried_through_as_the_empty_string(self):
        # The control: the case the mutant still catches.
        receipt = bind(
            b"artifact-bytes", _pin(),
            permitted_at_seq=3, epoch=3, clock_id="host-clock", issuer_id="issuer-a",
            subject="",
        )
        self.assertEqual(receipt.subject, "")


class MutantLtAt526OpenSealedTests(unittest.TestCase):
    """Kills the ``lt@526`` mutant in ``open_sealed``.

    The guard is ``if newline < 0:`` -- the container carries a newline
    that ends the receipt line.  Mutating ``<`` to ``<=`` treats a
    newline at index ``0`` as "no newline at all": a container whose
    receipt line is empty is then *opened* instead of being refused for
    a missing receipt.
    """

    def _container_without_a_receipt_line(self) -> bytes:
        return artifact_authority.SEAL_PREFIX + b"\n" + b"payload-bytes"

    def test_lt526_a_container_whose_receipt_line_is_empty_is_refused(self):
        # The boundary: the newline is at index 0, so the receipt line
        # IS present and empty -- the newline is found, and the empty
        # receipt is what the refusal names.  Under the mutant the
        # newline at index 0 is treated as absent, and the refusal
        # names the missing newline instead.
        with self.assertRaises(MalformedReceiptError) as caught:
            open_sealed(self._container_without_a_receipt_line())
        self.assertIn("non-empty str", str(caught.exception))
        self.assertNotIn("must carry its receipt", str(caught.exception))

    def test_lt526_a_container_with_no_newline_at_all_is_refused(self):
        # The control: the case the mutant still catches.
        with self.assertRaises(MalformedReceiptError) as caught:
            open_sealed(artifact_authority.SEAL_PREFIX + b"receipt-without-a-newline")
        self.assertIn("must carry its receipt", str(caught.exception))

    def test_lt526_a_well_formed_container_still_opens(self):
        receipt = _bind(b"payload-bytes")
        container = seal_bytes(b"payload-bytes", receipt)
        payload, opened = open_sealed(container)
        self.assertEqual(payload, b"payload-bytes")
        self.assertEqual(opened, receipt)


class MutantVerifyCounterTests(unittest.TestCase):
    """Kills the ``and@627``, ``gt@628`` and ``and@632`` mutants.

    ``verify`` compares the receipt's pin against the grant's current
    state:

    * ``and@627`` -- ``if receipt.grant.counter is not None and
      current_grant.counter is not None:`` -- the counter comparison
      needs *both* counters present.  Mutating ``and`` to ``or`` fires
      the comparison when only one counter is present, so a receipt
      whose counter is set and whose current grant's is null is treated
      as a re-issued grant.
    * ``gt@628`` -- ``current_grant.counter > receipt.grant.counter`` --
      mutating ``>`` to ``>=`` makes the *same* counter look like a
      re-issue.
    * ``and@632`` -- ``elif receipt.grant.counter is None and
      current_grant.counter is not None:`` -- the "became resolvable"
      arm needs both halves.  Mutating ``and`` to ``or`` fires it when
      either is null, so an unresolved receipt whose current grant is
      *also* unresolved is reported as having become resolvable.
    """

    def test_and627_a_receipt_with_a_counter_against_an_unresolved_grant_is_not_stale(self):
        receipt = bind(
            b"artifact-bytes", _pin(counter=7),
            permitted_at_seq=3, epoch=3, clock_id="host-clock", issuer_id="issuer-a",
        )
        verdict = verify(
            receipt, 3, None, current_grant=GrantPin("grant-1", "v2", None)
        )
        self.assertEqual(verdict.state, VALID)

    def test_and627_a_receipt_with_a_counter_against_the_same_counter_is_valid(self):
        receipt = bind(
            b"artifact-bytes", _pin(counter=7),
            permitted_at_seq=3, epoch=3, clock_id="host-clock", issuer_id="issuer-a",
        )
        verdict = verify(
            receipt, 3, None, current_grant=GrantPin("grant-1", "v2", 7)
        )
        self.assertEqual(verdict.state, VALID)

    def test_gt628_a_re_issued_grant_is_stale(self):
        # The control for both neighbours: the case the mutants still catch.
        receipt = bind(
            b"artifact-bytes", _pin(counter=7),
            permitted_at_seq=3, epoch=3, clock_id="host-clock", issuer_id="issuer-a",
        )
        verdict = verify(
            receipt, 3, None, current_grant=GrantPin("grant-1", "v2", 8)
        )
        self.assertEqual(verdict.state, STALE)

    def test_and632_an_unresolved_receipt_against_an_unresolved_grant_is_valid(self):
        receipt = bind(
            b"artifact-bytes", _pin(counter=None),
            permitted_at_seq=3, epoch=3, clock_id="host-clock", issuer_id="issuer-a",
        )
        verdict = verify(
            receipt, 3, None, current_grant=GrantPin("grant-1", "v2", None)
        )
        self.assertEqual(verdict.state, VALID)

    def test_and632_an_unresolved_receipt_that_became_resolvable_is_stale(self):
        # The control: the case the mutant still catches.
        receipt = bind(
            b"artifact-bytes", _pin(counter=None),
            permitted_at_seq=3, epoch=3, clock_id="host-clock", issuer_id="issuer-a",
        )
        verdict = verify(
            receipt, 3, None, current_grant=GrantPin("grant-1", "v2", 5)
        )
        self.assertEqual(verdict.state, STALE)


class MutantOrAt729LedgerSeqTests(unittest.TestCase):
    """Kills the ``or@729`` mutant in ``ArtifactAuthorityLedger.artifact``.

    The guard is ``if isinstance(seq, bool) or not isinstance(seq, int):``
    -- a sequence number is an integer *and* not a boolean.  Mutating
    ``or`` to ``and`` refuses only a value that fails both halves, so a
    boolean seq reaches the range check and indexes the ledger with
    ``True`` -- which is the integer 1, so the *first* artifact is
    returned for a boolean request.
    """

    def test_or729_a_boolean_seq_is_refused(self):
        ledger = ArtifactAuthorityLedger()
        ledger.bind_and_seal(
            b"artifact-bytes", _pin(),
            permitted_at_seq=3, epoch=3, clock_id="host-clock", issuer_id="issuer-a",
        )
        for value in (True, False):
            with self.subTest(value=value):
                with self.assertRaises(ArtifactAuthorityError):
                    ledger.artifact(value)

    def test_or729_a_non_integer_seq_is_refused(self):
        # The other half, as the control.
        ledger = ArtifactAuthorityLedger()
        for value in ("1", 1.0, None):
            with self.subTest(value=value):
                with self.assertRaises(ArtifactAuthorityError):
                    ledger.artifact(value)

    def test_or729_a_real_integer_seq_returns_the_artifact(self):
        ledger = ArtifactAuthorityLedger()
        artifact = ledger.bind_and_seal(
            b"artifact-bytes", _pin(),
            permitted_at_seq=3, epoch=3, clock_id="host-clock", issuer_id="issuer-a",
        )
        self.assertIs(ledger.artifact(1), artifact)


class MutantStdlibOnlyTests(unittest.TestCase):
    """Kills the ``retF@783``, ``retF@786`` and ``retT@787`` mutants.

    ``stdlib_only`` walks the module's own AST and refuses any import
    that is not stdlib:

    * ``retF@783`` -- ``return False`` for a disallowed ``import`` --
      mutating it to ``return True`` claims the module is stdlib-only
      when it is not.
    * ``retF@786`` -- ``return False`` for a disallowed ``from ... import``
      -- the same, for the other import form.
    * ``retT@787`` -- ``return True`` at the end -- mutating it to
      ``return False`` refuses a module that really is stdlib-only.

    The check reads the module's source through ``Path.read_text``, so
    the tests substitute the source the check is supposed to judge.
    """

    def _stdlib_only_for(self, source: str) -> bool:
        with mock.patch.object(
            artifact_authority.Path, "read_text", return_value=source
        ):
            return artifact_authority.stdlib_only()

    def test_retF783_a_non_stdlib_import_is_refused(self):
        self.assertIs(self._stdlib_only_for("import numpy\n"), False)

    def test_retF786_a_non_stdlib_from_import_is_refused(self):
        self.assertIs(self._stdlib_only_for("from numpy import array\n"), False)

    def test_retF786_a_non_stdlib_submodule_from_import_is_refused(self):
        self.assertIs(self._stdlib_only_for("from numpy.linalg import array\n"), False)

    def test_retT787_a_stdlib_only_module_is_accepted(self):
        # The control for the ``retT@787`` mutant: a module that really
        # is stdlib-only must be accepted.
        self.assertIs(
            self._stdlib_only_for(
                "import ast\nimport json\nfrom dataclasses import dataclass\n"
            ),
            True,
        )

    def test_retT787_this_module_is_stdlib_only(self):
        # The real module, not a substitute: the check must accept the
        # module it is checking.
        self.assertIs(artifact_authority.stdlib_only(), True)


class MutantMainSelfCheckTests(unittest.TestCase):
    """Kills the ``eq@802`` and ``eq@803`` mutants in ``main``.

    ``main`` is the module's self-check: it seals a receipt, reads it
    back at the epoch it was sealed under (``VALID``) and one epoch
    later (``STALE``).  Mutating either comparison (``==`` -> ``!=``)
    makes the self-check demand the *wrong* verdict, so the self-check
    fails on the module's own correct behaviour -- which is exactly how
    a broken self-check is caught.
    """

    def test_eq802_the_self_check_sees_the_receipt_valid_at_its_own_epoch(self):
        receipt = _bind(epoch=3)
        self.assertEqual(verify(receipt, epoch_now=3).state, VALID)

    def test_eq803_the_self_check_sees_the_receipt_stale_one_epoch_later(self):
        receipt = _bind(epoch=3)
        self.assertEqual(verify(receipt, epoch_now=4).state, STALE)

    def test_eq802_the_self_check_runs_to_completion(self):
        # The control: the module's own self-check must pass on the
        # unmutated module.
        with contextlib.redirect_stdout(io.StringIO()):
            artifact_authority.main()

    def test_eq803_the_self_check_refuses_a_tampered_container(self):
        receipt = _bind(b"artifact-bytes")
        container = seal_bytes(b"artifact-bytes", receipt)
        tampered = container[:-1] + b"X"
        with self.assertRaises(MalformedReceiptError):
            open_sealed(tampered)

    def test_eq817_importing_the_module_does_not_run_the_self_check(self):
        """``eq@817`` -- the ``if __name__ == "__main__":`` guard.

        The self-check belongs to the module *run as a script*, not to the
        module *imported*.  Mutating the comparison to ``!=`` makes the
        self-check run on every import, so importing the module prints the
        self-check's line.  The observation is the import's own output: a
        fresh interpreter that imports the module must say nothing.
        """
        import subprocess

        result = subprocess.run(
            [sys.executable, "-c", "import artifact_authority"],
            cwd=str(Path(artifact_authority.__file__).resolve().parent),
            capture_output=True,
            text=True,
            timeout=120,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout, "",
            "importing the module must not run its self-check",
        )

    def test_eq817_running_the_module_as_a_script_does_run_the_self_check(self):
        # The control: run as a script, the self-check DOES run and the
        # module reports its verdict.
        import subprocess

        result = subprocess.run(
            [sys.executable, str(Path(artifact_authority.__file__).resolve())],
            cwd=str(Path(artifact_authority.__file__).resolve().parent),
            capture_output=True,
            text=True,
            timeout=120,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("artifact-authority OK", result.stdout)






class ReceiptSeparatorRoundTripTests(unittest.TestCase):
    """A receipt must survive its own round trip.

    The receipt's text is a ``;``-separated list on a single line, and
    the sealed container carries that text as one line.  A field that
    carries a separator therefore breaks the format the receipt itself
    defines: the text cannot be parsed back into a receipt, and a
    container whose receipt line carries a newline is cut short at that
    newline, so it cannot be opened at all.

    The fields that could carry a separator are the digest and the pin's
    own text fields (the grant id and the grant version) -- the pin is
    reused verbatim from ``grant_pin_ledger``, which does not police the
    receipt's grammar, so the rule belongs here, where the grammar
    lives.
    """

    def _receipt(self, **overrides):
        fields = dict(
            artifact_digest="sha256:" + "0" * 64,
            grant=GrantPin("grant-1", "v2", 7),
            permitted_at=3,
            revocation_epoch=3,
            clock_id="host-clock",
            issuer_id="issuer-a",
        )
        fields.update(overrides)
        return ArtifactReceipt(**fields)

    def test_a_grant_id_carrying_the_semicolon_is_refused(self):
        with self.assertRaises(MalformedReceiptError):
            self._receipt(grant=GrantPin("grant;1", "v2", 7))

    def test_a_grant_id_carrying_a_newline_is_refused(self):
        with self.assertRaises(MalformedReceiptError):
            self._receipt(grant=GrantPin("grant\n1", "v2", 7))

    def test_a_grant_version_carrying_the_semicolon_is_refused(self):
        with self.assertRaises(MalformedReceiptError):
            self._receipt(grant=GrantPin("grant-1", "v;2", 7))

    def test_a_grant_version_carrying_a_newline_is_refused(self):
        with self.assertRaises(MalformedReceiptError):
            self._receipt(grant=GrantPin("grant-1", "v\n2", 7))

    def test_a_digest_carrying_the_semicolon_is_refused(self):
        with self.assertRaises(MalformedReceiptError):
            self._receipt(artifact_digest="sha256:a;b")

    def test_a_digest_carrying_a_newline_is_refused(self):
        with self.assertRaises(MalformedReceiptError):
            self._receipt(artifact_digest="sha256:a\nb")

    def test_a_receipt_without_a_separator_round_trips(self):
        # The control: an ordinary receipt is unaffected by the rule.
        receipt = self._receipt()
        self.assertEqual(ArtifactReceipt.parse(receipt.render()), receipt)

    def test_a_sealed_container_built_from_a_receipt_opens(self):
        payload = b"artifact-bytes"
        receipt = ArtifactReceipt(
            artifact_digest=artifact_authority._digest_bytes(payload),
            grant=GrantPin("grant-1", "v2", 7),
            permitted_at=3,
            revocation_epoch=3,
            clock_id="host-clock",
            issuer_id="issuer-a",
        )
        container = seal_bytes(payload, receipt)
        opened_payload, opened = open_sealed(container)
        self.assertEqual(opened_payload, payload)
        self.assertEqual(opened, receipt)

    def test_the_receipts_own_fields_carry_no_separator(self):
        # The rule, stated over the whole receipt: no field of a receipt
        # that can be rendered may carry a separator.
        receipt = self._receipt()
        for value in (
            receipt.artifact_digest,
            receipt.grant.grant_id,
            receipt.grant.version,
            receipt.clock_id,
            receipt.issuer_id,
            receipt.action,
            receipt.subject,
        ):
            with self.subTest(value=value):
                self.assertNotIn(";", value)
                self.assertNotIn("\n", value)
