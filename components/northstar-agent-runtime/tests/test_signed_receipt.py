"""Tests for signed_receipt: the receipt's own text is authenticated.

The gap under test, verbatim from ``docs/design/artifact-authority.md``
section 7:

    **The receipt is not a signature.** The receipt binds the *bytes* by
    digest, but its own text is not authenticated by this module: a
    container whose receipt line has been rewritten (a higher epoch, a
    different `permitted at` clause, a different action or counter) still
    opens and parses.

The rules under test:

* a valid issuer signature over the canonical receipt bytes is accepted,
  and the receipt that comes back is the one that was signed;
* a receipt line rewritten in any of the four ways the design doc names
  -- a higher epoch, a different ``permitted at`` clause, a different
  action, a different counter -- is refused;
* a tampered signature, a signature made by another key, and a receipt
  with no signature at all are refused;
* the signed path never accepts silently: every defect is an explicit
  exception;
* the signature layer does not break the existing seal: a signed receipt
  still opens through ``open_sealed``;
* the unsigned path is unchanged: ``artifact_authority.verify`` still
  takes an unsigned receipt.
"""

from __future__ import annotations

import dataclasses
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import artifact_authority
import message_signing
import signed_receipt
from artifact_authority import (
    ArtifactReceipt,
    GrantPin,
    bind,
    open_sealed,
    seal_bytes,
    verify,
)
from signed_receipt import (
    CanonicalReceiptError,
    IssuerKeyError,
    MissingSignatureError,
    SignatureMismatchError,
    SignedReceipt,
    SignedReceiptError,
    canonical_receipt_bytes,
    canonical_receipt_text,
    issuer_key_id,
    sign_receipt,
    verify_signed_receipt,
)

PAYLOAD = b"the artifact bytes that travel with the receipt"


def _seed(offset: int = 0) -> bytes:
    return bytes((offset + i) % 256 for i in range(32))


def signed_receipt_ed_pubkey(seed: bytes) -> bytes:
    """The public key for a seed, via the repo's own Ed25519 shim."""
    from ed25519 import public_key as ed_public_key

    return ed_public_key(bytes(seed))


def _receipt(**overrides) -> ArtifactReceipt:
    """A well-formed receipt (named grant, independent clock)."""
    fields = dict(
        artifact_digest=artifact_authority._digest_bytes(PAYLOAD),
        grant=GrantPin(grant_id="grant-alpha", version="v1", counter=7),
        permitted_at=42,
        revocation_epoch=3,
        clock_id="clock-west",
        issuer_id="issuer-east",
        action="dispatch",
        subject="",
    )
    fields.update(overrides)
    return ArtifactReceipt(**fields)


def _signed(seed: bytes | None = None, receipt: ArtifactReceipt | None = None) -> SignedReceipt:
    return sign_receipt(receipt or _receipt(), seed if seed is not None else _seed())


class CanonicalBytesTests(unittest.TestCase):
    """The canonical text is fixed, and it is the receipt's own text."""

    def test_canonical_text_is_the_receipt_rendering(self):
        receipt = _receipt()
        self.assertEqual(canonical_receipt_text(receipt), receipt.render())

    def test_canonical_bytes_are_utf8_of_the_canonical_text(self):
        receipt = _receipt()
        self.assertEqual(canonical_receipt_bytes(receipt), receipt.render().encode("utf-8"))

    def test_canonical_text_is_stable_across_equal_receipts(self):
        self.assertEqual(canonical_receipt_bytes(_receipt()), canonical_receipt_bytes(_receipt()))

    def test_canonical_text_carries_every_field(self):
        text = canonical_receipt_text(_receipt())
        for fragment in (
            "receipt:sha256:",
            "grant:grant-alpha",
            "version=v1",
            "counter=7",
            "permitted at 42",
            "epoch=3",
            "clock=clock-west",
            "issuer=issuer-east",
            "action=dispatch",
            "subject=",
            "check the list for now",
        ):
            self.assertIn(fragment, text)


class ValidSignatureTests(unittest.TestCase):
    """A correct signature is accepted, and the receipt comes back intact."""

    def test_valid_signature_verifies(self):
        signed = _signed()
        self.assertEqual(verify_signed_receipt(signed, signed.issuer_pubkey), signed.receipt)

    def test_verified_receipt_equals_the_issued_receipt(self):
        receipt = _receipt()
        signed = _signed(receipt=receipt)
        self.assertEqual(verify_signed_receipt(signed, signed.issuer_pubkey), receipt)

    def test_signature_is_hex_of_64_bytes(self):
        signed = _signed()
        self.assertEqual(len(signed.signature), 128)
        bytes.fromhex(signed.signature)

    def test_issuer_key_id_is_the_public_key_digest(self):
        signed = _signed()
        self.assertEqual(signed.issuer_key_id, issuer_key_id(signed.issuer_pubkey))


class ForgedReceiptLineTests(unittest.TestCase):
    """The four rewrites the design doc names are all refused.

    Each case rewrites the *receipt text* of an otherwise valid signed
    receipt and checks that the signed path refuses it.
    """

    def _assert_refused(self, forged: SignedReceipt, pubkey: bytes) -> None:
        with self.assertRaises(signed_receipt.SignedReceiptError):
            verify_signed_receipt(forged, pubkey)

    def test_forged_higher_epoch_is_refused(self):
        signed = _signed()
        forged = dataclasses.replace(
            signed, receipt=dataclasses.replace(signed.receipt, revocation_epoch=99)
        )
        self._assert_refused(forged, signed.issuer_pubkey)

    def test_forged_permitted_at_is_refused(self):
        signed = _signed()
        forged = dataclasses.replace(
            signed, receipt=dataclasses.replace(signed.receipt, permitted_at=12345)
        )
        self._assert_refused(forged, signed.issuer_pubkey)

    def test_forged_action_is_refused(self):
        signed = _signed()
        forged = dataclasses.replace(
            signed, receipt=dataclasses.replace(signed.receipt, action="delete")
        )
        self._assert_refused(forged, signed.issuer_pubkey)

    def test_forged_counter_is_refused(self):
        signed = _signed()
        forged = dataclasses.replace(
            signed,
            receipt=dataclasses.replace(
                signed.receipt, grant=GrantPin("grant-alpha", "v1", 8)
            ),
        )
        self._assert_refused(forged, signed.issuer_pubkey)

    def test_forged_receipt_line_text_is_refused(self):
        """The raw text of the receipt line, rewritten in place."""
        signed = _signed()
        forged_text = signed.rendered.replace("epoch=3", "epoch=99")
        self.assertNotEqual(forged_text, signed.rendered)
        forged = dataclasses.replace(
            signed, receipt=ArtifactReceipt.parse(forged_text)
        )
        self._assert_refused(forged, signed.issuer_pubkey)


class TamperedSignatureTests(unittest.TestCase):
    """A tampered signature, a wrong key, and no signature at all."""

    def test_tampered_signature_is_refused(self):
        signed = _signed()
        flipped = bytearray(bytes.fromhex(signed.signature))
        flipped[0] ^= 0x01
        message = dataclasses.replace(signed.message, signature=bytes(flipped).hex())
        forged = dataclasses.replace(signed, message=message)
        with self.assertRaises(SignatureMismatchError):
            verify_signed_receipt(forged, signed.issuer_pubkey)

    def test_wrong_issuer_public_key_is_refused(self):
        signed = _signed()
        other_pubkey = signed_receipt_ed_pubkey(_seed(offset=64))
        with self.assertRaises(SignatureMismatchError):
            verify_signed_receipt(signed, other_pubkey)

    def test_unsigned_receipt_on_the_signed_path_is_refused(self):
        receipt = _receipt()
        with self.assertRaises(MissingSignatureError):
            verify_signed_receipt(receipt, signed_receipt_ed_pubkey(_seed()))

    def test_signed_receipt_with_an_empty_signature_is_refused(self):
        signed = _signed()
        message = dataclasses.replace(signed.message, signature="")
        forged = dataclasses.replace(signed, message=message)
        with self.assertRaises(MissingSignatureError):
            verify_signed_receipt(forged, signed.issuer_pubkey)

    def test_mismatched_issuer_key_id_is_refused(self):
        signed = _signed()
        forged = dataclasses.replace(signed, issuer_key_id="sha256:" + "0" * 64)
        with self.assertRaises(IssuerKeyError):
            verify_signed_receipt(forged, signed.issuer_pubkey)

    def test_signature_over_a_different_receipt_body_is_refused(self):
        """A signature valid for *another* receipt must not carry this one."""
        other = sign_receipt(_receipt(permitted_at=99), _seed())
        signed = _signed()
        forged = dataclasses.replace(signed, message=other.message)
        with self.assertRaises(signed_receipt.SignedReceiptError):
            verify_signed_receipt(forged, signed.issuer_pubkey)


class RoundTripAndSealTests(unittest.TestCase):
    """The signed receipt survives serialisation and still opens the seal."""

    def test_roundtrip_through_a_dict_verifies(self):
        signed = _signed()
        rebuilt = SignedReceipt.from_dict(signed.to_dict())
        self.assertEqual(verify_signed_receipt(rebuilt, signed.issuer_pubkey), signed.receipt)

    def test_roundtrip_keeps_the_canonical_bytes(self):
        signed = _signed()
        rebuilt = SignedReceipt.from_dict(signed.to_dict())
        self.assertEqual(canonical_receipt_bytes(rebuilt.receipt), canonical_receipt_bytes(signed.receipt))

    def test_a_tampered_roundtripped_document_is_refused(self):
        signed = _signed()
        doc = signed.to_dict()
        doc["receipt"]["revocation_epoch"] = 99
        rebuilt = SignedReceipt.from_dict(doc)
        with self.assertRaises(signed_receipt.SignedReceiptError):
            verify_signed_receipt(rebuilt, signed.issuer_pubkey)

    def test_signed_receipt_still_opens_a_sealed_container(self):
        receipt = bind(PAYLOAD, GrantPin("grant-alpha", "v1", 7), 42, 3, "clock-west", "issuer-east")
        signed = sign_receipt(receipt, _seed())
        container = seal_bytes(PAYLOAD, signed.receipt)
        payload, opened = open_sealed(container)
        self.assertEqual(payload, PAYLOAD)
        self.assertEqual(opened, signed.receipt)
        self.assertEqual(verify_signed_receipt(signed, signed.issuer_pubkey), opened)

    def test_the_unsigned_path_still_takes_an_unsigned_receipt(self):
        """Backward compatibility: artifact_authority.verify is unchanged."""
        receipt = _receipt()
        verdict = verify(receipt, epoch_now=3)
        self.assertTrue(verdict.is_valid)

    def test_a_forged_receipt_line_still_parses_unsigned(self):
        """The gap this slice closes: unsigned parsing still accepts it.

        The unsigned path is deliberately left alone -- this module adds a
        signed path, it does not change the old one.  The test states the
        gap explicitly so nobody mistakes the two.
        """
        signed = _signed()
        forged_text = signed.rendered.replace("epoch=3", "epoch=99")
        forged = ArtifactReceipt.parse(forged_text)
        self.assertEqual(forged.revocation_epoch, 99)
        with self.assertRaises(signed_receipt.SignedReceiptError):
            verify_signed_receipt(
                dataclasses.replace(signed, receipt=forged), signed.issuer_pubkey
            )


class DependencyTests(unittest.TestCase):
    """The module reuses what exists; it does not grow new dependencies."""

    def test_no_import_of_the_key_custody_module(self):
        source = Path(signed_receipt.__file__).read_text(encoding="utf-8")
        self.assertNotIn("key_custody", source.replace("key-custody", ""))

    def test_the_module_only_imports_siblings_and_stdlib(self):
        import ast

        tree = ast.parse(Path(signed_receipt.__file__).read_text(encoding="utf-8"))
        allowed = {
            "__future__",
            "ast",
            "dataclasses",
            "hashlib",
            "typing",
            "artifact_authority",
            "message_signing",
            "ed25519",
        }
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.assertIn(alias.name.split(".")[0], allowed)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    self.assertIn(node.module.split(".")[0], allowed)

    def test_the_signing_primitive_is_reused_from_message_signing(self):
        self.assertIs(signed_receipt.sign_message, message_signing.sign_message)
        self.assertIs(signed_receipt.verify_message, message_signing.verify_message)


class MutantOrAt179IssuerKeyIdTests(unittest.TestCase):
    """Kills the ``or@179`` mutant in ``issuer_key_id``.

    The guard is::

        if not isinstance(issuer_pubkey, (bytes, bytearray)) or len(issuer_pubkey) != 32:

    Mutating ``or`` to ``and`` makes the guard fire only when the key is
    *both* not-bytes *and* the wrong length -- never, because a non-bytes
    value has no ``len`` of 32.  The guard stops firing and a wrong-length
    key reaches the digest.

    Two wrong ways are needed:

    * a **str** -- format right (not bytes) but type wrong.  The original
      raises ``IssuerKeyError``; the mutant raises ``TypeError`` from
      ``len()``/``hashlib`` instead.
    * a **31-byte** key -- type right (bytes) but format wrong.  The
      original raises ``IssuerKeyError``; the mutant computes a digest of
      the short key and returns it as a valid-looking id.
    """

    def test_or_at_179_a_str_key_is_refused_with_the_module_error(self):
        # Format right (not bytes) but type wrong.
        with self.assertRaises(IssuerKeyError):
            issuer_key_id("a" * 32)

    def test_or_at_179_a_none_key_is_refused_with_the_module_error(self):
        with self.assertRaises(IssuerKeyError):
            issuer_key_id(None)

    def test_or_at_179_a_key_one_byte_short_is_refused(self):
        # Type right (bytes) but format wrong.
        with self.assertRaises(IssuerKeyError):
            issuer_key_id(b"\x00" * 31)

    def test_or_at_179_a_key_one_byte_long_is_refused(self):
        with self.assertRaises(IssuerKeyError):
            issuer_key_id(b"\x00" * 33)

    def test_or_at_179_a_real_32_byte_key_still_names_itself(self):
        # The control: the happy path must survive the guard being pinned.
        key = b"\x01" * 32
        self.assertTrue(issuer_key_id(key).startswith("sha256:"))




class MutantOrAt280SignReceiptSeedTests(unittest.TestCase):
    """Kills the ``or@280`` mutant in ``sign_receipt``.

    The guard is::

        if not isinstance(issuer_seed, (bytes, bytearray)) or len(issuer_seed) != 32:

    Mutating ``or`` to ``and`` makes the guard fire only when the seed is
    *both* not-bytes *and* the wrong length -- never.  The guard stops
    firing and a bad seed reaches the Ed25519 shim.

    Two wrong ways are needed:

    * a **str** -- format right (not bytes) but type wrong.  The original
      raises ``SignedReceiptError``; the mutant raises ``TypeError`` from
      ``bytes()`` instead.
    * a **31-byte** seed -- type right (bytes) but format wrong.  The
      original raises ``SignedReceiptError``; the mutant lets the shim's
      own ``ValueError`` escape, which is not the module's error.
    """

    def test_or_at_280_a_str_seed_is_refused_with_the_module_error(self):
        # Format right (not bytes) but type wrong.
        with self.assertRaises(SignedReceiptError):
            sign_receipt(_receipt(), "s" * 32)

    def test_or_at_280_a_none_seed_is_refused_with_the_module_error(self):
        with self.assertRaises(SignedReceiptError):
            sign_receipt(_receipt(), None)

    def test_or_at_280_a_seed_one_byte_short_is_refused(self):
        # Type right (bytes) but format wrong.
        with self.assertRaises(SignedReceiptError):
            sign_receipt(_receipt(), b"\x00" * 31)

    def test_or_at_280_a_seed_one_byte_long_is_refused(self):
        with self.assertRaises(SignedReceiptError):
            sign_receipt(_receipt(), b"\x00" * 33)

    def test_or_at_280_a_real_32_byte_seed_still_signs(self):
        # The control: the happy path must survive the guard being pinned.
        signed = sign_receipt(_receipt(), _seed())
        self.assertIsInstance(signed, SignedReceipt)




class MutantOrAt317VerifySignedReceiptKeyTests(unittest.TestCase):
    """Kills the ``or@317`` mutant in ``verify_signed_receipt``.

    The guard is::

        if not isinstance(issuer_pubkey, (bytes, bytearray)) or len(issuer_pubkey) != 32:

    Mutating ``or`` to ``and`` makes the guard fire only when the key is
    *both* not-bytes *and* the wrong length -- never.  The guard stops
    firing and a wrong-length key reaches the verification path.

    Two wrong ways are needed:

    * a **str** -- format right (not bytes) but type wrong.  The original
      raises ``IssuerKeyError``; the mutant raises ``TypeError`` from
      ``bytes()`` instead.
    * a **31-byte** key -- type right (bytes) but format wrong.  The
      original raises ``IssuerKeyError``; the mutant reaches the signature
      check and fails with a *signature* error, which claims the receipt
      was forged when in fact the key was malformed.
    """

    def test_or_at_317_a_str_key_is_refused_with_the_module_error(self):
        # Format right (not bytes) but type wrong.
        signed = _signed()
        with self.assertRaises(IssuerKeyError):
            verify_signed_receipt(signed, "a" * 32)

    def test_or_at_317_a_none_key_is_refused_with_the_module_error(self):
        signed = _signed()
        with self.assertRaises(IssuerKeyError):
            verify_signed_receipt(signed, None)

    def test_or_at_317_a_key_one_byte_short_is_refused(self):
        # Type right (bytes) but format wrong.
        signed = _signed()
        with self.assertRaises(IssuerKeyError):
            verify_signed_receipt(signed, b"\x00" * 31)

    def test_or_at_317_a_key_one_byte_long_is_refused(self):
        signed = _signed()
        with self.assertRaises(IssuerKeyError):
            verify_signed_receipt(signed, b"\x00" * 33)

    def test_or_at_317_the_real_key_still_verifies(self):
        # The control: the happy path must survive the guard being pinned.
        seed = _seed()
        signed = _signed(seed)
        receipt = verify_signed_receipt(signed, signed_receipt_ed_pubkey(seed))
        self.assertEqual(receipt.action, "dispatch")


class MutantOrAt331PayloadGuardTests(unittest.TestCase):
    """The second half of the signed-body payload guard.

    The guard is

        if not isinstance(payload, dict) or CANONICAL_PAYLOAD_KEY not in payload:

    The FIRST half is "is the payload a mapping at all?" and the
    SECOND is "does it carry the canonical receipt bytes?".  The suite
    drove the first half -- a payload that is not a dict is refused --
    and left the second, so a fault planted there survived.

    The halves are NOT interchangeable, and the difference is what
    the guard exists for.  Under ``or`` -> ``and`` the guard reads
    "the payload is a mapping AND it carries the bytes", so a
    well-formed mapping that does NOT carry the canonical bytes
    passes the guard -- and the verifier then goes on to read
    ``payload[CANONICAL_PAYLOAD_KEY]``, which raises ``KeyError``:
    an unhandled error instead of the module's own explicit
    ``CanonicalReceiptError``.

    That matters because this module's contract is that the signed
    path NEVER accepts silently and every defect is an EXPLICIT
    exception.  A ``KeyError`` from deep inside is not that.
    """

    def _signed_with_payload(self, payload) -> SignedReceipt:
        """A receipt signed over a payload of the caller's choosing."""
        signed = _signed()
        message = message_signing.sign_message(
            "issuer-east",
            _seed(),
            signed_receipt.VERIFIER_RECIPIENT,
            payload,
        )
        return dataclasses.replace(signed, message=message)

    def test_a_signed_body_without_the_canonical_bytes_is_refused(self):
        """`or@331`: the second half of the payload guard.

        The signed body carries a mapping, but not the canonical
        receipt bytes.  The verifier must refuse it with the module's
        own ``CanonicalReceiptError``.

        Under the mutant the guard passes, and the verifier raises a
        bare ``KeyError`` -- which is not a
        ``CanonicalReceiptError``, so the test fails on the type.
        """
        signed = self._signed_with_payload({"something_else": "not the receipt"})
        with self.assertRaises(CanonicalReceiptError):
            verify_signed_receipt(signed, signed.issuer_pubkey)

    def test_a_signed_body_with_no_payload_at_all_is_refused(self):
        """`or@331`: the first half, as the control.

        A payload that is not a mapping is refused.  The payload is
        part of the signing body, so the message has to be signed OVER
        the non-mapping payload -- otherwise the signature check (which
        comes first) would refuse it and the payload guard would never
        be reached.
        """
        import json

        from ed25519 import sign as ed_sign

        signed = _signed()
        unsigned = message_signing.SignedMessage(
            sender_id=signed.message.sender_id,
            recipient_id=signed.message.recipient_id,
            payload="not a mapping",
            timestamp=signed.message.timestamp,
            nonce=signed.message.nonce,
        )
        body = json.dumps(unsigned._signing_body(), sort_keys=True).encode()
        message = dataclasses.replace(
            signed.message,
            payload="not a mapping",
            signature=ed_sign(_seed(), body).hex(),
        )
        forged = dataclasses.replace(signed, message=message)
        with self.assertRaises(CanonicalReceiptError):
            verify_signed_receipt(forged, signed.issuer_pubkey)

    def test_a_signed_body_carrying_the_canonical_bytes_still_verifies(self):
        """`or@331`: the control -- a real signed receipt verifies."""
        signed = _signed()
        receipt = verify_signed_receipt(signed, signed.issuer_pubkey)
        self.assertEqual(receipt, signed.receipt)


if __name__ == "__main__":
    unittest.main()
