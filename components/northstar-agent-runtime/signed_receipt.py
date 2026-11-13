"""Signed receipts: the receipt's own text is authenticated by the issuer.

The gap this closes, verbatim from ``docs/design/artifact-authority.md``
section 7 (the vina open item):

    **The receipt is not a signature.** The receipt binds the *bytes* by
    digest, but its own text is not authenticated by this module: a
    container whose receipt line has been rewritten (a higher epoch, a
    different `permitted at` clause, a different action or counter) still
    opens and parses. The receipt is meant to travel inside the
    forward-sealed chain -- whose records are HMAC-sealed and hash-chained
    -- and that binding is what would make a forged receipt detectable.
    This slice does not wire the receipt into the sealed chain, so a
    forged receipt is detectable only where it disagrees with the grant's
    current state or with a tombstone.

What this module adds: the issuer signs the receipt's **canonical bytes**
with Ed25519, and :func:`verify_signed_receipt` verifies that signature
*before* it accepts the receipt.  A rewritten receipt line -- a higher
epoch, a different ``permitted at`` clause, a different action, a
different counter -- no longer opens and parses *as an accepted receipt*:
the signature does not match, and the receipt is refused.

The signature primitive is **reused, not reimplemented**: this module
calls :func:`message_signing.sign_message` and
:func:`message_signing.verify_message`.  The canonical receipt bytes are
carried verbatim inside the signed message's payload, so any change to
the receipt text changes the signed body and the signature stops
verifying.  The key-custody module is **not** used and **not** imported:
this module holds no long-term key material of its own, it only signs
with a seed the caller hands it.

``artifact_authority.py`` is **read-only reused**: the receipt type, its
rendering and its parsing come from there, unchanged.

What a valid signature proves -- and what it does not:

* it **does** prove that the holder of the issuer's Ed25519 seed wrote
  *this exact receipt text*;
* it **does not** prove that the clock is independent of the issuer --
  the receipt still only *names* a clock;
* it **does not** prove that the grant was real, or that the epoch was
  read at the right moment, or that the counter was the right one.  The
  grant's truth is still checked elsewhere (the seal layer, the tombstone
  set), and that check is unchanged.

The canonical bytes are defined **here**, fixed: the field order, the
``;`` separator, the trailing ``check the list for now`` clause and the
UTF-8 encoding are all pinned in this module, and the canonical text is
required to equal :meth:`artifact_authority.ArtifactReceipt.render` --
if upstream ever drifts, signing fails closed instead of signing
something ambiguous.

House style: frozen dataclasses, fail-closed taxonomy, stdlib-only (plus
the repo's own ``ed25519`` shim, used through ``message_signing``),
``sha256:`` digest pins, version/schema pins.

Version pin: ``signed-receipt.v1``
Schema pin: ``northstar.signed-receipt.v1``
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from artifact_authority import (
    ArtifactReceipt,
    CHECK_THE_LIST_FOR_NOW,
    PERMITTED_AT_PREFIX,
    SCHEMA_PIN as RECEIPT_SCHEMA_PIN,
)
from message_signing import SignedMessage, sign_message, verify_message

#: Module version pin.
SIGNED_RECEIPT_VERSION = "signed-receipt.v1"

#: Schema pin carried by signed receipts.
SCHEMA_PIN = "northstar.signed-receipt.v1"

#: The field order of the canonical receipt bytes, fixed here.
CANONICAL_FIELD_ORDER = (
    "receipt_digest",
    "grant_id",
    "version",
    "counter",
    "permitted_at",
    "epoch",
    "clock_id",
    "issuer_id",
    "action",
    "subject",
)

#: The separator between canonical fields, fixed here.
CANONICAL_SEPARATOR = ";"

#: The encoding of the canonical bytes, fixed here.
CANONICAL_ENCODING = "utf-8"

#: The payload key the canonical bytes travel under, inside the signed
#: message body.
CANONICAL_PAYLOAD_KEY = "receipt_bytes"

#: The recipient identity the signed message is addressed to.  A receipt
#: is not delivered to a peer agent; it is addressed to whoever verifies
#: it, and this constant says so.
VERIFIER_RECIPIENT = "artifact-authority-verifier"


class SignedReceiptError(Exception):
    """Base class for signed-receipt errors."""


class MissingSignatureError(SignedReceiptError):
    """The receipt carries no signature: nothing to verify."""


class SignatureMismatchError(SignedReceiptError):
    """The signature does not verify under the issuer's public key."""


class CanonicalReceiptError(SignedReceiptError):
    """The receipt text is not the canonical text, or does not match it."""


class IssuerKeyError(SignedReceiptError):
    """The issuer key identifier does not match the key it was given for."""


def _null_or_text(value: Any) -> str:
    """``null`` for a missing field, the text itself otherwise."""
    return "null" if value is None else str(value)


def canonical_receipt_text(receipt: ArtifactReceipt) -> str:
    """The receipt's canonical text: the exact bytes that get signed.

    The field order, the separator and the trailing clause are fixed by
    this module (see :data:`CANONICAL_FIELD_ORDER`,
    :data:`CANONICAL_SEPARATOR`, :data:`CHECK_THE_LIST_FOR_NOW`).  The
    text is the receipt's own past-tense rendering, byte for byte; a
    receipt whose canonical text disagrees with
    :meth:`artifact_authority.ArtifactReceipt.render` is refused by the
    caller (see :func:`canonical_receipt_bytes`).
    """
    if not isinstance(receipt, ArtifactReceipt):
        raise CanonicalReceiptError("a canonical text is built from a receipt")
    parts = [
        f"receipt:{receipt.artifact_digest}",
        f"grant:{receipt.grant.grant_id}",
        f"version={_null_or_text(receipt.grant.version)}",
        f"counter={_null_or_text(receipt.grant.counter)}",
        f"{PERMITTED_AT_PREFIX}{receipt.permitted_at}",
        f"epoch={receipt.revocation_epoch}",
        f"clock={receipt.clock_id}",
        f"issuer={receipt.issuer_id}",
        f"action={receipt.action}",
        f"subject={receipt.subject}",
    ]
    text = CANONICAL_SEPARATOR.join(parts) + CANONICAL_SEPARATOR + CHECK_THE_LIST_FOR_NOW
    if text != receipt.render():
        raise CanonicalReceiptError(
            "the canonical receipt text does not match the receipt's own "
            "rendering: the canonical form and artifact_authority have drifted"
        )
    return text


def canonical_receipt_bytes(receipt: ArtifactReceipt) -> bytes:
    """The canonical bytes that are signed: the canonical text, UTF-8."""
    return canonical_receipt_text(receipt).encode(CANONICAL_ENCODING)


def issuer_key_id(issuer_pubkey: bytes) -> str:
    """The ``sha256:`` identifier of an issuer's public key."""
    import hashlib

    if not isinstance(issuer_pubkey, (bytes, bytearray)) or len(issuer_pubkey) != 32:
        raise IssuerKeyError("an issuer public key must be 32 bytes")
    return "sha256:" + hashlib.sha256(bytes(issuer_pubkey)).hexdigest()


@dataclass(frozen=True)
class SignedReceipt:
    """A receipt plus the issuer's signature over its canonical bytes.

    ``receipt`` is the receipt as issued.  ``message`` is the signed
    envelope: its payload carries the canonical bytes of that receipt
    verbatim, so the signature binds the receipt's text and not an
    approximation of it.  ``issuer_pubkey`` is the key the signature is
    meant to verify under, and ``issuer_key_id`` names it.
    """

    receipt: ArtifactReceipt
    message: SignedMessage
    issuer_pubkey: bytes
    issuer_key_id: str

    @property
    def signature(self) -> str:
        """The signature, hex."""
        return self.message.signature

    @property
    def rendered(self) -> str:
        """The canonical receipt text this signature covers."""
        return canonical_receipt_text(self.receipt)

    def to_dict(self) -> dict:
        """A serialisable mapping, round-tripped by :meth:`from_dict`."""
        return {
            "schema_version": SCHEMA_PIN,
            "receipt": self.receipt.to_dict(),
            "message": self.message.as_dict(),
            "issuer_pubkey": bytes(self.issuer_pubkey).hex(),
            "issuer_key_id": self.issuer_key_id,
        }

    @classmethod
    def from_dict(cls, doc: Any) -> "SignedReceipt":
        """Rebuild a signed receipt from :meth:`to_dict`."""
        if not isinstance(doc, dict):
            raise SignedReceiptError("a signed receipt document must be a mapping")
        if doc.get("schema_version") != SCHEMA_PIN:
            raise SignedReceiptError("a signed receipt document has the wrong schema")
        receipt_doc = doc.get("receipt")
        if not isinstance(receipt_doc, dict):
            raise SignedReceiptError("a signed receipt document must carry a receipt")
        from artifact_authority import GrantPin

        try:
            receipt = ArtifactReceipt(
                artifact_digest=receipt_doc["artifact_digest"],
                grant=GrantPin.from_dict(receipt_doc["grant"]),
                permitted_at=receipt_doc["permitted_at"],
                revocation_epoch=receipt_doc["revocation_epoch"],
                clock_id=receipt_doc["clock_id"],
                issuer_id=receipt_doc["issuer_id"],
                action=receipt_doc.get("action", "dispatch"),
                subject=receipt_doc.get("subject", ""),
            )
        except Exception as error:
            raise SignedReceiptError(f"a signed receipt document carries a malformed receipt: {error}") from error
        message_doc = doc.get("message")
        if not isinstance(message_doc, dict):
            raise SignedReceiptError("a signed receipt document must carry a message")
        pubkey_hex = doc.get("issuer_pubkey")
        if not isinstance(pubkey_hex, str):
            raise SignedReceiptError("a signed receipt document must carry an issuer key")
        try:
            pubkey = bytes.fromhex(pubkey_hex)
        except ValueError as error:
            raise SignedReceiptError("an issuer key is not hex") from error
        return cls(
            receipt=receipt,
            message=SignedMessage.from_dict(message_doc),
            issuer_pubkey=pubkey,
            issuer_key_id=str(doc.get("issuer_key_id", "")),
        )


def sign_receipt(
    receipt: ArtifactReceipt,
    issuer_seed: bytes,
    *,
    signer_id: str | None = None,
    timestamp: float | None = None,
    nonce: str | None = None,
) -> SignedReceipt:
    """Sign a receipt's canonical bytes with the issuer's Ed25519 seed.

    The seed is the caller's; this module stores no key material.  The
    signed body is produced by :func:`message_signing.sign_message` and
    carries the canonical receipt bytes verbatim.
    """
    if not isinstance(receipt, ArtifactReceipt):
        raise SignedReceiptError("a receipt is signed, not a string")
    canonical = canonical_receipt_bytes(receipt)
    if not isinstance(issuer_seed, (bytes, bytearray)) or len(issuer_seed) != 32:
        raise SignedReceiptError("an issuer seed must be a 32-byte Ed25519 seed")
    from ed25519 import public_key as ed_public_key

    pubkey = ed_public_key(bytes(issuer_seed))
    message = sign_message(
        signer_id if signer_id is not None else receipt.issuer_id,
        bytes(issuer_seed),
        VERIFIER_RECIPIENT,
        {CANONICAL_PAYLOAD_KEY: canonical.hex()},
        timestamp=timestamp,
        nonce=nonce,
    )
    return SignedReceipt(
        receipt=receipt,
        message=message,
        issuer_pubkey=pubkey,
        issuer_key_id=issuer_key_id(pubkey),
    )


def verify_signed_receipt(signed: Any, issuer_pubkey: bytes) -> ArtifactReceipt:
    """Verify the issuer's signature over the receipt, then return it.

    The order is the point: the signature is checked **first**, and the
    receipt is accepted only if it verifies.  A receipt whose text was
    rewritten, a signature that was tampered with, a signature made by
    another key, and a receipt with no signature at all are all refused
    -- explicitly, by exception, never by a silent accept.

    Returns the receipt as it was signed.
    """
    if not isinstance(signed, SignedReceipt):
        raise MissingSignatureError(
            "this is not a signed receipt: an unsigned receipt cannot be "
            "accepted on the signed path"
        )
    if not isinstance(issuer_pubkey, (bytes, bytearray)) or len(issuer_pubkey) != 32:
        raise IssuerKeyError("an issuer public key must be 32 bytes")
    signature = signed.message.signature
    if not signature:
        raise MissingSignatureError("the signed receipt carries no signature")
    # 1. the signature over the signed body, under the issuer's key.
    if not verify_message(signed.message, bytes(issuer_pubkey), max_age_seconds=float("inf")):
        raise SignatureMismatchError(
            "the receipt's signature does not verify under the issuer's key: "
            "the receipt text was rewritten, or the signature was, or it was "
            "made by another issuer"
        )
    # 2. the signed body must carry this receipt's canonical bytes.
    payload = signed.message.payload
    if not isinstance(payload, dict) or CANONICAL_PAYLOAD_KEY not in payload:
        raise CanonicalReceiptError("the signed body carries no canonical receipt bytes")
    try:
        canonical = bytes.fromhex(str(payload[CANONICAL_PAYLOAD_KEY]))
    except ValueError as error:
        raise CanonicalReceiptError("the canonical receipt bytes are not hex") from error
    try:
        expected = canonical_receipt_bytes(signed.receipt)
    except CanonicalReceiptError:
        raise
    if canonical != expected:
        raise CanonicalReceiptError(
            "the signed body does not carry this receipt's canonical bytes"
        )
    # 3. the canonical bytes must parse back into this receipt.
    try:
        parsed = ArtifactReceipt.parse(canonical.decode(CANONICAL_ENCODING))
    except Exception as error:
        raise CanonicalReceiptError(f"the canonical receipt text does not parse: {error}") from error
    if parsed != signed.receipt:
        raise CanonicalReceiptError("the canonical receipt text does not match the receipt")
    # 4. the key identifier must be the one for the key we verified under.
    if signed.issuer_key_id != issuer_key_id(bytes(issuer_pubkey)):
        raise IssuerKeyError(
            "the signed receipt's issuer key identifier does not match the "
            "issuer key it was verified under"
        )
    return parsed
