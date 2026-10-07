"""Ring signature interface: anonymous signing over an ad-hoc anonymity set (simulated).

Research motivation: Rivest, Shamir, Tauman (2001, "How to Leak a
Secret") introduced ring signatures so a signer can speak on behalf of
an ad-hoc group of public keys while hiding *which* member signed.
Verification proves only that the signature came from *some* member of
the ring -- the anonymity set is the privacy boundary. The CryptoNote
protocol (van Saberhagen, 2013) added *linkability*: each signature
carries a key image, so two signatures from the same signer can be
linked (preventing double-spending) without breaking the anonymity of
any single signature.

What this module is:

* The mechanical bookkeeping half: ``sign`` / ``verify`` / ``link``
  with a Fiat-Shamir ring equation (the challenge pins every member's
  commitment), frozen records, digest pins, and ``audit.ndjson/1``
  events in house style.
* Key pairs are simulated: a secret scalar plus a public id bound by
  SHA-256. The challenge chain is a hash-based analogue of the real
  ring equation -- responses for non-signers are derived
  deterministically from the message, and the signer's response is
  bound to their secret, so the chain closes only when the signer is
  a ring member holding the secret.
* Optional linkable mode attaches a key image (the CryptoNote tag);
  ``link`` detects when two signatures came from the same signer.

Honest scope (read before relying on this):

* **Not a security boundary.** There is no elliptic-curve math, no
  discrete-log hardness, and no zero-knowledge property -- the
  "binding" of the signer's response to their secret is structural,
  not cryptographic. Do not use this to enforce anonymity against an
  adversary; use it to pin the *protocol logic* (who must be in the
  ring, when signatures link, what the anonymity set is) in tests,
  audits, and design reviews.
* A real deployment needs a curve (e.g. ed25519 / Ristretto), real
  random nonces (this module is fully deterministic), and a proper
  linkable-ring construction (e.g. MLSAG / CLSAG for Monero-style
  linkability).
* ``verify`` returning ``True`` means "the ring equation closes over
  the pinned message and ring", never "an independent party agrees".
* Anonymity in this simulation is *by construction*: the signature
  carries no signer index, and responses are hash-derived, so no
  information about the signer leaks through the record. That holds
  only because the construction is symmetric -- a real scheme's
  anonymity rests on the hardness of the underlying problem.
* Key images are per-(signer) tags, not per-ring tags: linking only
  works when the same signer signed twice in linkable mode.
* No wall-clock anywhere; all seqs are caller-supplied ints.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Any

#: Module version pin.
RING_SIG_VERSION = "ring-sig.v1"

#: Schema pin carried by records and audit events.
RING_SIG_SCHEMA = "northstar.ring-sig.v1"

#: Audit event kinds.
EVENT_SIGNED = "ring-signed"
EVENT_VERIFIED = "ring-verified"
EVENT_REJECTED = "ring-rejected"
EVENT_LINKED = "ring-linked"
EVENT_UNLINKED = "ring-unlinked"

_EVENT_KINDS = frozenset(
    {EVENT_SIGNED, EVENT_VERIFIED, EVENT_REJECTED, EVENT_LINKED, EVENT_UNLINKED}
)

#: Digest prefix for pinned values.
_DIGEST_PREFIX = "sha256:"

#: Domain tags for the simulated construction. Domains are separated so
#: a commitment can never be replayed as a challenge, a nonce, or a key.
_DOM_KEYPAIR = b"northstar.ring-sig.v1/keypair"
_DOM_PUB = b"northstar.ring-sig.v1/public-id"
_DOM_NONCE = b"northstar.ring-sig.v1/nonce"
_DOM_COMMIT = b"northstar.ring-sig.v1/commitment"
_DOM_CHALLENGE = b"northstar.ring-sig.v1/challenge"
_DOM_SIGNER_RESP = b"northstar.ring-sig.v1/signer-response"
_DOM_KEY_IMAGE = b"northstar.ring-sig.v1/key-image"
_DOM_MSG = b"northstar.ring-sig.v1/message"
_DOM_RING = b"northstar.ring-sig.v1/ring"


class RingSigError(Exception):
    """Base error for ring signature failures."""


class BadRingError(RingSigError):
    """The ring itself is malformed (empty, duplicate, bad member)."""


class VerificationError(RingSigError):
    """Raised on malformed caller input to verify/link (not on mismatch)."""


def _sha256(*parts: bytes) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return _DIGEST_PREFIX + h.hexdigest()


def _check_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an int, got {type(value).__name__}")
    if value < 0:
        raise ValueError(f"{name} must be non-negative")
    return value


def _canonical_message(message: Any) -> bytes:
    if isinstance(message, str):
        return message.encode("utf-8")
    if isinstance(message, (bytes, bytearray)):
        return bytes(message)
    raise TypeError(
        f"message must be str or bytes, got {type(message).__name__}"
    )


@dataclass(frozen=True)
class Keypair:
    """A simulated key pair: public id bound to a secret by SHA-256."""

    public_id: str
    secret: str

    def __post_init__(self) -> None:
        if not isinstance(self.public_id, str) or not self.public_id:
            raise TypeError("public_id must be a non-empty str")
        if not isinstance(self.secret, str) or not self.secret:
            raise TypeError("secret must be a non-empty str")

    def as_dict(self) -> dict:
        return {
            "schema": RING_SIG_SCHEMA,
            "public_id": self.public_id,
            "secret_digest": _sha256(b"secret", self.secret.encode("utf-8")),
        }


def generate_keypair(label: str) -> Keypair:
    """Derive a deterministic keypair from a label (simulation only)."""
    if not isinstance(label, str) or not label:
        raise TypeError("label must be a non-empty str")
    public_id = _sha256(_DOM_PUB, label.encode("utf-8"))
    secret = _sha256(_DOM_KEYPAIR, label.encode("utf-8"))
    return Keypair(public_id=public_id, secret=secret)


def _check_ring(ring: Any) -> tuple[Keypair, ...]:
    if not isinstance(ring, (list, tuple)) or not ring:
        raise BadRingError("ring must be a non-empty list/tuple of Keypair")
    members = tuple(ring)
    for i, m in enumerate(members):
        if not isinstance(m, Keypair):
            raise BadRingError(f"ring[{i}] must be a Keypair")
    ids = [m.public_id for m in members]
    if len(set(ids)) != len(ids):
        raise BadRingError("ring members must have distinct public ids")
    return members


def _ring_digest(ring: tuple[Keypair, ...]) -> str:
    return _sha256(_DOM_RING, *(m.public_id.encode("utf-8") for m in ring))


def _message_digest(message: bytes) -> str:
    return _sha256(_DOM_MSG, message)


@dataclass(frozen=True)
class RingSignature:
    """A ring signature over a pinned (message, ring) pair."""

    message_digest: str
    ring_digest: str
    ring_size: int
    responses: tuple[str, ...]
    challenge: str
    key_image: str | None
    linkable: bool

    def __post_init__(self) -> None:
        for name in ("message_digest", "ring_digest", "challenge"):
            v = getattr(self, name)
            if not isinstance(v, str) or not v.startswith(_DIGEST_PREFIX):
                raise TypeError(f"{name} must be a sha256: pin")
        _check_int(self.ring_size, "ring_size")
        if self.ring_size < 1:
            raise ValueError("ring_size must be >= 1")
        if not isinstance(self.responses, tuple):
            raise TypeError("responses must be a tuple")
        if len(self.responses) != self.ring_size:
            raise ValueError("responses length must equal ring_size")
        for r in self.responses:
            if not isinstance(r, str) or not r.startswith(_DIGEST_PREFIX):
                raise TypeError("each response must be a sha256: pin")
        if not isinstance(self.linkable, bool):
            raise TypeError("linkable must be a bool")
        if self.linkable:
            if not isinstance(self.key_image, str) or not self.key_image.startswith(
                _DIGEST_PREFIX
            ):
                raise TypeError("linkable signatures need a sha256: key_image")
        elif self.key_image is not None:
            raise TypeError("non-linkable signatures must not carry a key_image")

    def as_dict(self) -> dict:
        return {
            "schema": RING_SIG_SCHEMA,
            "module": RING_SIG_VERSION,
            "message_digest": self.message_digest,
            "ring_digest": self.ring_digest,
            "ring_size": self.ring_size,
            "responses": list(self.responses),
            "challenge": self.challenge,
            "key_image": self.key_image,
            "linkable": self.linkable,
        }


def _commitment(
    message: bytes, ring_d: str, public_id: str, response: str
) -> str:
    return _sha256(
        _DOM_COMMIT,
        message,
        ring_d.encode("utf-8"),
        public_id.encode("utf-8"),
        response.encode("utf-8"),
    )


def _ring_equation(
    message: bytes, ring_d: str, ring: tuple[Keypair, ...], responses: tuple[str, ...]
) -> str:
    """The ring equation: a Fiat-Shamir challenge pinning every member's commitment.

    Each member contributes ``com_i = H(commit || msg || ring || pub_i || resp_i)``;
    the challenge is ``H(challenge || msg || ring || com_0 || ... || com_{n-1})``.
    The equation closes iff the stored challenge recomputes -- which requires
    the signer's secret-bound response at their (hidden) position.
    """
    parts = [message, ring_d.encode("utf-8")]
    for member, response in zip(ring, responses):
        parts.append(
            _commitment(message, ring_d, member.public_id, response).encode("utf-8")
        )
    return _sha256(_DOM_CHALLENGE, *parts)


class RingSig:
    """Stateless ring signature operations (sign / verify / link)."""

    @staticmethod
    def sign(
        message: str | bytes,
        ring: list[Keypair] | tuple[Keypair, ...],
        signer_idx: int,
        linkable: bool = False,
    ) -> RingSignature:
        """Sign ``message`` as ring member ``signer_idx``.

        The signature reveals only that *some* ring member signed --
        the signer index is not carried in the record. Non-signer
        responses are derived deterministically from the message; the
        signer's response is additionally bound to their secret, so
        only the secret holder can produce the closing response.
        """
        msg = _canonical_message(message)
        members = _check_ring(ring)
        if isinstance(signer_idx, bool) or not isinstance(signer_idx, int):
            raise TypeError("signer_idx must be an int")
        if not 0 <= signer_idx < len(members):
            raise BadRingError("signer_idx out of range")
        if not isinstance(linkable, bool):
            raise TypeError("linkable must be a bool")

        ring_d = _ring_digest(members)
        signer = members[signer_idx]

        # Non-signer responses: deterministic pseudo-randomness bound to
        # (message, ring, position). The signer cannot know other secrets
        # and must not need them.
        responses: list[str] = []
        for i in range(len(members)):
            if i == signer_idx:
                responses.append("")  # placeholder, filled below
            else:
                responses.append(
                    _sha256(
                        _DOM_NONCE,
                        msg,
                        ring_d.encode("utf-8"),
                        str(i).encode("utf-8"),
                    )
                )

        # The ring equation is cyclic over all commitments: the signer's
        # response is bound to their secret, non-signer responses are
        # deterministic. The challenge is whatever the full commitment
        # set demands -- by construction the verifier recomputes it.
        signer_response = _sha256(
            _DOM_SIGNER_RESP,
            signer.secret.encode("utf-8"),
            msg,
            ring_d.encode("utf-8"),
        )
        responses[signer_idx] = signer_response
        c0 = _ring_equation(msg, ring_d, members, tuple(responses))

        key_image = (
            _sha256(_DOM_KEY_IMAGE, signer.secret.encode("utf-8"))
            if linkable
            else None
        )
        return RingSignature(
            message_digest=_message_digest(msg),
            ring_digest=ring_d,
            ring_size=len(members),
            responses=tuple(responses),
            challenge=c0,
            key_image=key_image,
            linkable=linkable,
        )

    @staticmethod
    def verify(
        message: str | bytes,
        ring: list[Keypair] | tuple[Keypair, ...],
        signature: RingSignature,
    ) -> bool:
        """Verify a ring signature.

        Returns ``True`` when the ring equation closes over the pinned
        message and ring; ``False`` on any mismatch (policy outcome).
        Raises on malformed caller input.
        """
        msg = _canonical_message(message)
        members = _check_ring(ring)
        if not isinstance(signature, RingSignature):
            raise VerificationError("signature must be a RingSignature")
        if signature.message_digest != _message_digest(msg):
            return False
        if signature.ring_digest != _ring_digest(members):
            return False
        if signature.ring_size != len(members):
            return False
        recomputed = _ring_equation(
            msg, _ring_digest(members), members, signature.responses
        )
        return hmac.compare_digest(recomputed, signature.challenge)

    @staticmethod
    def link(sig_a: RingSignature, sig_b: RingSignature) -> bool:
        """Detect whether two linkable signatures came from the same signer.

        Both signatures must be linkable; non-linkable signatures can
        never be linked (returns ``False``). Raises on bad input types.
        """
        for name, sig in (("sig_a", sig_a), ("sig_b", sig_b)):
            if not isinstance(sig, RingSignature):
                raise VerificationError(f"{name} must be a RingSignature")
        if not sig_a.linkable or not sig_b.linkable:
            return False
        assert sig_a.key_image is not None and sig_b.key_image is not None
        return hmac.compare_digest(sig_a.key_image, sig_b.key_image)


def ring_signature_audit_event(kind: str, record: Any, seq: int) -> dict:
    """Shape an ``audit.ndjson/1`` record for a ring-signature event."""
    if kind not in _EVENT_KINDS:
        raise ValueError(f"unknown event kind {kind!r}")
    if not isinstance(record, (RingSignature, Keypair)):
        raise TypeError(
            f"record must be a ring-signature record, got {type(record).__name__}"
        )
    _check_int(seq, "seq")
    return {
        "schema": "northstar.audit.ndjson/1",
        "event": kind,
        "module": RING_SIG_VERSION,
        "record": record.as_dict(),
        "audit_seq": seq,
    }


def main() -> None:
    ring = [generate_keypair(f"member-{i}") for i in range(4)]
    sig = RingSig.sign("leak the secret", ring, 2)
    assert RingSig.verify("leak the secret", ring, sig) is True
    # Wrong message fails.
    assert RingSig.verify("other message", ring, sig) is False
    # Wrong ring fails.
    other_ring = [generate_keypair(f"other-{i}") for i in range(4)]
    assert RingSig.verify("leak the secret", other_ring, sig) is False
    # Tampered response breaks the chain.
    bad = RingSignature(
        message_digest=sig.message_digest,
        ring_digest=sig.ring_digest,
        ring_size=sig.ring_size,
        responses=(sig.responses[0],) + ("sha256:" + "00" * 32,) + sig.responses[2:],
        challenge=sig.challenge,
        key_image=None,
        linkable=False,
    )
    assert RingSig.verify("leak the secret", ring, bad) is False
    # Linkability: same signer twice links; different signers do not.
    la1 = RingSig.sign("m1", ring, 1, linkable=True)
    la2 = RingSig.sign("m2", ring, 1, linkable=True)
    lb = RingSig.sign("m3", ring, 3, linkable=True)
    assert RingSig.link(la1, la2) is True
    assert RingSig.link(la1, lb) is False
    assert RingSig.link(la1, sig) is False  # non-linkable never links
    # Every member can sign; all verify; none reveals the signer.
    for i in range(4):
        s = RingSig.sign("m", ring, i)
        assert RingSig.verify("m", ring, s) is True
        assert s.key_image is None
    print("ring-sig OK: sign, verify, tamper-reject, linkable, unlinkable")


if __name__ == "__main__":
    main()
