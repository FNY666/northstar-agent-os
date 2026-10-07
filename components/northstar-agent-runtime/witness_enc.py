"""Simulated witness encryption (API + bookkeeping, NOT real crypto).

Witness encryption (Garg, Gentry, Sahai, Waters 2013) encrypts a message
to an *NP statement* ``x`` instead of a public key: anyone holding a
witness ``w`` with ``R(x, w) = 1`` can decrypt, and the ciphertext reveals
nothing about the message otherwise. This module keeps that exact
two-algorithm shape — ``encrypt(data, statement)`` / ``decrypt(ciphertext,
witness)`` — with a small registry of checkable NP relations:

* ``hash-preimage.v1`` — the statement's instance is a 32-byte SHA-256
  digest; a witness is valid iff ``SHA-256(witness) == instance``.
* ``prefix.v1`` — the statement's instance is a required byte prefix; a
  witness is valid iff ``witness.startswith(instance)``.

The statement is public (as in real witness encryption); only the witness
is secret. Decryption re-checks the witness against the relation named in
the ciphertext's embedded statement, then derives the sealing key from the
statement pin — so a witness for a *different* statement never decrypts,
and tampered ciphertext fails its integrity tag.

Honest scope, stated plainly:

* This is a **simulation of the interface**, the same way
  ``consensus_interface`` simulates the Raft/Paxos message half without a
  network. There are no multilinear maps, no obfuscation, no extractable
  witness encryption. Confidentiality here rests on a SHA-256-derived
  stream cipher, not on cryptographic hardness assumptions.
* Encryption is **deterministic**: the same ``(data, statement)`` always
  produces the same ciphertext. A real witness-encryption scheme is
  randomized; determinism here is a deliberate choice for testability and
  audit replay (same inputs, same bytes).
* The relations are toy NP languages chosen because their checks are
  exact and side-effect-free. The module proves *relation membership of
  the presented witness*, not that the witness was hard to find.
* Do **not** use this as a cryptographic encryption scheme. It exists so
  Northstar code can program against the encrypt-to-statement API surface
  — e.g. "this audit bundle opens only for whoever can exhibit the
  preimage" — with deterministic, testable behavior.

Everything here is offline and deterministic. No network, no clock reads,
no randomness. ``hashlib``, ``hmac``, ``dataclasses`` only.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Mapping

#: Module version.
WITNESS_ENC_VERSION = "witness-enc.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.witness-enc.v1"

#: Digest prefix used for statement pins.
_DIGEST_PREFIX = "sha256:"

#: Domain separator for all key/tag derivations.
_DOMAIN = b"northstar-witness-enc.v1"

#: Integrity tag length in bytes.
_TAG_LEN = 16

#: Supported NP relations: relation_id -> human description.
RELATIONS = (
    "hash-preimage.v1",
    "prefix.v1",
)

_AUDIT_KINDS = (
    "encrypted",
    "decrypted",
    "decrypt-refused",
)


class WitnessEncError(Exception):
    """Malformed input or broken invariant (programming error)."""


def _check_bytes(value: object, what: str) -> bytes:
    if not isinstance(value, bytes):
        raise WitnessEncError(f"{what} must be bytes, got {type(value).__name__}")
    return value


def _check_seq(seq: object, what: str = "seq") -> int:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise WitnessEncError(f"{what} must be a non-negative int")
    return seq


def _check_digest(value: object, what: str = "statement_pin") -> str:
    if (
        not isinstance(value, str)
        or not value.startswith(_DIGEST_PREFIX)
        or len(value) != len(_DIGEST_PREFIX) + 64
    ):
        raise WitnessEncError(f"{what} must be a '{_DIGEST_PREFIX}<64 hex>' pin")
    return value


def _check_relation(relation_id: object) -> str:
    if not isinstance(relation_id, str) or relation_id not in RELATIONS:
        raise WitnessEncError(f"relation_id must be one of {RELATIONS}")
    return relation_id


def _statement_pin(relation_id: str, instance: bytes) -> str:
    """``sha256:`` pin over the canonical statement body."""
    body = json.dumps(
        {"instance": instance.hex(), "relation": relation_id},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return _DIGEST_PREFIX + hashlib.sha256(body).hexdigest()


def _relation_holds(relation_id: str, instance: bytes, witness: bytes) -> bool:
    """The NP check ``R(x, w)`` for the supported relations."""
    if relation_id == "hash-preimage.v1":
        return hmac.compare_digest(hashlib.sha256(witness).digest(), instance)
    if relation_id == "prefix.v1":
        return witness.startswith(instance)
    raise WitnessEncError(f"unknown relation: {relation_id}")  # pragma: no cover


def _derive_key(statement_pin: str) -> bytes:
    """Sealing key bound to the statement pin (domain-separated)."""
    return hashlib.sha256(_DOMAIN + b"\x01" + statement_pin.encode("ascii")).digest()


def _keystream(key: bytes, length: int) -> bytes:
    """Deterministic SHA-256 counter-mode stream."""
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(
            key + b"\x02" + counter.to_bytes(8, "big")
        ).digest()
        counter += 1
    return bytes(out[:length])


def _tag(key: bytes, ciphertext: bytes) -> bytes:
    """Integrity tag over the ciphertext, bound to the sealing key."""
    return hashlib.sha256(key + b"\x03" + ciphertext).digest()[:_TAG_LEN]


@dataclass(frozen=True)
class Statement:
    """A public NP statement: a relation plus its instance.

    ``instance`` is canonical bytes. For ``hash-preimage.v1`` it must be
    the 32-byte SHA-256 digest the witness preimages; for ``prefix.v1`` it
    is the required byte prefix (possibly empty, which makes every witness
    valid — the host's choice, stated here).
    """

    relation_id: str
    instance: bytes

    def __post_init__(self) -> None:
        relation = _check_relation(self.relation_id)
        _check_bytes(self.instance, "instance")
        if relation == "hash-preimage.v1" and len(self.instance) != 32:
            raise WitnessEncError(
                "hash-preimage.v1 instance must be exactly 32 bytes (a SHA-256 digest)"
            )

    @property
    def statement_pin(self) -> str:
        """``sha256:`` pin binding relation and instance."""
        return _statement_pin(self.relation_id, self.instance)

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "relation_id": self.relation_id,
            "instance": self.instance.hex(),
            "statement_pin": self.statement_pin,
        }


@dataclass(frozen=True)
class Ciphertext:
    """The sealed output of ``encrypt``.

    Carries the *public* statement (relation + instance) it is bound to,
    the sealed bytes, and the integrity tag. The statement pin is
    re-derivable from the embedded statement; the tag is keyed by the
    statement-derived sealing key, so swapping the statement invalidates
    the tag.
    """

    statement: Statement
    ciphertext: bytes
    tag: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.statement, Statement):
            raise WitnessEncError("statement must be a Statement")
        _check_bytes(self.ciphertext, "ciphertext")
        _check_bytes(self.tag, "tag")
        if len(self.tag) != _TAG_LEN:
            raise WitnessEncError(f"tag must be exactly {_TAG_LEN} bytes")

    @property
    def statement_pin(self) -> str:
        return self.statement.statement_pin

    def as_dict(self) -> dict:
        return {
            "schema": SCHEMA_PIN,
            "statement": self.statement.as_dict(),
            "ciphertext": self.ciphertext.hex(),
            "tag": self.tag.hex(),
        }


class WitnessEnc:
    """Witness encryption scheme (simulated).

    Stateless: the same scheme instance encrypts to any statement.
    ``encrypt`` is deterministic; ``decrypt`` returns the plaintext bytes
    on a valid witness and ``None`` (policy outcome, never an exception)
    on an invalid witness or tampered ciphertext. Malformed inputs raise
    ``WitnessEncError``.
    """

    def encrypt(self, data: object, statement: object) -> Ciphertext:
        """Seal ``data`` (bytes) to the public ``statement``."""
        plaintext = _check_bytes(data, "data")
        if not isinstance(statement, Statement):
            raise WitnessEncError("statement must be a Statement")
        key = _derive_key(statement.statement_pin)
        sealed = bytes(
            b ^ k for b, k in zip(plaintext, _keystream(key, len(plaintext)))
        )
        return Ciphertext(statement=statement, ciphertext=sealed, tag=_tag(key, sealed))

    def decrypt(self, ciphertext: object, witness: object) -> bytes | None:
        """Open ``ciphertext`` with ``witness``.

        Returns the plaintext iff the witness satisfies the statement's
        relation *and* the integrity tag verifies; otherwise ``None``.
        """
        if not isinstance(ciphertext, Ciphertext):
            raise WitnessEncError("ciphertext must be a Ciphertext")
        witness_bytes = _check_bytes(witness, "witness")
        statement = ciphertext.statement
        if not _relation_holds(statement.relation_id, statement.instance, witness_bytes):
            return None
        key = _derive_key(statement.statement_pin)
        if not hmac.compare_digest(_tag(key, ciphertext.ciphertext), ciphertext.tag):
            return None
        stream = _keystream(key, len(ciphertext.ciphertext))
        return bytes(b ^ k for b, k in zip(ciphertext.ciphertext, stream))


def witness_enc_audit_event(
    kind: str, record: Mapping[str, object], seq: int
) -> dict:
    """Shape an ``audit.ndjson/1``-style record for a witness-encryption event."""
    if kind not in _AUDIT_KINDS:
        raise WitnessEncError(f"kind must be one of {_AUDIT_KINDS}")
    if not isinstance(record, Mapping):
        raise WitnessEncError("record must be a mapping")
    seq = _check_seq(seq, "audit seq")
    return {
        "schema": SCHEMA_PIN,
        "kind": f"witness-enc.{kind}",
        "record": dict(record),
        "audit_seq": seq,
    }


def main() -> None:
    we = WitnessEnc()

    # hash-preimage relation: witness is the preimage.
    preimage = b"northstar-witness"
    digest = hashlib.sha256(preimage).digest()
    stmt = Statement("hash-preimage.v1", digest)
    assert stmt.statement_pin.startswith("sha256:"), stmt.statement_pin

    ct = we.encrypt(b"secret payload", stmt)
    assert we.decrypt(ct, preimage) == b"secret payload"
    # Wrong witness cannot decrypt.
    assert we.decrypt(ct, b"wrong") is None
    # Witness for a different statement cannot decrypt.
    other = Statement("hash-preimage.v1", hashlib.sha256(b"other").digest())
    assert we.decrypt(ct, b"other") is None
    # Deterministic: same inputs, same bytes.
    assert we.encrypt(b"secret payload", stmt).ciphertext == ct.ciphertext
    # Tampered ciphertext fails the tag.
    tampered = Ciphertext(
        statement=ct.statement,
        ciphertext=bytes([ct.ciphertext[0] ^ 0xFF]) + ct.ciphertext[1:],
        tag=ct.tag,
    )
    assert we.decrypt(tampered, preimage) is None

    # prefix relation: any witness carrying the prefix opens it.
    pfx = Statement("prefix.v1", b"auth:")
    pfx_ct = we.encrypt(b"token-data", pfx)
    assert we.decrypt(pfx_ct, b"auth:token-123") == b"token-data"
    assert we.decrypt(pfx_ct, b"nope") is None

    # Empty plaintext round-trips.
    empty_ct = we.encrypt(b"", stmt)
    assert we.decrypt(empty_ct, preimage) == b""

    # Statement pin binds relation and instance.
    assert stmt.statement_pin != pfx.statement_pin

    print("witness-enc OK: encrypt, witness-gated decrypt, tamper rejection")


if __name__ == "__main__":
    main()
