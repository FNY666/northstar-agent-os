"""Encryption at rest: envelope-encrypted store interface.

Research motivation: at-rest encryption in production systems (AWS EBS
encryption, GCP persistent-disk encryption, LUKS/dm-crypt, SQL Server
TDE) is *envelope encryption*: a key-encryption key (KEK) wraps
per-object data-encryption keys (DEKs), and key *rotation* is a metadata
operation - old generations stay decryptable while new writes use the
current generation. The load-bearing policy rules are:

- A store (volume/table/bucket) has exactly one **current** key
  generation; encryption always uses the current generation.
- Decrypt accepts any non-revoked generation, so data written before a
  rotation stays readable (re-encryption is an explicit, auditable
  migration step, not silent magic).
- Rotation is cheap (bumps the generation counter); migration is the
  host-driven ``reencrypt()`` walk over old-generation blocks.
- Revocation is terminal and immediate (crypto-erasure shape): a
  revoked store encrypts and decrypts nothing.

This module pins that shape as a deterministic, network-free state
machine. It is *not* a crypto library: key material is derived from
SHA-256 KDF chains (deterministic, no entropy source), sealing is a
SHA-256 keystream under an HMAC integrity tag, and the nonce is derived
from the block identity (one block per ``data_id``, so nonce reuse
cannot occur). The *policy* - which generation encrypts, which
generations decrypt, what rotation and revocation do - is the part the
runtime depends on, and it is pinned here.

Public API:

- ``EncryptionAtRest()`` -- in-memory store registry; all operations
  take caller-supplied int seqs (no wall-clock), RLock-guarded.
- ``create_store(store_id, seq) -> StoreRecord`` -- registers a store at
  generation 1, state ``active``. Duplicate ids fail closed.
- ``encrypt(store_id, data_id, plaintext, seq) -> EncryptedBlock`` --
  seals with the store's current generation. Duplicate ``data_id``
  refused (re-encryption has its own entry point).
- ``decrypt(store_id, data_id, seq) -> bytes`` -- verifies the HMAC tag
  against the block's own generation KEK, then unseals. Tamper or
  revoked stores fail closed.
- ``rotate(store_id, seq) -> RotationRecord`` -- bumps the generation;
  old blocks keep decrypting (decrypt-only).
- ``reencrypt(store_id, data_id, seq) -> EncryptedBlock`` -- migrates
  one block to the current generation; the old-generation envelope is
  superseded.
- ``revoke(store_id, seq) -> RevocationRecord`` -- terminal; both
  directions and rotation refuse afterwards.
- ``StoreRecord`` / ``EncryptedBlock`` / ``RotationRecord`` /
  ``RevocationRecord`` -- frozen records with ``as_dict()`` and
  ``sha256:`` digest pins. Block records pin the DEK digest, never the
  key material.
- ``encryption_at_rest_audit_event(kind, seq, ...)`` --
  ``audit.ndjson/1`` shaped records with fixed vocabulary
  (``store-created`` / ``store-rotated`` / ``store-revoked`` /
  ``encrypted`` / ``reencrypted`` / ``decrypted`` / ``rejected``).

Honest scope: simulated - the keystream is SHA-256, key material is
KDF-derived and visible to the host (no HSM, no secure channel, no
access policy beyond the state machine); confidentiality against the
host operator is not claimed. Deterministic on purpose: same inputs give
bit-identical envelopes, which keeps audit snapshots reproducible.
This pins the *interface shape*; real KMS/HSM backends drop in without
changing call sites. It does not duplicate ``kms_interface``: that
module owns *key lifecycle*; this module owns *at-rest envelope policy*
(stores, generations, block envelopes, migration) and derives its keys
internally rather than registering aliases.
"""

from __future__ import annotations

import hashlib
import hmac
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

__version__ = "encryption-at-rest.v1"
__schema__ = "northstar.encryption-at-rest.v1"

_DOMAIN = b"northstar.encryption-at-rest.v1"
_MAX_PLAINTEXT_BYTES = 1 << 20  # 1 MiB per block; DoS guardrail.

_STATE_ACTIVE = "active"
_STATE_REVOKED = "revoked"

_EAR_EVENT_KINDS = (
    "store-created",
    "store-rotated",
    "store-revoked",
    "encrypted",
    "reencrypted",
    "decrypted",
    "rejected",
)


class EncryptionAtRestError(Exception):
    """Base error for the encryption-at-rest interface."""


class BadInputError(EncryptionAtRestError):
    """Malformed id, payload, or parameter; refused fail-closed."""


class UnknownStoreError(EncryptionAtRestError):
    """No store registered under this id."""


class DuplicateStoreError(EncryptionAtRestError):
    """Store id already registered; creation refused."""


class UnknownBlockError(EncryptionAtRestError):
    """No block for this (store_id, data_id)."""


class AlreadyEncryptedError(EncryptionAtRestError):
    """A block already exists for this data_id; use reencrypt()."""


class IntegrityError(EncryptionAtRestError):
    """Envelope tag mismatch; never silently decrypted."""


class StoreRevokedError(EncryptionAtRestError):
    """Store is revoked; all operations refuse."""


class SeqOrderError(EncryptionAtRestError):
    """Mutation seqs must be strictly increasing."""


def _fail_closed_str(value: object, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise BadInputError(f"{name} must be a non-empty str")
    if len(value) > 256:
        raise BadInputError(f"{name} must be at most 256 chars")
    return value


def _fail_closed_seq(seq: object, name: str = "seq") -> int:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise BadInputError(f"{name} must be a non-negative int")
    return seq


def _fail_closed_plaintext(value: object) -> bytes:
    if not isinstance(value, bytes):
        raise BadInputError("plaintext must be bytes")
    if len(value) > _MAX_PLAINTEXT_BYTES:
        raise BadInputError("plaintext exceeds 1 MiB cap")
    return value


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _pin(data: bytes) -> str:
    return "sha256:" + _sha256(data).hex()


def _kdf(context: bytes, *parts: bytes) -> bytes:
    """Domain-separated deterministic key derivation."""
    acc = _DOMAIN + b"/" + context
    for part in parts:
        acc += b"/" + _sha256(part)
    return _sha256(acc)


def _kek(store_id: str, generation: int) -> bytes:
    """Key-encryption key for one store generation (never leaves the module)."""
    return _kdf(b"kek", store_id.encode("utf-8"), generation.to_bytes(8, "big"))


def _dek(kek: bytes, data_id: str) -> bytes:
    """Per-block data-encryption key wrapped by the generation KEK."""
    return _kdf(b"dek", kek, data_id.encode("utf-8"))


def _mac_key(kek: bytes) -> bytes:
    return _kdf(b"mac", kek)


def _nonce(store_id: str, generation: int, data_id: str) -> bytes:
    """Deterministic nonce bound to the block identity (16 bytes)."""
    return _kdf(b"nonce", store_id.encode("utf-8"),
                generation.to_bytes(8, "big"),
                data_id.encode("utf-8"))[:16]


def _keystream(dek: bytes, nonce: bytes, length: int) -> bytes:
    """SHA-256 counter-mode keystream (simulated, deterministic)."""
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += _sha256(dek + b"/stream/" + nonce + counter.to_bytes(8, "big"))
        counter += 1
    return bytes(out[:length])


@dataclass(frozen=True)
class StoreRecord:
    """Immutable snapshot of one store's lifecycle state."""
    store_id: str
    generation: int
    state: str
    created_seq: int
    schema: str = field(default=__schema__, repr=False)

    def __post_init__(self) -> None:
        _fail_closed_str(self.store_id, "store_id")
        if isinstance(self.generation, bool) or not isinstance(self.generation, int) \
                or self.generation < 1:
            raise BadInputError("generation must be a positive int")
        if self.state not in (_STATE_ACTIVE, _STATE_REVOKED):
            raise BadInputError("unknown store state")
        _fail_closed_seq(self.created_seq, "created_seq")
        if self.schema != __schema__:
            raise BadInputError("schema pin mismatch")

    def as_dict(self) -> dict:
        return {
            "store_id": self.store_id,
            "generation": self.generation,
            "state": self.state,
            "created_seq": self.created_seq,
            "module": __version__,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class EncryptedBlock:
    """One sealed block: envelope bound to a store generation.

    The DEK is pinned (``dek_pin``), never stored; the KEK that wrapped
    it is re-derived at decrypt time from the store id + generation.
    """
    store_id: str
    data_id: str
    generation: int
    nonce: bytes
    ciphertext: bytes
    tag: bytes
    dek_pin: str
    seq: int
    schema: str = field(default=__schema__, repr=False)

    def __post_init__(self) -> None:
        _fail_closed_str(self.store_id, "store_id")
        _fail_closed_str(self.data_id, "data_id")
        if isinstance(self.generation, bool) or not isinstance(self.generation, int) \
                or self.generation < 1:
            raise BadInputError("generation must be a positive int")
        for name, val in (("nonce", self.nonce), ("tag", self.tag)):
            if not isinstance(val, bytes) or not val:
                raise BadInputError(f"{name} must be non-empty bytes")
        if not isinstance(self.ciphertext, bytes):
            raise BadInputError("ciphertext must be bytes")
        if not isinstance(self.dek_pin, str) or not self.dek_pin.startswith("sha256:"):
            raise BadInputError("dek_pin must be a sha256: pin")
        _fail_closed_seq(self.seq, "seq")
        if self.schema != __schema__:
            raise BadInputError("schema pin mismatch")

    def as_dict(self) -> dict:
        return {
            "store_id": self.store_id,
            "data_id": self.data_id,
            "generation": self.generation,
            "digest": _pin(self.nonce + self.ciphertext),
            "dek_pin": self.dek_pin,
            "seq": self.seq,
            "module": __version__,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class RotationRecord:
    """Evidence that a store moved from one generation to the next."""
    store_id: str
    old_generation: int
    new_generation: int
    seq: int
    schema: str = field(default=__schema__, repr=False)

    def __post_init__(self) -> None:
        _fail_closed_str(self.store_id, "store_id")
        for name, val in (("old_generation", self.old_generation),
                          ("new_generation", self.new_generation)):
            if isinstance(val, bool) or not isinstance(val, int) or val < 1:
                raise BadInputError(f"{name} must be a positive int")
        if self.new_generation != self.old_generation + 1:
            raise BadInputError("rotation must advance exactly one generation")
        _fail_closed_seq(self.seq, "seq")
        if self.schema != __schema__:
            raise BadInputError("schema pin mismatch")

    def as_dict(self) -> dict:
        return {
            "store_id": self.store_id,
            "old_generation": self.old_generation,
            "new_generation": self.new_generation,
            "seq": self.seq,
            "module": __version__,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class RevocationRecord:
    """Terminal evidence: store revoked (crypto-erasure shape)."""
    store_id: str
    seq: int
    schema: str = field(default=__schema__, repr=False)

    def __post_init__(self) -> None:
        _fail_closed_str(self.store_id, "store_id")
        _fail_closed_seq(self.seq, "seq")
        if self.schema != __schema__:
            raise BadInputError("schema pin mismatch")

    def as_dict(self) -> dict:
        return {
            "store_id": self.store_id,
            "seq": self.seq,
            "module": __version__,
            "schema": self.schema,
        }


class EncryptionAtRest:
    """In-memory registry of at-rest encrypted stores.

    All mutation methods take caller-supplied int seqs (no wall-clock)
    which must be strictly increasing; failed mutations consume their
    seq (fail-closed ledger position). Plaintext and key material never
    enter records or the audit trail - only ids and ``sha256:`` pins.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = -1
        self._stores: Dict[str, StoreRecord] = {}
        self._blocks: Dict[Tuple[str, str], EncryptedBlock] = {}
        self._audit_log: List[dict] = []

    # -- internals -----------------------------------------------------

    def _claim(self, seq: object) -> int:
        """Validate and consume a mutation seq (consumed even on failure)."""
        seq = _fail_closed_seq(seq)
        with self._lock:
            if seq <= self._last_seq:
                raise SeqOrderError(
                    f"seq must be strictly increasing (last={self._last_seq})")
            self._last_seq = seq
        return seq

    def _emit(self, kind: str, seq: int, **fields: object) -> None:
        with self._lock:
            self._audit_log.append(
                encryption_at_rest_audit_event(kind, seq, **fields))

    def _get_store(self, store_id: str) -> StoreRecord:
        store = self._stores.get(store_id)
        if store is None:
            raise UnknownStoreError(f"unknown store: {store_id!r}")
        if store.state == _STATE_REVOKED:
            raise StoreRevokedError(f"store revoked: {store_id!r}")
        return store

    def _get_block(self, store_id: str, data_id: str) -> EncryptedBlock:
        block = self._blocks.get((store_id, data_id))
        if block is None:
            raise UnknownBlockError(
                f"no block for store={store_id!r} data={data_id!r}")
        return block

    @staticmethod
    def _seal(store_id: str, data_id: str, generation: int,
              plaintext: bytes) -> EncryptedBlock:
        """Build an envelope for plaintext under a generation's KEK."""
        kek = _kek(store_id, generation)
        dek = _dek(kek, data_id)
        nonce = _nonce(store_id, generation, data_id)
        ciphertext = bytes(a ^ b for a, b in
                           zip(plaintext, _keystream(dek, nonce, len(plaintext))))
        tag = hmac.new(_mac_key(kek), nonce + ciphertext,
                       hashlib.sha256).digest()
        return EncryptedBlock(
            store_id=store_id,
            data_id=data_id,
            generation=generation,
            nonce=nonce,
            ciphertext=ciphertext,
            tag=tag,
            dek_pin=_pin(dek),
            seq=0,  # patched by the caller after the seq is known
        )

    @staticmethod
    def _open(block: EncryptedBlock) -> bytes:
        """Verify the tag against the block's own generation, then unseal."""
        kek = _kek(block.store_id, block.generation)
        expected = hmac.new(_mac_key(kek),
                            block.nonce + block.ciphertext,
                            hashlib.sha256).digest()
        if not hmac.compare_digest(expected, block.tag):
            raise IntegrityError("envelope tag mismatch")
        dek = _dek(kek, block.data_id)
        if _pin(dek) != block.dek_pin:
            raise IntegrityError("dek pin mismatch")
        return bytes(a ^ b for a, b in
                     zip(block.ciphertext,
                         _keystream(dek, block.nonce, len(block.ciphertext))))

    # -- mutations -----------------------------------------------------

    def create_store(self, store_id: str, seq: int) -> StoreRecord:
        seq = self._claim(seq)
        try:
            _fail_closed_str(store_id, "store_id")
            with self._lock:
                if store_id in self._stores:
                    raise DuplicateStoreError(f"store exists: {store_id!r}")
                record = StoreRecord(store_id=store_id, generation=1,
                                     state=_STATE_ACTIVE, created_seq=seq)
                self._stores[store_id] = record
            self._emit("store-created", seq, store_id=store_id, generation=1)
            return record
        except EncryptionAtRestError:
            self._emit("rejected", seq, op="create_store",
                       store_id=str(store_id))
            raise

    def encrypt(self, store_id: str, data_id: str, plaintext: bytes,
                seq: int) -> EncryptedBlock:
        seq = self._claim(seq)
        try:
            store = self._get_store(_fail_closed_str(store_id, "store_id"))
            _fail_closed_str(data_id, "data_id")
            _fail_closed_plaintext(plaintext)
            with self._lock:
                if (store_id, data_id) in self._blocks:
                    raise AlreadyEncryptedError(
                        f"block exists: {store_id!r}/{data_id!r}")
                sealed = self._seal(store_id, data_id, store.generation,
                                    plaintext)
                block = EncryptedBlock(
                    store_id=sealed.store_id, data_id=sealed.data_id,
                    generation=sealed.generation, nonce=sealed.nonce,
                    ciphertext=sealed.ciphertext, tag=sealed.tag,
                    dek_pin=sealed.dek_pin, seq=seq)
                self._blocks[(store_id, data_id)] = block
            self._emit("encrypted", seq, store_id=store_id, data_id=data_id,
                       generation=store.generation)
            return block
        except EncryptionAtRestError:
            self._emit("rejected", seq, op="encrypt",
                       store_id=str(store_id), data_id=str(data_id))
            raise

    def decrypt(self, store_id: str, data_id: str, seq: int) -> bytes:
        seq = self._claim(seq)
        try:
            store = self._get_store(_fail_closed_str(store_id, "store_id"))
            _fail_closed_str(data_id, "data_id")
            block = self._get_block(store_id, data_id)
            plaintext = self._open(block)
            self._emit("decrypted", seq, store_id=store_id, data_id=data_id,
                       generation=block.generation)
            return plaintext
        except EncryptionAtRestError:
            self._emit("rejected", seq, op="decrypt",
                       store_id=str(store_id), data_id=str(data_id))
            raise

    def rotate(self, store_id: str, seq: int) -> RotationRecord:
        seq = self._claim(seq)
        try:
            store = self._get_store(_fail_closed_str(store_id, "store_id"))
            record = RotationRecord(store_id=store_id,
                                    old_generation=store.generation,
                                    new_generation=store.generation + 1,
                                    seq=seq)
            with self._lock:
                self._stores[store_id] = StoreRecord(
                    store_id=store.store_id,
                    generation=store.generation + 1,
                    state=store.state, created_seq=store.created_seq)
            self._emit("store-rotated", seq, store_id=store_id,
                       old_generation=record.old_generation,
                       new_generation=record.new_generation)
            return record
        except EncryptionAtRestError:
            self._emit("rejected", seq, op="rotate",
                       store_id=str(store_id))
            raise

    def reencrypt(self, store_id: str, data_id: str,
                  seq: int) -> EncryptedBlock:
        """Migrate one block to the store's current generation.

        Decrypts under the block's recorded generation (fail-closed on
        tamper), then seals fresh under the current generation.
        """
        seq = self._claim(seq)
        try:
            store = self._get_store(_fail_closed_str(store_id, "store_id"))
            _fail_closed_str(data_id, "data_id")
            block = self._get_block(store_id, data_id)
            plaintext = self._open(block)
            sealed = self._seal(store_id, data_id, store.generation,
                                plaintext)
            new_block = EncryptedBlock(
                store_id=sealed.store_id, data_id=sealed.data_id,
                generation=sealed.generation, nonce=sealed.nonce,
                ciphertext=sealed.ciphertext, tag=sealed.tag,
                dek_pin=sealed.dek_pin, seq=seq)
            with self._lock:
                self._blocks[(store_id, data_id)] = new_block
            self._emit("reencrypted", seq, store_id=store_id,
                       data_id=data_id,
                       old_generation=block.generation,
                       new_generation=store.generation)
            return new_block
        except EncryptionAtRestError:
            self._emit("rejected", seq, op="reencrypt",
                       store_id=str(store_id), data_id=str(data_id))
            raise

    def revoke(self, store_id: str, seq: int) -> RevocationRecord:
        """Terminal revocation (crypto-erasure shape): the store stops
        encrypting and decrypting immediately."""
        seq = self._claim(seq)
        try:
            store = self._get_store(_fail_closed_str(store_id, "store_id"))
            record = RevocationRecord(store_id=store_id, seq=seq)
            with self._lock:
                self._stores[store_id] = StoreRecord(
                    store_id=store.store_id, generation=store.generation,
                    state=_STATE_REVOKED, created_seq=store.created_seq)
            self._emit("store-revoked", seq, store_id=store_id)
            return record
        except EncryptionAtRestError:
            self._emit("rejected", seq, op="revoke",
                       store_id=str(store_id))
            raise

    # -- views ---------------------------------------------------------

    def store(self, store_id: str) -> StoreRecord:
        store = self._stores.get(store_id)
        if store is None:
            raise UnknownStoreError(f"unknown store: {store_id!r}")
        return store

    def block(self, store_id: str, data_id: str) -> EncryptedBlock:
        return self._get_block(store_id, data_id)

    def store_ids(self) -> List[str]:
        with self._lock:
            return sorted(self._stores)

    def block_ids(self, store_id: str) -> List[str]:
        with self._lock:
            return sorted(d for (s, d) in self._blocks if s == store_id)

    def stats(self) -> dict:
        with self._lock:
            return {
                "stores": len(self._stores),
                "blocks": len(self._blocks),
                "revoked": sum(1 for s in self._stores.values()
                               if s.state == _STATE_REVOKED),
            }

    def audit_log(self) -> List[dict]:
        with self._lock:
            return list(self._audit_log)


def encryption_at_rest_audit_event(kind: str, seq: int,
                                   **fields: object) -> dict:
    """Audit-shaped record for an encryption-at-rest observation.

    Carries ids and digest pins only; plaintext and key material never
    cross the audit boundary.
    """
    if kind not in _EAR_EVENT_KINDS:
        raise ValueError("unknown kind")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise ValueError("seq must be a non-negative int")
    record = {
        "event": "encryption-at-rest",
        "kind": kind,
        "audit_seq": seq,
        "schema": "audit.ndjson/1",
    }
    record.update(fields)
    return record


def main() -> None:
    ear = EncryptionAtRest()
    s = ear.create_store("vault", 1)
    assert s.generation == 1 and s.state == "active"
    b1 = ear.encrypt("vault", "row-1", b"secret-bytes", 2)
    assert ear.decrypt("vault", "row-1", 3) == b"secret-bytes"
    rot = ear.rotate("vault", 4)
    assert (rot.old_generation, rot.new_generation) == (1, 2)
    b2 = ear.encrypt("vault", "row-2", b"new-secret", 5)
    assert b2.generation == 2
    assert ear.decrypt("vault", "row-1", 6) == b"secret-bytes"  # old gen ok
    mig = ear.reencrypt("vault", "row-1", 7)
    assert mig.generation == 2
    assert ear.decrypt("vault", "row-1", 8) == b"secret-bytes"
    ear.revoke("vault", 9)
    try:
        ear.decrypt("vault", "row-1", 10)
        raise AssertionError("revoked decrypt must refuse")
    except StoreRevokedError:
        pass
    kinds = {e["kind"] for e in ear.audit_log()}
    assert {"store-created", "store-rotated", "store-revoked", "encrypted",
            "reencrypted", "decrypted", "rejected"} <= kinds
    print("encryption-at-rest OK: store, encrypt, rotate, reencrypt, "
          "revoke, pins, audit")


if __name__ == "__main__":
    main()
