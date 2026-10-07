"""HSM operations ledger: book declared hardware-security-module operations.

Distinct from ``hsm_interface.py`` (which simulates the in-process crypto
boundary: key material derived and used inside a vault): this module is
the *operations ledger* layer - it books declared key lifecycles and
declared sign/decrypt operations against named HSM partitions without
performing any cryptography itself and without ever touching key
material.

* **Partitions** - ``register_partition()`` declares one HSM slot in a
  fleet. Partition ids are never recycled.
* **Key lifecycle** - ``generate()`` books a key minted inside a
  partition (material pin only - raw key material never enters a
  record); ``revoke()`` is terminal: revoked ids are retired forever
  and refuse ``sign()``/``decrypt()`` fail-closed.
* **Operations** - ``sign()`` / ``decrypt()`` book declared operations
  against a live key; the message/ciphertext travels as a ``sha256:``
  digest pin only. Algorithm usage is pinned: signing keys
  (``ed25519-sim``, ``hmac-sha256``) sign; encryption keys
  (``rsa-oaep-sim``, ``aes-256-gcm-sim``) decrypt; cross-use is refused
  fail-closed (mirroring the crypto layer's cross-key refusal).

Design (deterministic single-host ledger):
1. Frozen dataclasses, caller int seqs strictly increasing
   (claim-then-burn: failed mutations consume their seq + book
   ``hsm.rejected``; rewinds raise bare), no wall-clock, RLock-guarded,
   fail-closed taxonomy.
2. stdlib-only + the single ``canonical_json`` try/except fallback;
   ``sha256:`` digest pins with ``verify()``; ``audit.ndjson/1``
   events; version pin ``hsm.v1``; schema pin ``northstar.hsm.v1``.

Honest scope:
- This module books *declared* HSM operations - it performs no
  cryptography, inspects no bytes, and proves nothing about where keys
  are really held or whether a real HSM executed an operation. Pair
  with ``hsm_interface.HSM`` for the simulated in-process crypto layer.
- A booked ``signed`` record means "the host declared a signing
  operation for this key", never "a hardware module signed this".
- Digest pins prove ledger integrity and ordering, never the truth of
  the declared operations.
- No persistence: the ledger is in-memory.
"""

from __future__ import annotations

import hashlib
import re
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


VERSION = "hsm.v1"
SCHEMA = "northstar.hsm.v1"

KIND_PARTITION_REGISTERED = "partition-registered"
KIND_KEY_GENERATED = "key-generated"
KIND_SIGNED = "signed"
KIND_DECRYPTED = "decrypted"
KIND_REVOKED = "revoked"
KIND_REJECTED = "rejected"
_KINDS = frozenset({
    KIND_PARTITION_REGISTERED, KIND_KEY_GENERATED, KIND_SIGNED,
    KIND_DECRYPTED, KIND_REVOKED, KIND_REJECTED,
})

_SIGNING_ALGORITHMS = ("ed25519-sim", "hmac-sha256")
_ENCRYPTION_ALGORITHMS = ("rsa-oaep-sim", "aes-256-gcm-sim")
_ALGORITHMS = _SIGNING_ALGORITHMS + _ENCRYPTION_ALGORITHMS

_REVOKE_REASONS = ("manual", "key-compromised", "rotation",
                   "suspected-misuse", "decommission")

_MAX_ID_LEN = 256
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

# Raw key material / message content must never cross the audit boundary.
_BANNED_DETAIL_KEYS = frozenset({
    "key", "material", "key_material", "private", "secret", "seed",
    "message", "plaintext", "ciphertext", "payload", "raw", "value",
    "data", "text", "body", "content", "signature", "sig",
})


class HSMError(Exception):
    """Base class for all HSM ledger errors."""


class BadIdError(HSMError):
    """Malformed partition id, key id, or operation id."""


class DuplicatePartitionError(HSMError):
    """Partition id already registered (ids are never recycled)."""


class UnknownPartitionError(HSMError):
    """Partition id not registered."""


class DuplicateKeyError(HSMError):
    """Key id already generated (ids are never recycled)."""


class RetiredKeyError(HSMError):
    """Key id was revoked; revoked ids are never recycled."""


class UnknownKeyError(HSMError):
    """Key id not generated."""


class RevokedKeyError(HSMError):
    """Key is revoked; operations on it are refused fail-closed."""


class BadAlgorithmError(HSMError):
    """Algorithm not in the pinned sim vocabulary."""


class WrongKeyUseError(HSMError):
    """Operation does not match the key's algorithm class
    (signing key used for decrypt, encryption key used for sign)."""


class BadDigestError(HSMError):
    """Digest is not a sha256:<64hex> pin."""


class BadReasonError(HSMError):
    """Revocation reason not in the pinned vocabulary."""


class UnknownOperationError(HSMError):
    """Operation id not booked."""


class SeqOrderError(HSMError):
    """Malformed seq or seq not strictly increasing."""


class AuditKindError(HSMError):
    """Unknown audit kind, or banned key at the audit boundary."""


def _check_seq(value: object, name: str = "seq") -> int:
    """Validate a caller-supplied ordering seq: int, not bool, >= 0."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise SeqOrderError(f"{name} must be int, got {type(value).__name__}")
    if value < 0:
        raise SeqOrderError(f"{name} must be >= 0, got {value}")
    return value


def _check_id(value: object, label: str) -> str:
    """Validate an id: non-empty str, no whitespace, <= 256 chars."""
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadIdError(f"{label} must be str, got {type(value).__name__}")
    if not value:
        raise BadIdError(f"{label} must not be empty")
    if len(value) > _MAX_ID_LEN:
        raise BadIdError(f"{label} too long (>{_MAX_ID_LEN} chars)")
    if any(ch.isspace() for ch in value):
        raise BadIdError(f"{label} must not contain whitespace")
    return value


def _check_digest(value: object, label: str) -> str:
    """Validate a sha256:<64hex> digest pin."""
    if isinstance(value, bool) or not isinstance(value, str):
        raise BadDigestError(f"{label} must be str, got {type(value).__name__}")
    if not _DIGEST_RE.match(value):
        raise BadDigestError(f"{label} must be sha256:<64hex>")
    return value


def _digest_pin(payload: Any) -> str:
    """sha256: digest pin over canonical JSON of payload."""
    return "sha256:" + jcs_sha256_hex(payload)


def hsm_audit_event(kind: str, detail: Dict[str, object],
                    seq: object) -> Dict[str, object]:
    """Build one ``audit.ndjson/1`` audit row for the HSM ledger."""
    if kind not in _KINDS:
        raise AuditKindError(f"unknown audit kind: {kind!r}")
    _check_seq(seq)
    banned = _BANNED_DETAIL_KEYS.intersection(detail.keys())
    if banned:
        raise AuditKindError(
            f"detail keys banned from audit boundary: {sorted(banned)}")
    return {
        "audit_version": "audit.ndjson/1",
        "schema": SCHEMA,
        "version": VERSION,
        "kind": "hsm." + kind,
        "detail": dict(detail),
        "seq": seq,
    }


def _record_digest(tag: str, fields: Dict[str, object]) -> str:
    return _digest_pin({"hsm": tag, **fields})


@dataclass(frozen=True)
class PartitionRecord:
    """One declared HSM partition (slot)."""

    partition_id: str
    digest: str

    def as_dict(self) -> Dict[str, object]:
        return {
            "schema": SCHEMA,
            "version": VERSION,
            "partition_id": self.partition_id,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _record_digest(
            "partition", {"partition_id": self.partition_id})


@dataclass(frozen=True)
class KeyRecord:
    """One declared key minted inside a partition.

    Carries a declared material *pin* only - raw key material never
    enters a record.
    """

    key_id: str
    partition_id: str
    algorithm: str
    material_pin: str
    digest: str

    def as_dict(self) -> Dict[str, object]:
        return {
            "schema": SCHEMA,
            "version": VERSION,
            "key_id": self.key_id,
            "partition_id": self.partition_id,
            "algorithm": self.algorithm,
            "material_pin": self.material_pin,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _record_digest("key", {
            "key_id": self.key_id,
            "partition_id": self.partition_id,
            "algorithm": self.algorithm,
            "material_pin": self.material_pin,
        })


@dataclass(frozen=True)
class SignRecord:
    """One declared signing operation against a live signing key."""

    op_id: str
    key_id: str
    partition_id: str
    message_digest: str
    digest: str

    def as_dict(self) -> Dict[str, object]:
        return {
            "schema": SCHEMA,
            "version": VERSION,
            "op_id": self.op_id,
            "key_id": self.key_id,
            "partition_id": self.partition_id,
            "message_digest": self.message_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _record_digest("sign", {
            "op_id": self.op_id,
            "key_id": self.key_id,
            "partition_id": self.partition_id,
            "message_digest": self.message_digest,
        })


@dataclass(frozen=True)
class DecryptRecord:
    """One declared decryption operation against a live encryption key."""

    op_id: str
    key_id: str
    partition_id: str
    ciphertext_digest: str
    digest: str

    def as_dict(self) -> Dict[str, object]:
        return {
            "schema": SCHEMA,
            "version": VERSION,
            "op_id": self.op_id,
            "key_id": self.key_id,
            "partition_id": self.partition_id,
            "ciphertext_digest": self.ciphertext_digest,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _record_digest("decrypt", {
            "op_id": self.op_id,
            "key_id": self.key_id,
            "partition_id": self.partition_id,
            "ciphertext_digest": self.ciphertext_digest,
        })


@dataclass(frozen=True)
class RevokeRecord:
    """Terminal revocation of a key id; the id is retired forever."""

    key_id: str
    reason: str
    digest: str

    def as_dict(self) -> Dict[str, object]:
        return {
            "schema": SCHEMA,
            "version": VERSION,
            "key_id": self.key_id,
            "reason": self.reason,
            "digest": self.digest,
        }

    def verify(self) -> bool:
        return self.digest == _record_digest("revoke", {
            "key_id": self.key_id,
            "reason": self.reason,
        })


class HSM:
    """Declared HSM operations ledger: partitions, key lifecycle, and
    declared sign/decrypt operations. Performs no cryptography."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._partitions: Dict[str, PartitionRecord] = {}
        self._keys: Dict[str, KeyRecord] = {}
        self._revoked: Dict[str, RevokeRecord] = {}
        self._ops: Dict[str, Any] = {}  # op_id -> SignRecord | DecryptRecord
        self._key_ops: Dict[str, List[str]] = {}  # key_id -> op_ids in order
        self._audit: Tuple[Dict[str, object], ...] = ()
        self._last_seq = -1
        self._op_counter = 0

    # -- seq discipline ------------------------------------------------

    def _claim(self, seq: int) -> None:
        """Claim a seq (strictly increasing); raise bare on rewind."""
        _check_seq(seq)
        with self._lock:
            if seq <= self._last_seq:
                raise SeqOrderError(
                    f"seq must be > {self._last_seq}, got {seq}")
            self._last_seq = seq

    def _burn(self, seq: int, key_id: str = "") -> None:
        """Book a rejected row after a failed mutation consumed its seq."""
        detail: Dict[str, object] = {}
        if key_id:
            detail["key_id"] = key_id
        event = hsm_audit_event(KIND_REJECTED, detail, seq)
        with self._lock:
            self._audit = self._audit + (event,)

    def _emit(self, audit_kind: str, detail: Dict[str, object],
              seq: int) -> None:
        """Append a normal audit row (seq already claimed)."""
        event = hsm_audit_event(audit_kind, detail, seq)
        with self._lock:
            self._audit = self._audit + (event,)

    def _mint_op(self, prefix: str) -> str:
        with self._lock:
            self._op_counter += 1
            return "%s-%d" % (prefix, self._op_counter)

    # -- key guards ------------------------------------------------------

    def _require_live_signing_key(self, partition_id: str,
                                  key_id: str) -> KeyRecord:
        key = self._keys.get(key_id)
        if key is None:
            raise UnknownKeyError(f"unknown key_id {key_id!r}")
        if key.partition_id != partition_id:
            raise UnknownPartitionError(
                f"key {key_id!r} not in partition {partition_id!r}")
        if key_id in self._revoked:
            raise RevokedKeyError(f"key_id {key_id!r} is revoked")
        if key.algorithm not in _SIGNING_ALGORITHMS:
            raise WrongKeyUseError(
                f"key {key_id!r} ({key.algorithm}) cannot sign")
        return key

    def _require_live_encryption_key(self, partition_id: str,
                                     key_id: str) -> KeyRecord:
        key = self._keys.get(key_id)
        if key is None:
            raise UnknownKeyError(f"unknown key_id {key_id!r}")
        if key.partition_id != partition_id:
            raise UnknownPartitionError(
                f"key {key_id!r} not in partition {partition_id!r}")
        if key_id in self._revoked:
            raise RevokedKeyError(f"key_id {key_id!r} is revoked")
        if key.algorithm not in _ENCRYPTION_ALGORITHMS:
            raise WrongKeyUseError(
                f"key {key_id!r} ({key.algorithm}) cannot decrypt")
        return key

    # -- public API -------------------------------------------------------

    def register_partition(self, partition_id: str,
                           seq: int) -> PartitionRecord:
        """Declare one HSM partition (slot). Ids are never recycled."""
        self._claim(seq)
        try:
            partition_id = _check_id(partition_id, "partition_id")
            with self._lock:
                if partition_id in self._partitions:
                    raise DuplicatePartitionError(
                        f"partition {partition_id!r} already registered")
                record = PartitionRecord(
                    partition_id=partition_id,
                    digest=_record_digest("partition",
                                         {"partition_id": partition_id}),
                )
                self._partitions[partition_id] = record
            self._emit(KIND_PARTITION_REGISTERED,
                       {"partition_id": partition_id}, seq)
            return record
        except HSMError:
            self._burn(seq)
            raise

    def generate(self, partition_id: str, key_id: str, algorithm: str,
                 seq: int) -> KeyRecord:
        """Book a key minted inside a partition.

        Only the declared material *pin* is booked - raw key material
        never enters a record.
        """
        self._claim(seq)
        try:
            partition_id = _check_id(partition_id, "partition_id")
            key_id = _check_id(key_id, "key_id")
            if algorithm not in _ALGORITHMS:
                raise BadAlgorithmError(f"unknown algorithm {algorithm!r}")
            with self._lock:
                if partition_id not in self._partitions:
                    raise UnknownPartitionError(
                        f"unknown partition {partition_id!r}")
                if key_id in self._revoked:
                    raise RetiredKeyError(
                        f"key_id {key_id!r} is retired (revoked)")
                if key_id in self._keys:
                    raise DuplicateKeyError(
                        f"key_id {key_id!r} already generated")
                material_pin = _digest_pin({
                    "hsm.key-material": 1,
                    "partition_id": partition_id,
                    "key_id": key_id,
                    "algorithm": algorithm,
                })
                record = KeyRecord(
                    key_id=key_id,
                    partition_id=partition_id,
                    algorithm=algorithm,
                    material_pin=material_pin,
                    digest=_record_digest("key", {
                        "key_id": key_id,
                        "partition_id": partition_id,
                        "algorithm": algorithm,
                        "material_pin": material_pin,
                    }),
                )
                self._keys[key_id] = record
                self._key_ops[key_id] = []
            self._emit(KIND_KEY_GENERATED, {
                "key_id": key_id,
                "partition_id": partition_id,
                "algorithm": algorithm,
            }, seq)
            return record
        except HSMError:
            self._burn(seq, key_id if isinstance(key_id, str) else "")
            raise

    def sign(self, partition_id: str, key_id: str, message_digest: str,
             seq: int) -> SignRecord:
        """Book a declared signing operation against a live signing key.

        The message travels as a ``sha256:`` digest pin only.
        """
        self._claim(seq)
        try:
            partition_id = _check_id(partition_id, "partition_id")
            key_id = _check_id(key_id, "key_id")
            message_digest = _check_digest(message_digest, "message_digest")
            self._require_live_signing_key(partition_id, key_id)
            op_id = self._mint_op("sig")
            record = SignRecord(
                op_id=op_id,
                key_id=key_id,
                partition_id=partition_id,
                message_digest=message_digest,
                digest=_record_digest("sign", {
                    "op_id": op_id,
                    "key_id": key_id,
                    "partition_id": partition_id,
                    "message_digest": message_digest,
                }),
            )
            with self._lock:
                self._ops[op_id] = record
                self._key_ops[key_id].append(op_id)
            self._emit(KIND_SIGNED, {
                "op_id": op_id,
                "key_id": key_id,
                "partition_id": partition_id,
                "message_digest": message_digest,
            }, seq)
            return record
        except HSMError:
            self._burn(seq, key_id if isinstance(key_id, str) else "")
            raise

    def decrypt(self, partition_id: str, key_id: str,
                ciphertext_digest: str, seq: int) -> DecryptRecord:
        """Book a declared decryption operation against a live
        encryption key. The ciphertext travels as a ``sha256:`` pin only.
        """
        self._claim(seq)
        try:
            partition_id = _check_id(partition_id, "partition_id")
            key_id = _check_id(key_id, "key_id")
            ciphertext_digest = _check_digest(ciphertext_digest,
                                              "ciphertext_digest")
            self._require_live_encryption_key(partition_id, key_id)
            op_id = self._mint_op("dec")
            record = DecryptRecord(
                op_id=op_id,
                key_id=key_id,
                partition_id=partition_id,
                ciphertext_digest=ciphertext_digest,
                digest=_record_digest("decrypt", {
                    "op_id": op_id,
                    "key_id": key_id,
                    "partition_id": partition_id,
                    "ciphertext_digest": ciphertext_digest,
                }),
            )
            with self._lock:
                self._ops[op_id] = record
                self._key_ops[key_id].append(op_id)
            self._emit(KIND_DECRYPTED, {
                "op_id": op_id,
                "key_id": key_id,
                "partition_id": partition_id,
                "ciphertext_digest": ciphertext_digest,
            }, seq)
            return record
        except HSMError:
            self._burn(seq, key_id if isinstance(key_id, str) else "")
            raise

    def revoke(self, key_id: str, seq: int,
               reason: str = "manual") -> RevokeRecord:
        """Terminally revoke a key id; the id is retired forever."""
        self._claim(seq)
        try:
            key_id = _check_id(key_id, "key_id")
            if reason not in _REVOKE_REASONS:
                raise BadReasonError(f"unknown reason {reason!r}")
            with self._lock:
                if key_id in self._revoked:
                    raise RevokedKeyError(
                        f"key_id {key_id!r} already revoked")
                if key_id not in self._keys:
                    raise UnknownKeyError(f"unknown key_id {key_id!r}")
                record = RevokeRecord(
                    key_id=key_id,
                    reason=reason,
                    digest=_record_digest("revoke", {
                        "key_id": key_id,
                        "reason": reason,
                    }),
                )
                self._revoked[key_id] = record
            self._emit(KIND_REVOKED, {"key_id": key_id, "reason": reason},
                       seq)
            return record
        except HSMError:
            self._burn(seq, key_id if isinstance(key_id, str) else "")
            raise

    # -- pure-read views (seq shape validated, never consumed) ----------

    def partition_record(self, partition_id: str,
                         seq: int) -> PartitionRecord:
        _check_seq(seq)
        partition_id = _check_id(partition_id, "partition_id")
        with self._lock:
            try:
                return self._partitions[partition_id]
            except KeyError:
                raise UnknownPartitionError(
                    f"unknown partition {partition_id!r}") from None

    def key_record(self, key_id: str, seq: int) -> KeyRecord:
        _check_seq(seq)
        key_id = _check_id(key_id, "key_id")
        with self._lock:
            try:
                return self._keys[key_id]
            except KeyError:
                raise UnknownKeyError(
                    f"unknown key_id {key_id!r}") from None

    def revocation_record(self, key_id: str, seq: int) -> RevokeRecord:
        _check_seq(seq)
        key_id = _check_id(key_id, "key_id")
        with self._lock:
            try:
                return self._revoked[key_id]
            except KeyError:
                raise UnknownKeyError(
                    f"key_id {key_id!r} not revoked") from None

    def operation_record(self, op_id: str, seq: int) -> Any:
        _check_seq(seq)
        op_id = _check_id(op_id, "op_id")
        with self._lock:
            try:
                return self._ops[op_id]
            except KeyError:
                raise UnknownOperationError(
                    f"unknown op_id {op_id!r}") from None

    def partition_ids(self, seq: int) -> Tuple[str, ...]:
        _check_seq(seq)
        with self._lock:
            return tuple(sorted(self._partitions))

    def key_ids(self, seq: int) -> Tuple[str, ...]:
        _check_seq(seq)
        with self._lock:
            return tuple(sorted(self._keys))

    def revoked_ids(self, seq: int) -> Tuple[str, ...]:
        _check_seq(seq)
        with self._lock:
            return tuple(sorted(self._revoked))

    def operations_for(self, key_id: str, seq: int) -> Tuple[Any, ...]:
        _check_seq(seq)
        key_id = _check_id(key_id, "key_id")
        with self._lock:
            if key_id not in self._keys:
                raise UnknownKeyError(
                    f"unknown key_id {key_id!r}") from None
            return tuple(self._ops[op_id] for op_id in self._key_ops[key_id])

    def stats(self, seq: int) -> Dict[str, object]:
        _check_seq(seq)
        with self._lock:
            n_sign = sum(1 for op in self._ops.values()
                         if isinstance(op, SignRecord))
            n_dec = sum(1 for op in self._ops.values()
                        if isinstance(op, DecryptRecord))
            rejected = sum(1 for row in self._audit
                           if row["kind"] == "hsm." + KIND_REJECTED)
            return {
                "schema": SCHEMA,
                "version": VERSION,
                "partitions": len(self._partitions),
                "keys": len(self._keys),
                "revoked": len(self._revoked),
                "signatures": n_sign,
                "decryptions": n_dec,
                "rejected": rejected,
            }

    def audit_log(self, seq: int) -> Tuple[Dict[str, object], ...]:
        _check_seq(seq)
        with self._lock:
            return self._audit


def main() -> None:
    h = HSM()
    h.register_partition("slot-0", 0)
    sig_key = h.generate("slot-0", "k-sign", "ed25519-sim", 1)
    enc_key = h.generate("slot-0", "k-enc", "aes-256-gcm-sim", 2)
    assert sig_key.verify() and enc_key.verify()
    md = _digest_pin({"m": "hello"})
    cd = _digest_pin({"c": "world"})
    s = h.sign("slot-0", "k-sign", md, 3)
    d = h.decrypt("slot-0", "k-enc", cd, 4)
    assert s.verify() and d.verify()
    assert h.operations_for("k-sign", 5) == (s,)
    h.revoke("k-sign", 6, reason="rotation")
    assert h.revoked_ids(7) == ("k-sign",)
    assert h.stats(8)["signatures"] == 1
    print("hsm OK: partition, generate, sign, decrypt, revoke, pins, audit")


if __name__ == "__main__":
    main()
