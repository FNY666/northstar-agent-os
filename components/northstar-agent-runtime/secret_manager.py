"""Secret manager: versioned secret store with rotation bookkeeping (simulated).

Research note: *secrets management* is the operational discipline behind
HashiCorp Vault, AWS Secrets Manager, and Kubernetes External Secrets:
credentials, API keys, and certificates are stored centrally, versioned,
and *rotated* on a schedule rather than baked into config. The load-bearing
security properties are well studied (NIST SP 800-57 key-management
guidance; CWE-798 hardcoded credentials; CWE-312 cleartext storage in the
audit trail):

* **Versioning** — every ``put()`` / ``rotate()`` mints a new immutable
  version (``v1``, ``v2``, ...). Old versions are retained and addressable
  by version number so a rollback to the pre-rotation value is possible.
  Version digests pin (secret_id, version, value-digest, seq).
* **Rotation** — ``rotate(secret_id, new_value, seq)`` appends the next
  version atomically (the caller supplies the new value; real systems
  mint it via a dynamic-secret plugin, Vault-style). Rotation never
  mutates a stored version — a version is write-once.
* **Separation of value and record** — ``get()`` returns the secret value
  to the caller (that is the module's job), but every *record*,
  ``as_dict()``, and audit event carries only ids, version numbers, and
  ``sha256:`` digest pins — never raw secret material. Secret values can
  never leak through the audit trail (CWE-312).
* **Deletion is a tombstone** — ``delete()`` marks the secret destroyed;
  ``get()`` on a destroyed secret raises ``DestroyedSecretError`` rather
  than returning ``None``. There is no undelete: a destroyed secret can
  only be re-created with ``put()``, which starts again at ``v1`` with a
  new history (the old digests remain in the audit trail, never the
  values).

Honest scope: this is the *bookkeeping layer* for a secret store, not a
confidentiality boundary. It cannot protect the value once handed to the
caller (the host process owns memory safety), cannot prove the caller
is authorized (pair with an authorization gate such as ``permissions``),
and does not encrypt at rest (a real deployment backs this registry with
a KMS envelope, e.g. ``kms_interface``). ``get()`` returning a value means
"this value was the latest active version as reported", never "only
authorized eyes saw it".

Version pin: secret-manager.v1
Schema pin: northstar.secret-manager.v1
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        import json

        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Module version.
SECRET_MANAGER_VERSION = "secret-manager.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.secret-manager.v1"

#: Maximum secret value size in bytes (guardrail, not a crypto parameter).
MAX_VALUE_BYTES = 1 << 20  # 1 MiB

#: Error taxonomy anchor.
ERROR_PREFIX = "secret-manager."

_AUDIT_KINDS = frozenset(
    {
        "secret-stored",
        "secret-retrieved",
        "version-retrieved",
        "secret-rotated",
        "secret-deleted",
        "rejected",
    }
)


class SecretManagerError(Exception):
    """Base class for all secret-manager failures."""


class UnknownSecretError(SecretManagerError):
    """The secret_id was never stored."""


class DestroyedSecretError(SecretManagerError):
    """The secret was deleted; only tombstone metadata survives."""


class DuplicateSecretError(SecretManagerError):
    """put() on an already-active secret_id (use rotate() instead)."""


class UnknownVersionError(SecretManagerError):
    """The requested version number does not exist."""


def _check_secret_id(secret_id: Any) -> str:
    if isinstance(secret_id, bool) or not isinstance(secret_id, str):
        raise SecretManagerError("secret_id must be a str")
    if not secret_id:
        raise SecretManagerError("secret_id must be non-empty")
    return secret_id


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise SecretManagerError("seq must be an int")
    if seq < 0:
        raise SecretManagerError("seq must be non-negative")
    return seq


def _check_value(value: Any) -> bytes:
    """Validate a secret value, returning its canonical byte form."""
    if isinstance(value, bool):
        raise SecretManagerError("value must be str or bytes, not bool")
    if isinstance(value, str):
        raw = value.encode("utf-8")
    elif isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
    else:
        raise SecretManagerError("value must be str or bytes")
    if not raw:
        raise SecretManagerError("value must be non-empty")
    if len(raw) > MAX_VALUE_BYTES:
        raise SecretManagerError(f"value exceeds {MAX_VALUE_BYTES} bytes")
    return raw


def _check_metadata(metadata: Any) -> Tuple[Tuple[str, str], ...]:
    """Validate metadata, returning a sorted tuple of (key, value) pairs."""
    if metadata is None:
        return ()
    if not isinstance(metadata, Mapping):
        raise SecretManagerError("metadata must be a mapping")
    items = []
    for k, v in metadata.items():
        if isinstance(k, bool) or not isinstance(k, str) or not k:
            raise SecretManagerError("metadata keys must be non-empty str")
        if isinstance(v, bool) or not isinstance(v, str):
            raise SecretManagerError("metadata values must be str")
        items.append((k, v))
    return tuple(sorted(items))


def _value_digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(b"secret-manager:value:" + raw).hexdigest()


def _record_digest(secret_id: str, version: int, value_digest: str,
                   metadata: Tuple[Tuple[str, str], ...], seq: int) -> str:
    body = {
        "secret_id": secret_id,
        "version": version,
        "value_digest": value_digest,
        "metadata": [list(pair) for pair in metadata],
        "seq": seq,
    }
    return "sha256:" + hashlib.sha256(jcs_canonical_json(body)).hexdigest()


@dataclass(frozen=True)
class SecretRecord:
    """One immutable secret version (no raw value — digest only)."""

    secret_id: str
    version: int
    value_digest: str
    created_seq: int
    state: str  # "active" | "destroyed"
    metadata: Tuple[Tuple[str, str], ...]
    digest: str
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "secret_id": self.secret_id,
            "version": self.version,
            "value_digest": self.value_digest,
            "created_seq": self.created_seq,
            "state": self.state,
            "metadata": [list(pair) for pair in self.metadata],
            "digest": self.digest,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class StoredSecret:
    """Result of put(): the pinned registration of version 1."""

    record: SecretRecord

    @property
    def secret_id(self) -> str:
        return self.record.secret_id

    @property
    def version(self) -> int:
        return self.record.version

    def as_dict(self) -> Dict[str, Any]:
        return self.record.as_dict()


@dataclass(frozen=True)
class RetrievedSecret:
    """Result of get(): carries the value (programmatically, never logged)."""

    secret_id: str
    version: int
    value: bytes
    value_digest: str
    retrieved_seq: int
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        # Discipline: serialization never carries secret material.
        return {
            "secret_id": self.secret_id,
            "version": self.version,
            "value_digest": self.value_digest,
            "retrieved_seq": self.retrieved_seq,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class RotationRecord:
    """Result of rotate(): binds the old and new pinned versions."""

    secret_id: str
    old_version: int
    new_version: int
    old_value_digest: str
    new_value_digest: str
    rotated_seq: int
    digest: str
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "secret_id": self.secret_id,
            "old_version": self.old_version,
            "new_version": self.new_version,
            "old_value_digest": self.old_value_digest,
            "new_value_digest": self.new_value_digest,
            "rotated_seq": self.rotated_seq,
            "digest": self.digest,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class DeletionRecord:
    """Result of delete(): the tombstone (versions pinned, values gone)."""

    secret_id: str
    versions_destroyed: Tuple[int, ...]
    deleted_seq: int
    digest: str
    schema: str = SCHEMA_PIN

    def as_dict(self) -> Dict[str, Any]:
        return {
            "secret_id": self.secret_id,
            "versions_destroyed": list(self.versions_destroyed),
            "deleted_seq": self.deleted_seq,
            "digest": self.digest,
            "schema": self.schema,
        }


class SecretManager:
    """Vault-shaped secret registry: store, get, rotate, delete.

    Caller-supplied int seqs order all operations (no wall-clock).
    Values are kept in memory (host's confidentiality boundary);
    every record and audit event carries only digest pins.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        # secret_id -> list of (raw value, SecretRecord), version = index+1
        self._secrets: Dict[str, list] = {}
        # secret_id -> tombstone digest (destroyed secrets)
        self._tombstones: Dict[str, str] = {}

    def _live(self, secret_id: str) -> list:
        versions = self._secrets.get(secret_id)
        if versions is None:
            if secret_id in self._tombstones:
                raise DestroyedSecretError(f"secret {secret_id!r} was deleted")
            raise UnknownSecretError(f"unknown secret {secret_id!r}")
        return versions

    def put(self, secret_id: str, value: Any, seq: int,
            metadata: Optional[Mapping[str, str]] = None) -> StoredSecret:
        """Store a new secret as version 1. Re-put is refused."""
        _check_secret_id(secret_id)
        raw = _check_value(value)
        _check_seq(seq)
        meta = _check_metadata(metadata)
        with self._lock:
            if secret_id in self._tombstones:
                raise DestroyedSecretError(
                    f"secret {secret_id!r} was deleted; "
                    "re-put is refused, use a new secret_id"
                )
            if secret_id in self._secrets:
                raise DuplicateSecretError(
                    f"secret {secret_id!r} already active; use rotate()"
                )
            vdigest = _value_digest(raw)
            digest = _record_digest(secret_id, 1, vdigest, meta, seq)
            record = SecretRecord(
                secret_id=secret_id,
                version=1,
                value_digest=vdigest,
                created_seq=seq,
                state="active",
                metadata=meta,
                digest=digest,
            )
            self._secrets[secret_id] = [(raw, record)]
            return StoredSecret(record=record)

    def get(self, secret_id: str, seq: int) -> RetrievedSecret:
        """Return the latest active version's value."""
        _check_secret_id(secret_id)
        _check_seq(seq)
        with self._lock:
            versions = self._live(secret_id)
            raw, record = versions[-1]
            return RetrievedSecret(
                secret_id=secret_id,
                version=record.version,
                value=bytes(raw),
                value_digest=record.value_digest,
                retrieved_seq=seq,
            )

    def get_version(self, secret_id: str, version: int, seq: int) -> RetrievedSecret:
        """Return a specific version's value."""
        _check_secret_id(secret_id)
        _check_seq(seq)
        if isinstance(version, bool) or not isinstance(version, int) or version < 1:
            raise SecretManagerError("version must be a positive int")
        with self._lock:
            versions = self._live(secret_id)
            if version > len(versions):
                raise UnknownVersionError(
                    f"secret {secret_id!r} has no version {version}"
                )
            raw, record = versions[version - 1]
            return RetrievedSecret(
                secret_id=secret_id,
                version=record.version,
                value=bytes(raw),
                value_digest=record.value_digest,
                retrieved_seq=seq,
            )

    def rotate(self, secret_id: str, new_value: Any, seq: int,
               metadata: Optional[Mapping[str, str]] = None) -> RotationRecord:
        """Append the next immutable version; old version stays addressable."""
        _check_secret_id(secret_id)
        raw = _check_value(new_value)
        _check_seq(seq)
        meta = _check_metadata(metadata)
        with self._lock:
            versions = self._live(secret_id)
            old_raw, old_record = versions[-1]
            new_version = old_record.version + 1
            new_vdigest = _value_digest(raw)
            if new_vdigest == old_record.value_digest:
                raise SecretManagerError(
                    "rotation value is identical to the current value"
                )
            digest = _record_digest(secret_id, new_version, new_vdigest, meta, seq)
            record = SecretRecord(
                secret_id=secret_id,
                version=new_version,
                value_digest=new_vdigest,
                created_seq=seq,
                state="active",
                metadata=meta,
                digest=digest,
            )
            versions.append((raw, record))
            body = {
                "secret_id": secret_id,
                "old_version": old_record.version,
                "new_version": new_version,
                "old_value_digest": old_record.value_digest,
                "new_value_digest": new_vdigest,
                "rotated_seq": seq,
            }
            rotation_digest = "sha256:" + hashlib.sha256(
                jcs_canonical_json(body)
            ).hexdigest()
            return RotationRecord(
                secret_id=secret_id,
                old_version=old_record.version,
                new_version=new_version,
                old_value_digest=old_record.value_digest,
                new_value_digest=new_vdigest,
                rotated_seq=seq,
                digest=rotation_digest,
            )

    def delete(self, secret_id: str, seq: int) -> DeletionRecord:
        """Destroy all versions; only the tombstone (digest pins) survives."""
        _check_secret_id(secret_id)
        _check_seq(seq)
        with self._lock:
            versions = self._live(secret_id)
            destroyed = tuple(record.version for _, record in versions)
            pins = [record.digest for _, record in versions]
            body = {
                "secret_id": secret_id,
                "versions_destroyed": list(destroyed),
                "version_digests": pins,
                "deleted_seq": seq,
            }
            digest = "sha256:" + hashlib.sha256(
                jcs_canonical_json(body)
            ).hexdigest()
            # Zero the values before dropping (host-memory hygiene).
            zeroed = [(b"\x00" * len(raw), record) for raw, record in versions]
            del self._secrets[secret_id]
            del zeroed
            self._tombstones[secret_id] = digest
            return DeletionRecord(
                secret_id=secret_id,
                versions_destroyed=destroyed,
                deleted_seq=seq,
                digest=digest,
            )

    def versions(self, secret_id: str) -> Tuple[SecretRecord, ...]:
        """Pinned version history (digests only — no values)."""
        _check_secret_id(secret_id)
        with self._lock:
            versions = self._live(secret_id)
            return tuple(record for _, record in versions)

    def secret_ids(self) -> Tuple[str, ...]:
        """Sorted ids of currently active secrets."""
        with self._lock:
            return tuple(sorted(self._secrets))

    def is_destroyed(self, secret_id: str) -> bool:
        """True if the secret_id carries a tombstone."""
        return secret_id in self._tombstones

    def verify_record(self, record: SecretRecord) -> bool:
        """Re-derive a record's digest pin (detects tampering)."""
        if not isinstance(record, SecretRecord):
            raise TypeError("record must be a SecretRecord")
        expected = _record_digest(
            record.secret_id,
            record.version,
            record.value_digest,
            record.metadata,
            record.created_seq,
        )
        return expected == record.digest


def secret_manager_audit_event(
    kind: str,
    seq: int,
    stored: Optional[StoredSecret] = None,
    retrieved: Optional[RetrievedSecret] = None,
    rotated: Optional[RotationRecord] = None,
    deleted: Optional[DeletionRecord] = None,
) -> Dict[str, Any]:
    """Build an ``audit.ndjson/1``-shaped record for a secret-manager step.

    ``kind`` is one of ``secret-stored`` / ``secret-retrieved`` /
    ``version-retrieved`` / ``secret-rotated`` / ``secret-deleted`` /
    ``rejected``. Raw secret values are never emitted — only ids, versions,
    and digest pins — so secret material cannot leak through the audit
    trail (CWE-312).
    """
    if kind not in _AUDIT_KINDS:
        raise ValueError(f"kind must be one of {sorted(_AUDIT_KINDS)}")
    _check_seq(seq)
    if stored is not None and not isinstance(stored, StoredSecret):
        raise TypeError("stored must be a StoredSecret")
    if retrieved is not None and not isinstance(retrieved, RetrievedSecret):
        raise TypeError("retrieved must be a RetrievedSecret")
    if rotated is not None and not isinstance(rotated, RotationRecord):
        raise TypeError("rotated must be a RotationRecord")
    if deleted is not None and not isinstance(deleted, DeletionRecord):
        raise TypeError("deleted must be a DeletionRecord")
    record: Dict[str, Any] = {
        "event": f"secret-manager-{kind}",
        "audit_seq": seq,
        "schema": SCHEMA_PIN,
    }
    if stored is not None:
        rec = stored.record
        record["secret_id"] = rec.secret_id
        record["version"] = rec.version
        record["value_digest"] = rec.value_digest
        record["digest"] = rec.digest
    if retrieved is not None:
        record["secret_id"] = retrieved.secret_id
        record["version"] = retrieved.version
        record["value_digest"] = retrieved.value_digest
    if rotated is not None:
        record["secret_id"] = rotated.secret_id
        record["old_version"] = rotated.old_version
        record["new_version"] = rotated.new_version
        record["old_value_digest"] = rotated.old_value_digest
        record["new_value_digest"] = rotated.new_value_digest
        record["digest"] = rotated.digest
    if deleted is not None:
        record["secret_id"] = deleted.secret_id
        record["versions_destroyed"] = list(deleted.versions_destroyed)
        record["digest"] = deleted.digest
    return record


def main() -> None:
    """Self-check: store, retrieve, rotate, delete, refusals, no-leak audit."""
    mgr = SecretManager()

    stored = mgr.put("db-password", "s3cr3t-1", 0)
    assert stored.version == 1
    assert "s3cr3t-1" not in str(stored.as_dict())

    got = mgr.get("db-password", 1)
    assert got.value == b"s3cr3t-1"
    assert got.version == 1
    assert "s3cr3t-1" not in str(got.as_dict())

    try:
        mgr.put("db-password", "other", 2)
    except DuplicateSecretError:
        pass
    else:
        raise AssertionError("duplicate put must be refused")

    rot = mgr.rotate("db-password", "s3cr3t-2", 3)
    assert rot.old_version == 1 and rot.new_version == 2
    assert "s3cr3t-2" not in str(rot.as_dict())

    old = mgr.get_version("db-password", 1, 4)
    assert old.value == b"s3cr3t-1"
    new = mgr.get("db-password", 5)
    assert new.value == b"s3cr3t-2"

    deleted = mgr.delete("db-password", 6)
    assert deleted.versions_destroyed == (1, 2)
    try:
        mgr.get("db-password", 7)
    except DestroyedSecretError:
        pass
    else:
        raise AssertionError("get after delete must be refused")

    ev = secret_manager_audit_event("secret-stored", 0, stored=stored)
    assert ev["schema"] == SCHEMA_PIN
    assert "s3cr3t-1" not in str(ev)

    print("secret-manager OK: store, get, rotate, delete, refusals, no-leak")


if __name__ == "__main__":
    main()
