"""key_management: KMS-shaped key lifecycle decision ledger.

Simulated bookkeeping for key-management *decisions* (AWS KMS / HashiCorp
Vault / GCP Cloud KMS shaped): declared key creation, declared key
rotation, and key revocation.  The module generates no real keys,
wraps nothing, performs no cryptography, and never sees key material:
raw secret bytes, key contents, and plaintext data travel only as
``sha256:`` digest pins.  A booked ``active=True`` means "this ledger
declares the key live", never "this key is safe to use".  All
cryptographic outcomes are host-reported (GIGO).

Public API:
    KeyManagement.create(key_id, seq, algorithm="aes-256-gcm",
                         key_digest="")
    KeyManagement.rotate(key_id, seq, key_digest="")
    KeyManagement.revoke(key_id, seq, reason="manual")
    KeyManagement.key_record(key_id, seq)  # pure read
    KeyManagement.key_ids(seq) / revoked_ids(seq) / stats(seq) /
        audit_log(seq)                    # pure reads
    key_management_audit_event(kind, seq, detail=None)

Honest scope: simulated ledger.  Booking is a declaration; key material
is digest-pinned and can never be used to encrypt, decrypt, wrap, or
sign anything.  Rotation books a declared version bump, never proof that
dependent systems re-encrypted.  Revocation is a ledger-terminal state,
never a guarantee that live sessions stopped using the key.
"""
from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

try:  # standard sibling fallback
    from canonical_json import jcs_dumps as _jcs_dumps
except Exception:  # pragma: no cover - fallback path
    import json as _json

    def _jcs_dumps(obj: Any) -> str:
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False)


VERSION = "key-management.v1"
SCHEMA = "northstar.key-management.v1"
AUDIT_SCHEMA = "audit.ndjson/1"

_AUDIT_KINDS = (
    "key-created",
    "rotated",
    "revoked",
    "rejected",
)

# Raw material that must never cross the audit boundary: only ids,
# digest pins, versions, algorithms, reasons, and verdicts travel.
# Exact-key matching (no substring false positives).
_BANNED_KEYS = frozenset({
    "key", "secret", "material", "raw", "plaintext", "value", "payload",
    "bytes", "private", "contents", "ciphertext", "password",
})

# Pinned algorithm vocabulary (KMS-shaped; a declaration, never a claim
# that any backend supports it).
_ALGORITHMS = frozenset({
    "aes-256-gcm", "aes-256-cbc", "chacha20-poly1305",
    "rsa-2048", "rsa-4096",
    "ecdsa-p256", "ecdsa-p384", "ed25519",
})

# Pinned revocation-reason vocabulary.
_REASONS = frozenset({
    "manual", "key-compromised", "rotation-policy",
    "employee-departure", "suspected-leak", "superseded",
})


# ---------------------------------------------------------------------------
# error taxonomy
# ---------------------------------------------------------------------------

class KeyManagementError(Exception):
    """Base error for the key-management ledger."""


class BadIdError(KeyManagementError):
    """Malformed identifier (not a non-empty str of bounded length)."""


class DuplicateKeyError(KeyManagementError):
    """A key id is already registered."""


class RevokedKeyError(KeyManagementError):
    """A key id was revoked and may never be reused."""


class UnknownKeyError(KeyManagementError):
    """No such registered key."""


class BadDigestError(KeyManagementError):
    """Malformed digest (not ``sha256:<64hex>``)."""


class BadAlgorithmError(KeyManagementError):
    """Unknown or malformed algorithm name."""


class BadReasonError(KeyManagementError):
    """Unknown or malformed revocation reason."""


class SeqOrderError(KeyManagementError):
    """Seq not a strictly increasing int."""


class AuditKindError(KeyManagementError):
    """Unknown audit kind or banned key in audit detail."""


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _digest_pin(data: str) -> str:
    return "sha256:" + hashlib.sha256(data.encode("utf-8")).hexdigest()


def _check_id(value: Any, name: str = "id") -> str:
    if not isinstance(value, str) or not value or len(value) > 128:
        raise BadIdError(f"bad {name}")
    if value.strip() != value or any(c.isspace() for c in value):
        raise BadIdError(f"bad {name}")
    return value


def _check_digest(value: Any, name: str = "digest") -> str:
    if not isinstance(value, str):
        raise BadDigestError(f"bad {name}")
    import re
    if not re.match(r"^sha256:[0-9a-f]{64}$", value):
        raise BadDigestError(f"bad {name}")
    return value


def _check_algorithm(value: Any) -> str:
    if not isinstance(value, str) or value not in _ALGORITHMS:
        raise BadAlgorithmError(f"bad algorithm: {value!r}")
    return value


def _check_reason(value: Any) -> str:
    if not isinstance(value, str) or value not in _REASONS:
        raise BadReasonError(f"bad reason: {value!r}")
    return value


def _check_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise SeqOrderError("bad seq")
    return seq


def key_management_audit_event(kind: str, seq: int,
                               detail: Optional[Dict[str, Any]] = None
                               ) -> Dict[str, Any]:
    """Build one ``audit.ndjson/1`` event row for the key ledger."""
    if kind not in _AUDIT_KINDS:
        raise AuditKindError(f"unknown kind: {kind!r}")
    seq = _check_seq(seq)
    detail = dict(detail or {})
    for key in detail:
        if key in _BANNED_KEYS:
            raise AuditKindError(f"banned key in audit detail: {key!r}")
    row = {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "seq": seq,
        "module": "key-management",
        "detail": detail,
    }
    row["digest"] = _digest_pin(_jcs_dumps(row))
    return row


# ---------------------------------------------------------------------------
# frozen records
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class KeyRecord:
    key_id: str
    algorithm: str
    version: int
    key_digest: str
    active: bool
    schema: str = SCHEMA
    digest: str = field(default="")

    def as_dict(self) -> Dict[str, Any]:
        return {"key_id": self.key_id, "algorithm": self.algorithm,
                "version": self.version, "key_digest": self.key_digest,
                "active": self.active, "schema": self.schema,
                "digest": self.digest}

    def verify(self) -> bool:
        body = {"key_id": self.key_id, "algorithm": self.algorithm,
                "version": self.version, "key_digest": self.key_digest,
                "active": self.active, "schema": self.schema}
        return self.digest == _digest_pin(_jcs_dumps(body))


@dataclass(frozen=True)
class RotationRecord:
    rotation_id: str
    key_id: str
    old_version: int
    new_version: int
    new_key_digest: str
    schema: str = SCHEMA
    digest: str = field(default="")

    def as_dict(self) -> Dict[str, Any]:
        return {"rotation_id": self.rotation_id, "key_id": self.key_id,
                "old_version": self.old_version,
                "new_version": self.new_version,
                "new_key_digest": self.new_key_digest,
                "schema": self.schema, "digest": self.digest}

    def verify(self) -> bool:
        body = {"rotation_id": self.rotation_id, "key_id": self.key_id,
                "old_version": self.old_version,
                "new_version": self.new_version,
                "new_key_digest": self.new_key_digest,
                "schema": self.schema}
        return self.digest == _digest_pin(_jcs_dumps(body))


@dataclass(frozen=True)
class RevocationRecord:
    key_id: str
    reason: str
    version: int
    schema: str = SCHEMA
    digest: str = field(default="")

    def as_dict(self) -> Dict[str, Any]:
        return {"key_id": self.key_id, "reason": self.reason,
                "version": self.version, "schema": self.schema,
                "digest": self.digest}

    def verify(self) -> bool:
        body = {"key_id": self.key_id, "reason": self.reason,
                "version": self.version, "schema": self.schema}
        return self.digest == _digest_pin(_jcs_dumps(body))


# ---------------------------------------------------------------------------
# the ledger
# ---------------------------------------------------------------------------

class KeyManagement:
    """Deterministic single-host key-lifecycle decision ledger."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._seq = -1
        self._keys: Dict[str, KeyRecord] = {}
        self._rotations: Dict[str, RotationRecord] = {}
        self._rot_counter = 0
        self._revoked: Dict[str, RevocationRecord] = {}
        self._audit: List[Dict[str, Any]] = []

    # -- seq discipline: claim-then-burn -------------------------------

    def _claim(self, seq: int) -> None:
        seq = _check_seq(seq)
        if seq <= self._seq:
            raise SeqOrderError("seq must strictly increase")
        self._seq = seq

    def _emit(self, audit_kind: str, detail: Dict[str, Any]) -> None:
        self._audit.append(key_management_audit_event(audit_kind, self._seq,
                                                     detail))

    def _reject(self, detail: Dict[str, Any]) -> None:
        self._audit.append(key_management_audit_event("rejected", self._seq,
                                                      detail))

    # -- API ------------------------------------------------------------

    def create(self, key_id: str, seq: int, algorithm: str = "aes-256-gcm",
               key_digest: str = "") -> KeyRecord:
        """Declare a new key; raw key material never enters a record.

        ``key_digest`` pins the key content (the host generated it, the
        module never sees it).  Empty ``key_digest`` defaults to a
        deterministic placeholder pin — suitable for bookkeeping only.
        """
        with self._lock:
            self._claim(seq)
            try:
                key_id = _check_id(key_id, "key_id")
                algorithm = _check_algorithm(algorithm)
                key_digest = _check_digest(key_digest, "key_digest") \
                    if key_digest else _digest_pin("key-material:" + key_id)
                if key_id in self._revoked:
                    raise RevokedKeyError(f"revoked key: {key_id!r}")
                if key_id in self._keys:
                    raise DuplicateKeyError(f"duplicate key: {key_id!r}")
                body = {"key_id": key_id, "algorithm": algorithm,
                        "version": 1, "key_digest": key_digest,
                        "active": True, "schema": SCHEMA}
                rec = KeyRecord(key_id=key_id, algorithm=algorithm,
                                version=1, key_digest=key_digest,
                                active=True,
                                digest=_digest_pin(_jcs_dumps(body)))
                self._keys[key_id] = rec
                self._emit("key-created", {"key_id": key_id,
                                           "algorithm": algorithm,
                                           "version": 1})
                return rec
            except KeyManagementError:
                self._reject({"op": "create", "key_id": str(key_id)})
                raise

    def rotate(self, key_id: str, seq: int,
               key_digest: str = "") -> RotationRecord:
        """Book a declared key rotation: version bumps by one, booked as
        data.  Rotation of a revoked or unknown key fails closed.  This
        proves no re-encryption anywhere."""
        with self._lock:
            self._claim(seq)
            try:
                key_id = _check_id(key_id, "key_id")
                if key_id in self._revoked:
                    raise RevokedKeyError(f"revoked key: {key_id!r}")
                cur = self._keys.get(key_id)
                if cur is None:
                    raise UnknownKeyError(f"unknown key: {key_id!r}")
                key_digest = _check_digest(key_digest, "key_digest") \
                    if key_digest else _digest_pin(
                        "key-material:%s:v%d" % (key_id, cur.version + 1))
                self._rot_counter += 1
                rotation_id = f"rot-{self._rot_counter}"
                body = {"rotation_id": rotation_id, "key_id": key_id,
                        "old_version": cur.version,
                        "new_version": cur.version + 1,
                        "new_key_digest": key_digest, "schema": SCHEMA}
                rec = RotationRecord(
                    rotation_id=rotation_id, key_id=key_id,
                    old_version=cur.version, new_version=cur.version + 1,
                    new_key_digest=key_digest,
                    digest=_digest_pin(_jcs_dumps(body)))
                self._rotations[rotation_id] = rec
                new_body = {"key_id": cur.key_id, "algorithm": cur.algorithm,
                            "version": cur.version + 1,
                            "key_digest": key_digest,
                            "active": True, "schema": SCHEMA}
                self._keys[key_id] = KeyRecord(
                    key_id=cur.key_id, algorithm=cur.algorithm,
                    version=cur.version + 1, key_digest=key_digest,
                    active=True,
                    digest=_digest_pin(_jcs_dumps(new_body)))
                self._emit("rotated", {"rotation_id": rotation_id,
                                       "key_id": key_id,
                                       "old_version": cur.version,
                                       "new_version": cur.version + 1})
                return rec
            except KeyManagementError:
                self._reject({"op": "rotate", "key_id": str(key_id)})
                raise

    def revoke(self, key_id: str, seq: int,
               reason: str = "manual") -> RevocationRecord:
        """Terminal: revoke a key.  Rotating or re-creating a revoked key
        fails closed forever."""
        with self._lock:
            self._claim(seq)
            try:
                key_id = _check_id(key_id, "key_id")
                reason = _check_reason(reason)
                if key_id in self._revoked:
                    raise RevokedKeyError(f"revoked key: {key_id!r}")
                cur = self._keys.get(key_id)
                if cur is None:
                    raise UnknownKeyError(f"unknown key: {key_id!r}")
                body = {"key_id": key_id, "reason": reason,
                        "version": cur.version, "schema": SCHEMA}
                rec = RevocationRecord(
                    key_id=key_id, reason=reason, version=cur.version,
                    digest=_digest_pin(_jcs_dumps(body)))
                self._revoked[key_id] = rec
                new_body = {"key_id": cur.key_id, "algorithm": cur.algorithm,
                            "version": cur.version,
                            "key_digest": cur.key_digest,
                            "active": False, "schema": SCHEMA}
                self._keys[key_id] = KeyRecord(
                    key_id=cur.key_id, algorithm=cur.algorithm,
                    version=cur.version, key_digest=cur.key_digest,
                    active=False,
                    digest=_digest_pin(_jcs_dumps(new_body)))
                self._emit("revoked", {"key_id": key_id, "reason": reason,
                                       "version": cur.version})
                return rec
            except KeyManagementError:
                self._reject({"op": "revoke", "key_id": str(key_id)})
                raise

    # -- pure-read views (validate seq shape, never consume, no audit) --

    def key_record(self, key_id: str, seq: int) -> KeyRecord:
        with self._lock:
            _check_seq(seq)
            key_id = _check_id(key_id, "key_id")
            rec = self._keys.get(key_id)
            if rec is None:
                raise UnknownKeyError(f"unknown key: {key_id!r}")
            return rec

    def key_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            _check_seq(seq)
            return tuple(sorted(self._keys))

    def revoked_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            _check_seq(seq)
            return tuple(sorted(self._revoked))

    def rotation_record(self, rotation_id: str, seq: int) -> RotationRecord:
        with self._lock:
            _check_seq(seq)
            rotation_id = _check_id(rotation_id, "rotation_id")
            rec = self._rotations.get(rotation_id)
            if rec is None:
                raise UnknownKeyError(f"unknown rotation: {rotation_id!r}")
            return rec

    def rotation_ids(self, seq: int) -> Tuple[str, ...]:
        with self._lock:
            _check_seq(seq)
            return tuple(sorted(
                self._rotations, key=lambda r: int(r.split("-")[1])))

    def stats(self, seq: int) -> Dict[str, Any]:
        with self._lock:
            _check_seq(seq)
            return {
                "keys": len(self._keys),
                "revoked": len(self._revoked),
                "rotations": len(self._rotations),
                "audit_rows": len(self._audit),
            }

    def audit_log(self, seq: int) -> Tuple[Dict[str, Any], ...]:
        with self._lock:
            _check_seq(seq)
            return tuple(self._audit)


def main() -> None:
    km = KeyManagement()
    rec = km.create("prod-enc-1", 1, algorithm="aes-256-gcm")
    assert rec.version == 1 and rec.active and rec.verify()
    rot = km.rotate("prod-enc-1", 2)
    assert rot.old_version == 1 and rot.new_version == 2
    assert rot.verify()
    rev = km.revoke("prod-enc-1", 3, reason="key-compromised")
    assert rev.reason == "key-compromised" and rev.verify()
    assert km.key_record("prod-enc-1", 4).active is False
    kinds = [r["kind"] for r in km.audit_log(5)]
    assert kinds == ["key-created", "rotated", "revoked"], kinds
    print("key-management OK: create, rotate, revoke, pins, audit")


if __name__ == "__main__":
    main()
