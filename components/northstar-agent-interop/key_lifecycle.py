"""Signing-key lifecycle for proof attestations.

A proof signature is only as trustworthy as the key that produced it, so the key
set itself needs a history that a verifier can check without trusting the log
that carries it. This module records introduction, rotation, and revocation as a
hash-chained history that never stores key material, and pins the chain to an
externally fixed trust anchor.

The deliberate asymmetry: a *retired* key keeps verifying the attestations it
signed, while a *revoked* key stops resolving immediately, even for signatures
that were produced before the revocation. The history can say that revocation
happened, but it cannot say when relative to a given signature, because an
attestation carries no signing time. Failing closed is the only defensible
reading of that gap.

Not proved here: real PKI, certificate chains, key custody, hardware backing,
or that a revocation was authorised by anyone. The history proves that a key set
did not change silently *given* a pinned anchor, and nothing about who held it.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

SCHEMA = "northstar.key-history.v1"
ZERO = "sha256:" + "0" * 64
ACTIONS = ("introduced", "rotated", "revoked")
TRUSTED_STATES = ("trusted", "trusted-retired")
_FIELDS = frozenset(
    {"revision", "key_id", "material_digest", "action", "previous_digest", "record_digest"}
)
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_MIN_MATERIAL = 16


class KeyLifecycleError(ValueError):
    """Malformed, conflicting, or unauthorised key lifecycle operation."""


def _canon(value: Any) -> bytes:
    try:
        return json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:  # pragma: no cover - defensive
        raise KeyLifecycleError("value is not canonical JSON") from exc


def _sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _digest_of(material: bytes) -> str:
    """Digest the key material. The material itself is never persisted."""
    return _sha(material)


def _validate_material(material: Any) -> bytes:
    if not isinstance(material, (bytes, bytearray)) or len(material) < _MIN_MATERIAL:
        raise KeyLifecycleError("signing material must be at least 16 bytes")
    return bytes(material)


def _record_digest(revision: int, key_id: str, material_digest: str, action: str, previous_digest: str) -> str:
    return _sha(
        _canon(
            {
                "revision": revision,
                "key_id": key_id,
                "material_digest": material_digest,
                "action": action,
                "previous_digest": previous_digest,
            }
        )
    )


@dataclass(frozen=True)
class KeyRecord:
    revision: int
    key_id: str
    material_digest: str
    action: str
    previous_digest: str
    record_digest: str

    def to_dict(self) -> dict:
        return {
            "revision": self.revision,
            "key_id": self.key_id,
            "material_digest": self.material_digest,
            "action": self.action,
            "previous_digest": self.previous_digest,
            "record_digest": self.record_digest,
        }

    @classmethod
    def from_dict(cls, value: Any) -> "KeyRecord":
        if not isinstance(value, dict) or set(value) != _FIELDS:
            raise KeyLifecycleError("key record fields are invalid")
        revision = value["revision"]
        if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
            raise KeyLifecycleError("key record revision is invalid")
        action = value["action"]
        if action not in ACTIONS:
            raise KeyLifecycleError("key record action is invalid")
        key_id = value["key_id"]
        if not isinstance(key_id, str) or not key_id.strip():
            raise KeyLifecycleError("key record key_id is invalid")
        for field in ("material_digest", "previous_digest", "record_digest"):
            if not isinstance(value[field], str) or _DIGEST.fullmatch(value[field]) is None:
                raise KeyLifecycleError(f"key record {field} is invalid")
        return cls(
            revision,
            key_id,
            value["material_digest"],
            action,
            value["previous_digest"],
            value["record_digest"],
        )


@dataclass(frozen=True)
class KeyVerdict:
    state: str
    reasons: tuple[str, ...] = ()


class KeyHistory:
    """Append-only, hash-chained history of key lifecycle decisions."""

    def __init__(self, path: Any, *, anchor: str | None = None):
        if anchor is not None and (not isinstance(anchor, str) or _DIGEST.fullmatch(anchor) is None):
            raise KeyLifecycleError("anchor must be a sha256 digest")
        self.path = Path(path)
        self.anchor = anchor

    # -- reading ---------------------------------------------------------

    def _read_records(self) -> tuple[tuple[KeyRecord, ...], bool]:
        """Return the parsed records and whether any line failed to parse."""
        if not self.path.exists():
            return (), False
        try:
            raw = self.path.read_text(encoding="utf-8")
        except OSError:
            return (), True
        records: list[KeyRecord] = []
        for line in raw.splitlines():
            if not line.strip():
                continue
            try:
                records.append(KeyRecord.from_dict(json.loads(line)))
            except (json.JSONDecodeError, KeyLifecycleError, TypeError):
                return tuple(records), True
        return tuple(records), False

    @property
    def records(self) -> tuple[KeyRecord, ...]:
        return self._read_records()[0]

    def digest_for(self, key_id: str) -> str | None:
        mine = [record for record in self.records if record.key_id == key_id]
        return mine[-1].material_digest if mine else None

    # -- writing ---------------------------------------------------------

    def _append(self, key_id: str, material_digest: str, action: str) -> KeyRecord:
        records = self.records
        revision = records[-1].revision + 1 if records else 1
        previous = records[-1].record_digest if records else ZERO
        digest = _record_digest(revision, key_id, material_digest, action, previous)
        record = KeyRecord(revision, key_id, material_digest, action, previous, digest)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(
                json.dumps(record.to_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                + "\n"
            )
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(self.path, 0o600)
        return record

    def _declare(self, key_id: str, material: bytes, action: str) -> KeyRecord:
        material = _validate_material(material)
        if not isinstance(key_id, str) or not key_id.strip():
            raise KeyLifecycleError("key_id is invalid")
        if any(record.key_id == key_id for record in self.records):
            raise KeyLifecycleError("key_id already appears in the history")
        return self._append(key_id, _digest_of(material), action)

    def introduce(self, key_id: str, material: bytes) -> KeyRecord:
        return self._declare(key_id, material, "introduced")

    def rotate(self, key_id: str, material: bytes) -> KeyRecord:
        """Bring a new key into use. The previously introduced key becomes retired."""
        return self._declare(key_id, material, "rotated")

    def revoke(self, key_id: str) -> KeyRecord:
        state = self._derive(self.records, key_id)
        if state == "unknown-key":
            raise KeyLifecycleError("key is not in the history")
        if state == "revoked":
            raise KeyLifecycleError("key is already revoked")
        digest = self.digest_for(key_id)
        return self._append(key_id, digest, "revoked")

    # -- verification ----------------------------------------------------

    def verify_chain(self) -> KeyVerdict:
        """Check the history against itself and against the pinned anchor."""
        records, failed = self._read_records()
        if failed:
            return KeyVerdict("unverifiable", ("history_unreadable",))
        if not records:
            return KeyVerdict("unverifiable", ("history_missing",))
        previous = ZERO
        expected = 1
        for record in records:
            if record.revision != expected:
                return KeyVerdict("unverifiable", ("revision_gap",))
            if record.previous_digest != previous:
                return KeyVerdict("unverifiable", ("chain_break",))
            recomputed = _record_digest(
                record.revision, record.key_id, record.material_digest, record.action, record.previous_digest
            )
            if recomputed != record.record_digest:
                return KeyVerdict("unverifiable", ("record_digest_mismatch",))
            previous = record.record_digest
            expected += 1
        if self.anchor is not None and records[0].record_digest != self.anchor:
            return KeyVerdict("untrusted-anchor", ("anchor_mismatch",))
        if self.anchor is None:
            return KeyVerdict("trusted", ("anchor_unpinned",))
        return KeyVerdict("trusted", ())

    @staticmethod
    def _derive(records: tuple[KeyRecord, ...], key_id: str) -> str:
        mine = [record for record in records if record.key_id == key_id]
        if not mine:
            return "unknown-key"
        last = mine[-1]
        if last.action == "revoked":
            return "revoked"
        if last.action == "rotated":
            return "trusted"
        superseded = any(
            record.revision > last.revision and record.action == "rotated" for record in records
        )
        return "trusted-retired" if superseded else "trusted"

    def verdict(self, key_id: str) -> KeyVerdict:
        chain = self.verify_chain()
        if chain.state != "trusted":
            return KeyVerdict("unverifiable", ("chain_not_trusted",) + chain.reasons)
        state = self._derive(self.records, key_id)
        if state == "unknown-key":
            return KeyVerdict("unknown-key", ("key_not_in_history",))
        return KeyVerdict(state, ())


class KeyRing:
    """In-memory key material bound to a verifiable history.

    Registration is not authorisation: material can be registered for a key the
    history knows about, but the resolver still refuses revoked keys, and it
    refuses everything when the history itself stops verifying.
    """

    def __init__(self, history: KeyHistory):
        self.history = history
        self._material: dict[str, bytes] = {}

    def register(self, key_id: str, material: bytes) -> None:
        material = _validate_material(material)
        expected = self.history.digest_for(key_id)
        if expected is None:
            raise KeyLifecycleError("key is not declared in the history")
        if expected != _digest_of(material):
            raise KeyLifecycleError("material does not match the declared key")
        self._material[key_id] = material

    def verdict(self, key_id: str) -> KeyVerdict:
        return self.history.verdict(key_id)

    def resolver(self) -> Callable[[str], bytes | None]:
        def resolve(key_id: str) -> bytes | None:
            if self.history.verdict(key_id).state not in TRUSTED_STATES:
                return None
            return self._material.get(key_id)

        return resolve
