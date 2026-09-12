"""Persistent, verifier-scoped challenge ledger and v2 freshness seals.

The v1 ChallengeBook keeps issued/consumed state in memory. This research
slice persists the state as a hash-chained JSONL event log and binds each
challenge to a verifier audience. It deliberately provides same-host locking
only: fcntl.flock is not a distributed consensus mechanism.

The v2 seal is separate from attestation_freshness' v1 API. It binds verifier
identity into the signature domain without changing the v1 schema or domain.
"""
from __future__ import annotations

import base64
import fcntl
import hashlib
import hmac
import json
import os
import re
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from evidence_proof import ProofAttestation
from proof_signing import ProofSignatureError

SCHEMA = "northstar.challenge-ledger.v1"
SEAL_SCHEMA = "northstar.verifier-bound-seal.v2"
META_SCHEMA = "northstar.challenge-ledger-meta.v1"
ZERO = "sha256:" + "0" * 64
_DOMAIN = b"northstar.verifier-bound-seal.v2"
_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_CHALLENGE = re.compile(r"^[0-9a-f]{32}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SIGNATURE = re.compile(r"^[A-Za-z0-9_-]{16,256}$")
_ACTIONS = frozenset({"issued", "consumed"})
_RECORD_FIELDS = frozenset({
    "schema_version", "sequence", "action", "challenge_id", "verifier_id",
    "issued_at", "expires_at", "key_id", "previous_digest", "record_digest",
})
_SEAL_FIELDS = frozenset({
    "schema_version", "challenge_id", "verifier_id", "key_id",
    "attestation_digest", "signature",
})


class LedgerError(ValueError):
    """Malformed, stale, conflicting, or unavailable ledger state."""


@dataclass(frozen=True)
class LedgerChallenge:
    challenge_id: str
    verifier_id: str
    issued_at: int
    expires_at: int
    key_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "challenge_id": self.challenge_id,
            "verifier_id": self.verifier_id,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "key_id": self.key_id,
        }


@dataclass(frozen=True)
class LedgerVerdict:
    state: str
    reasons: tuple[str, ...] = ()


@dataclass(frozen=True)
class VerifierBoundSeal:
    schema_version: str
    challenge_id: str
    verifier_id: str
    key_id: str
    attestation_digest: str
    signature: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "challenge_id": self.challenge_id,
            "verifier_id": self.verifier_id,
            "key_id": self.key_id,
            "attestation_digest": self.attestation_digest,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, value: Any) -> "VerifierBoundSeal":
        if not isinstance(value, dict) or set(value) != _SEAL_FIELDS:
            raise ProofSignatureError("verifier-bound seal fields invalid")
        if value["schema_version"] != SEAL_SCHEMA:
            raise ProofSignatureError("verifier-bound seal schema invalid")
        if not isinstance(value["challenge_id"], str) or _CHALLENGE.fullmatch(value["challenge_id"]) is None:
            raise ProofSignatureError("verifier-bound seal challenge invalid")
        for field in ("verifier_id", "key_id"):
            if not isinstance(value[field], str) or _ID.fullmatch(value[field]) is None:
                raise ProofSignatureError(f"verifier-bound seal {field} invalid")
        if not isinstance(value["attestation_digest"], str) or _DIGEST.fullmatch(value["attestation_digest"]) is None:
            raise ProofSignatureError("verifier-bound seal attestation digest invalid")
        if not isinstance(value["signature"], str) or _SIGNATURE.fullmatch(value["signature"]) is None:
            raise ProofSignatureError("verifier-bound seal signature invalid")
        return cls(
            SEAL_SCHEMA, value["challenge_id"], value["verifier_id"],
            value["key_id"], value["attestation_digest"], value["signature"],
        )


def _canonical(value: Any) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise LedgerError("value is not canonical JSON") from exc


def _id(value: Any, field: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise LedgerError(f"{field} is invalid")
    return value


def _digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise LedgerError(f"{field} is invalid")
    return value


def _challenge_id(value: Any) -> str:
    if not isinstance(value, str) or _CHALLENGE.fullmatch(value) is None:
        raise LedgerError("challenge_id is invalid")
    return value


def _time(value: Any, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise LedgerError(f"{field} is invalid")
    return value


def _secret(secret: Any) -> bytes:
    if not isinstance(secret, (bytes, bytearray)) or len(secret) < 16:
        raise ProofSignatureError("signing secret is too short")
    return bytes(secret)


def _record_digest(payload: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(_canonical(payload)).hexdigest()


def _attestation_digest(attestation: ProofAttestation) -> str:
    if not isinstance(attestation, ProofAttestation) or attestation.verdict != "verified":
        raise ProofSignatureError("only a verified attestation can be sealed")
    return "sha256:" + hashlib.sha256(_canonical(attestation.to_dict())).hexdigest()


def _seal_payload(challenge_id: str, verifier_id: str,
                  attestation_digest: str, key_id: str) -> bytes:
    return b"\x00".join((
        _DOMAIN, challenge_id.encode("utf-8"), verifier_id.encode("utf-8"),
        attestation_digest.encode("ascii"), key_id.encode("utf-8"),
    ))


def _signature(secret: bytes, challenge_id: str, verifier_id: str,
               attestation_digest: str, key_id: str) -> str:
    digest = hmac.new(
        _secret(secret), _seal_payload(challenge_id, verifier_id,
                                       attestation_digest, key_id), hashlib.sha256
    ).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def _validate_challenge(challenge: LedgerChallenge) -> None:
    if not isinstance(challenge, LedgerChallenge):
        raise ProofSignatureError("challenge is invalid")
    if _CHALLENGE.fullmatch(challenge.challenge_id) is None:
        raise ProofSignatureError("challenge_id is invalid")
    if _ID.fullmatch(challenge.verifier_id) is None:
        raise ProofSignatureError("verifier_id is invalid")
    if not isinstance(challenge.issued_at, int) or not isinstance(challenge.expires_at, int):
        raise ProofSignatureError("challenge timing is invalid")
    if challenge.expires_at < challenge.issued_at:
        raise ProofSignatureError("challenge expiry is invalid")
    if challenge.key_id is not None and _ID.fullmatch(challenge.key_id) is None:
        raise ProofSignatureError("challenge key_id is invalid")


class ChallengeLedger:
    """Same-host persistent challenge state with fail-closed recovery."""

    def __init__(self, root: str | Path, *, clock: Callable[[], int],
                 ttl: int = 300, nonce_source: Callable[[int], bytes] | None = None):
        if not callable(clock):
            raise LedgerError("clock must be callable")
        if not isinstance(ttl, int) or isinstance(ttl, bool) or ttl < 1:
            raise LedgerError("ttl must be positive")
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)
        self.path = self.root / "ledger.jsonl"
        self.lock_path = self.root / "ledger.lock"
        self.meta_path = self.root / "ledger.meta"
        self.clock = clock
        self.ttl = ttl
        self.nonce_source = nonce_source or os.urandom
        self._state_error: str | None = None
        self._ensure_meta()
        self._load_state()

    def _ensure_meta(self) -> None:
        if self.meta_path.exists():
            try:
                value = json.loads(self.meta_path.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise LedgerError("ledger metadata is corrupt") from exc
            if (not isinstance(value, dict)
                    or value.get("schema_version") != META_SCHEMA
                    or not isinstance(value.get("history_started"), bool)):
                raise LedgerError("ledger metadata is invalid")
            return
        value = {"schema_version": META_SCHEMA, "history_started": False}
        self._write_meta(value)

    def _write_meta(self, value: dict[str, Any]) -> None:
        temporary = self.meta_path.with_suffix(".meta.tmp")
        with temporary.open("w", encoding="utf-8") as handle:
            handle.write(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, self.meta_path)
        directory = os.open(self.root, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def _history_started(self) -> bool:
        try:
            value = json.loads(self.meta_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise LedgerError("ledger metadata is corrupt") from exc
        return bool(value.get("history_started"))

    @contextmanager
    def _lock(self):
        with self.lock_path.open("a+") as handle:
            os.chmod(self.lock_path, 0o600)
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def _read_records(self) -> tuple[list[dict[str, Any]], str | None]:
        if not self.path.exists():
            return ([], "history_missing") if self._history_started() else ([], None)
        try:
            raw = self.path.read_bytes()
        except OSError:
            return [], "history_unreadable"
        complete = raw.endswith(b"\n")
        lines = raw.split(b"\n")
        if not complete:
            lines = lines[:-1]
        records: list[dict[str, Any]] = []
        previous = ZERO
        expected = 1
        for line in lines:
            if not line.strip():
                continue
            try:
                value = json.loads(line.decode("utf-8"))
                record = self._parse_record(value)
            except (UnicodeDecodeError, json.JSONDecodeError, LedgerError):
                return records, "history_corrupt"
            if record["sequence"] != expected or record["previous_digest"] != previous:
                return records, "chain_break"
            payload = {key: record[key] for key in _RECORD_FIELDS if key != "record_digest"}
            if _record_digest(payload) != record["record_digest"]:
                return records, "record_digest_mismatch"
            records.append(record)
            previous = record["record_digest"]
            expected += 1
        return records, None

    @staticmethod
    def _parse_record(value: Any) -> dict[str, Any]:
        if not isinstance(value, dict) or set(value) != _RECORD_FIELDS:
            raise LedgerError("ledger record fields invalid")
        if value["schema_version"] != SCHEMA or value["action"] not in _ACTIONS:
            raise LedgerError("ledger record schema/action invalid")
        if not isinstance(value["sequence"], int) or isinstance(value["sequence"], bool) or value["sequence"] < 1:
            raise LedgerError("ledger record sequence invalid")
        _challenge_id(value["challenge_id"])
        _id(value["verifier_id"], "verifier_id")
        issued = _time(value["issued_at"], "issued_at")
        expires = _time(value["expires_at"], "expires_at")
        if expires < issued:
            raise LedgerError("ledger record expiry invalid")
        key_id = value["key_id"]
        if key_id is not None:
            _id(key_id, "key_id")
        _digest(value["previous_digest"], "previous_digest")
        _digest(value["record_digest"], "record_digest")
        return dict(value)

    def _load_state(self) -> None:
        _, error = self._read_records()
        self._state_error = error

    @property
    def records(self) -> list[dict[str, Any]]:
        records, error = self._read_records()
        if error:
            raise LedgerError(error)
        return [dict(record) for record in records]

    def verdict(self) -> LedgerVerdict:
        _, error = self._read_records()
        if error is not None:
            return LedgerVerdict("unverifiable", (error,))
        return LedgerVerdict("replayable", ())

    def _require_healthy(self, records: list[dict[str, Any]], error: str | None) -> None:
        if error is not None:
            raise LedgerError(error)

    def _append(self, records: list[dict[str, Any]], *, action: str,
                challenge: LedgerChallenge) -> dict[str, Any]:
        sequence = len(records) + 1
        previous = records[-1]["record_digest"] if records else ZERO
        payload = {
            "schema_version": SCHEMA, "sequence": sequence, "action": action,
            "challenge_id": challenge.challenge_id, "verifier_id": challenge.verifier_id,
            "issued_at": challenge.issued_at, "expires_at": challenge.expires_at,
            "key_id": challenge.key_id, "previous_digest": previous,
        }
        record = {**payload, "record_digest": _record_digest(payload)}
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(self.path, 0o600)
        if not self._history_started():
            self._write_meta({"schema_version": META_SCHEMA, "history_started": True})
        return record

    def issue(self, *, verifier_id: str, key_id: str | None = None) -> LedgerChallenge:
        verifier = _id(verifier_id, "verifier_id")
        if key_id is not None:
            key_id = _id(key_id, "key_id")
        now = _time(self.clock(), "clock")
        with self._lock():
            records, error = self._read_records()
            self._require_healthy(records, error)
            used = {record["challenge_id"] for record in records}
            for attempt in range(1024):
                raw = self.nonce_source(16)
                if not isinstance(raw, (bytes, bytearray)) or len(raw) < 16:
                    raise LedgerError("nonce source is too short")
                candidate = bytes(raw)[:16].hex()
                if attempt:
                    candidate = hashlib.sha256(
                        candidate.encode("ascii") + str(attempt).encode("ascii")
                    ).hexdigest()[:32]
                if candidate not in used:
                    break
            else:
                raise LedgerError("nonce source exhausted")
            challenge = LedgerChallenge(candidate, verifier, now, now + self.ttl, key_id)
            self._append(records, action="issued", challenge=challenge)
            return challenge

    def consume(self, challenge_id: str, *, verifier_id: str) -> LedgerChallenge:
        challenge_id = _challenge_id(challenge_id)
        verifier_id = _id(verifier_id, "verifier_id")
        now = _time(self.clock(), "clock")
        with self._lock():
            records, error = self._read_records()
            self._require_healthy(records, error)
            issued = [record for record in records
                      if record["challenge_id"] == challenge_id and record["action"] == "issued"]
            if not issued:
                raise LedgerError("challenge is unknown")
            if any(record["challenge_id"] == challenge_id and record["action"] == "consumed"
                   for record in records):
                raise LedgerError("challenge is already consumed")
            record = issued[-1]
            if record["verifier_id"] != verifier_id:
                raise LedgerError("challenge audience mismatch")
            if now > record["expires_at"]:
                raise LedgerError("challenge is expired")
            challenge = LedgerChallenge(
                record["challenge_id"], record["verifier_id"], record["issued_at"],
                record["expires_at"], record["key_id"],
            )
            self._append(records, action="consumed", challenge=challenge)
            return challenge


def seal_v2(attestation: ProofAttestation, challenge: LedgerChallenge, *,
            key_id: str, secret: bytes) -> VerifierBoundSeal:
    _validate_challenge(challenge)
    key_id = _id(key_id, "key_id")
    if challenge.key_id is not None and challenge.key_id != key_id:
        raise ProofSignatureError("challenge key identity mismatch")
    digest = _attestation_digest(attestation)
    return VerifierBoundSeal(
        SEAL_SCHEMA, challenge.challenge_id, challenge.verifier_id, key_id,
        digest, _signature(secret, challenge.challenge_id, challenge.verifier_id,
                           digest, key_id),
    )


def verify_v2(seal: VerifierBoundSeal, attestation: ProofAttestation, *,
              expected_challenge_id: str, expected_verifier_id: str,
              key_resolver: Callable[[str], bytes | None]) -> ProofAttestation:
    if not isinstance(seal, VerifierBoundSeal):
        raise ProofSignatureError("verifier-bound seal is invalid")
    if _challenge_id(expected_challenge_id) != seal.challenge_id:
        raise ProofSignatureError("challenge identity mismatch")
    if _id(expected_verifier_id, "verifier_id") != seal.verifier_id:
        raise ProofSignatureError("verifier audience mismatch")
    digest = _attestation_digest(attestation)
    if digest != seal.attestation_digest:
        raise ProofSignatureError("attestation digest mismatch")
    try:
        secret = key_resolver(seal.key_id)
    except Exception as exc:
        raise ProofSignatureError("key resolver failed") from exc
    if secret is None:
        raise ProofSignatureError("signing key unavailable")
    expected = _signature(secret, seal.challenge_id, seal.verifier_id,
                          seal.attestation_digest, seal.key_id)
    if not hmac.compare_digest(expected, seal.signature):
        raise ProofSignatureError("verifier-bound seal mismatch")
    return attestation


__all__ = [
    "ChallengeLedger", "LedgerChallenge", "LedgerError", "LedgerVerdict",
    "SEAL_SCHEMA", "VerifierBoundSeal", "seal_v2", "verify_v2",
]
