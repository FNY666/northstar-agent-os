"""Idempotency key manager: safe retries without duplicate execution.

A client assigns an opaque idempotency ``key`` to one logical operation.
``IdempotencyManager.check_or_store(key, result, payload=..., seq=...)``
stores the result on first sight and returns the cached result on every
retry with the same key -- the operation's effect is applied once no matter
how many times the caller retries.

Payload binding (the load-bearing rule): a key is bound to the payload it
was first stored with. A retry presenting the *same* key with a *different*
payload raises ``PayloadMismatchError`` fail-closed. Without this binding,
a key collision across two different logical operations would silently
return the wrong cached result -- the dangerous failure mode of naive
idempotency tables.

House style: frozen dataclasses, no wall-clock (caller-supplied int seqs),
fail-closed validation (``TypeError``/``ValueError``/``PayloadMismatchError``
on malformed or conflicting input), stdlib-only, deterministic, version and
schema pins, ``main()`` self-check.

Honest scope: this is a *caller-reported* idempotency ledger. It records
that a key was seen and what result was stored; it cannot prove the host
actually executed the operation exactly once (that is the executor's job),
and it cannot see operations the host never reports. A cache hit means
"this key was already stored", never "the world changed exactly once".
Results are pinned by ``sha256:`` digests of canonical JSON; results that
are not JSON-canonicalizable (NaN/inf, non-str dict keys, arbitrary objects)
are rejected fail-closed rather than hashed ambiguously.

Version pin: idempotency-manager.v1
Schema pin: northstar.idempotency-manager.v1
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from typing import Any, Optional

IDEMPOTENCY_MANAGER_VERSION = "idempotency-manager.v1"
SCHEMA_PIN = "northstar.idempotency-manager.v1"

_MAX_KEY_LEN = 1024


class IdempotencyError(Exception):
    """Base class for idempotency-manager errors."""


class PayloadMismatchError(IdempotencyError):
    """Raised when a known key is retried with a different payload.

    The key is bound to the payload it was first stored with; a different
    payload under the same key is a key-reuse bug or a confused caller, and
    returning the old cached result would be silently wrong.
    """


def _require_key(key: Any) -> str:
    if not isinstance(key, str):
        raise TypeError(f"key must be a str, got {type(key).__name__}")
    if not key:
        raise ValueError("key must be non-empty")
    if len(key) > _MAX_KEY_LEN:
        raise ValueError(f"key must be at most {_MAX_KEY_LEN} chars")
    return key


def _require_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise TypeError(f"seq must be an int, got {type(seq).__name__}")
    if seq < 0:
        raise ValueError("seq must be non-negative")
    return seq


def _canonical(value: Any) -> bytes:
    """Canonical JSON bytes for digesting; rejects non-canonicalizable input."""
    if value is None or isinstance(value, bool):
        pass
    elif isinstance(value, int):
        pass
    elif isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise TypeError("result/payload must not contain NaN or infinity")
    elif isinstance(value, str):
        pass
    elif isinstance(value, (list, tuple)):
        for item in value:
            _canonical(item)
    elif isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                raise TypeError("dict keys must be str for canonicalization")
            _canonical(v)
    else:
        raise TypeError(
            f"value of type {type(value).__name__} is not JSON-canonicalizable"
        )
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _require_result_hash(value: Any) -> str:
    if not isinstance(value, str):
        raise TypeError(f"result_hash must be a str, got {type(value).__name__}")
    if not value.startswith("sha256:") or len(value) != len("sha256:") + 64:
        raise ValueError("result_hash must look like 'sha256:' + 64 hex chars")
    hexpart = value[len("sha256:") :]
    if any(c not in "0123456789abcdef" for c in hexpart):
        raise ValueError("result_hash hex part must be lowercase hex")
    return value


@dataclass(frozen=True)
class IdempotencyKey:
    """An idempotency key paired with the digest of its stored result."""

    key: str
    result_hash: str
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        _require_key(self.key)
        _require_result_hash(self.result_hash)

    def as_dict(self) -> dict:
        return {
            "key": self.key,
            "result_hash": self.result_hash,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class IdempotencyRecord:
    """Internal stored record for one key (frozen)."""

    key: str
    payload_digest: Optional[str]
    result_digest: str
    result: Any
    first_seq: int
    schema: str = SCHEMA_PIN

    def as_dict(self) -> dict:
        return {
            "key": self.key,
            "payload_digest": self.payload_digest,
            "result_digest": self.result_digest,
            "first_seq": self.first_seq,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class IdempotencyOutcome:
    """Result of ``check_or_store`` (frozen).

    ``hit`` is False on first store, True on replay. ``result`` is always the
    canonical stored result (on a hit, the caller's freshly supplied result is
    *not* adopted). ``result_consistent`` reports whether the caller-supplied
    result on a hit digested to the same value as the stored one -- False is
    an informational signal that the operation may be non-deterministic, not
    an error: the stored (first) result remains the truth.
    """

    hit: bool
    result: Any
    result_digest: str
    payload_digest: Optional[str]
    first_seq: int
    result_consistent: bool
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        if not isinstance(self.hit, bool):
            raise TypeError("hit must be a bool")
        if not isinstance(self.result_consistent, bool):
            raise TypeError("result_consistent must be a bool")
        _require_result_hash(self.result_digest)
        if self.payload_digest is not None:
            _require_result_hash(self.payload_digest)
        _require_seq(self.first_seq)

    def as_dict(self) -> dict:
        return {
            "hit": self.hit,
            "result_digest": self.result_digest,
            "payload_digest": self.payload_digest,
            "first_seq": self.first_seq,
            "result_consistent": self.result_consistent,
            "schema": self.schema,
        }


class IdempotencyManager:
    """In-memory idempotency ledger over caller-supplied keys.

    ``check_or_store(key, result, payload=None, seq=0)``: first sight stores
    the result and returns ``hit=False``; a retry with the same key and the
    same payload returns the cached result with ``hit=True``. A retry with a
    different payload raises ``PayloadMismatchError``. Persistence across
    restarts is the host's job -- this ledger is in-memory by design.
    """

    def __init__(self) -> None:
        self._records: dict[str, IdempotencyRecord] = {}

    def check_or_store(
        self,
        key: str,
        result: Any,
        payload: Any = None,
        seq: int = 0,
    ) -> IdempotencyOutcome:
        _require_key(key)
        _require_seq(seq)
        result_digest = _digest(result)
        payload_digest = None if payload is None else _digest(payload)

        existing = self._records.get(key)
        if existing is None:
            self._records[key] = IdempotencyRecord(
                key=key,
                payload_digest=payload_digest,
                result_digest=result_digest,
                result=result,
                first_seq=seq,
            )
            return IdempotencyOutcome(
                hit=False,
                result=result,
                result_digest=result_digest,
                payload_digest=payload_digest,
                first_seq=seq,
                result_consistent=True,
            )

        if existing.payload_digest != payload_digest:
            raise PayloadMismatchError(
                f"key {key!r} already stored with a different payload"
            )
        return IdempotencyOutcome(
            hit=True,
            result=existing.result,
            result_digest=existing.result_digest,
            payload_digest=existing.payload_digest,
            first_seq=existing.first_seq,
            result_consistent=(result_digest == existing.result_digest),
        )

    def lookup(self, key: str) -> Optional[IdempotencyKey]:
        """Return the ``IdempotencyKey`` for a stored key, or None."""
        _require_key(key)
        record = self._records.get(key)
        if record is None:
            return None
        return IdempotencyKey(key=record.key, result_hash=record.result_digest)

    def stored_keys(self) -> tuple[str, ...]:
        """Keys stored so far, in first-seen order (deterministic)."""
        return tuple(self._records.keys())

    def __len__(self) -> int:
        return len(self._records)


def idempotency_audit_event(key: str, outcome: IdempotencyOutcome, seq: int) -> dict:
    """Build an ``audit.ndjson/1``-shaped record for a ``check_or_store`` call.

    The raw key is never emitted -- only its digest -- so a key that embeds
    sensitive context does not leak through the audit trail.
    """
    _require_key(key)
    if not isinstance(outcome, IdempotencyOutcome):
        raise TypeError("outcome must be an IdempotencyOutcome")
    _require_seq(seq)
    return {
        "event": "idempotency-replay" if outcome.hit else "idempotency-store",
        "key_digest": _key_digest(key),
        "hit": outcome.hit,
        "result_digest": outcome.result_digest,
        "payload_digest": outcome.payload_digest,
        "first_seq": outcome.first_seq,
        "result_consistent": outcome.result_consistent,
        "audit_seq": seq,
        "schema": SCHEMA_PIN,
    }


def _key_digest(key: str) -> str:
    return "sha256:" + hashlib.sha256(key.encode("utf-8")).hexdigest()


def main() -> None:
    mgr = IdempotencyManager()
    first = mgr.check_or_store("op-1", {"status": "ok"}, payload={"x": 1}, seq=3)
    assert not first.hit and first.first_seq == 3
    replay = mgr.check_or_store("op-1", {"status": "ok"}, payload={"x": 1}, seq=9)
    assert replay.hit and replay.first_seq == 3 and replay.result_consistent
    try:
        mgr.check_or_store("op-1", {"status": "ok"}, payload={"x": 2}, seq=10)
    except PayloadMismatchError:
        pass
    else:
        raise AssertionError("payload mismatch should raise")
    assert mgr.lookup("op-1") is not None
    assert mgr.lookup("missing") is None
    print("idempotency-manager OK: store, replay-hit, payload-mismatch raises")


if __name__ == "__main__":
    main()
