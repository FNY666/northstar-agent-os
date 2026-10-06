"""Inter-agent message signing and provenance (beyond delegation tokens).

arXiv:2609.22949 found agent-to-agent message signing + provenance
tracking reduced inter-agent injection by 91%. Northstar already signs
delegation *tokens*; this module signs ordinary *messages* so agent A
cannot forge a message claiming to be from agent B on the message bus.

Design:
- Each message carries sender_id, recipient_id, payload, timestamp, nonce.
- Ed25519 signature covers the canonical body (all fields except signature).
- Verification checks: signature, timestamp freshness (max_age_seconds),
  and nonce uniqueness (replay prevention) via an in-memory NonceTracker.
- NonceTracker is bounded: nonces expire after max_age_seconds so the
  set cannot grow without limit.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class SignedMessage:
    """One signed inter-agent message."""

    sender_id: str
    recipient_id: str
    payload: dict[str, Any]
    timestamp: float
    nonce: str
    signature: str = ""  # hex, 64 bytes

    def _signing_body(self) -> dict[str, Any]:
        return {
            "sender_id": self.sender_id,
            "recipient_id": self.recipient_id,
            "payload": self.payload,
            "timestamp": self.timestamp,
            "nonce": self.nonce,
        }

    def as_dict(self) -> dict[str, Any]:
        return {**self._signing_body(), "signature": self.signature}

    @classmethod
    def from_dict(cls, doc: dict[str, Any]) -> "SignedMessage":
        return cls(
            sender_id=str(doc["sender_id"]),
            recipient_id=str(doc["recipient_id"]),
            payload=dict(doc["payload"]),
            timestamp=float(doc["timestamp"]),
            nonce=str(doc["nonce"]),
            signature=str(doc.get("signature", "")),
        )


def sign_message(
    sender_id: str,
    sender_seed: bytes,
    recipient_id: str,
    payload: dict[str, Any],
    *,
    timestamp: float | None = None,
    nonce: str | None = None,
) -> SignedMessage:
    """Sign a message from sender to recipient. Raises on bad inputs."""
    if not sender_id or not recipient_id:
        raise ValueError("sender_id and recipient_id must be non-empty")
    if not isinstance(sender_seed, (bytes, bytearray)) or len(sender_seed) != 32:
        raise ValueError("sender_seed must be a 32-byte Ed25519 seed")
    try:
        from ed25519 import sign as ed_sign
    except ImportError as e:
        raise RuntimeError("ed25519 module unavailable") from e
    ts = time.time() if timestamp is None else float(timestamp)
    unsigned = SignedMessage(
        sender_id=sender_id,
        recipient_id=recipient_id,
        payload=dict(payload),
        timestamp=ts,
        nonce=nonce or uuid.uuid4().hex,
    )
    body = json.dumps(unsigned._signing_body(), sort_keys=True).encode()
    sig = ed_sign(bytes(sender_seed), body).hex()
    return SignedMessage(
        sender_id=unsigned.sender_id,
        recipient_id=unsigned.recipient_id,
        payload=unsigned.payload,
        timestamp=unsigned.timestamp,
        nonce=unsigned.nonce,
        signature=sig,
    )


@dataclass
class NonceTracker:
    """Replay prevention: remembers seen nonces until they expire.

    Bounded: a nonce is kept for ``max_age_seconds`` after first seen, then
    dropped. ``seen`` returns True for a fresh nonce (and records it), False
    for a replay or an expired-window duplicate.
    """

    max_age_seconds: float = 300.0
    _seen: dict[str, float] = field(default_factory=dict, repr=False)

    def _prune(self, now: float) -> None:
        cutoff = now - self.max_age_seconds
        expired = [n for n, ts in self._seen.items() if ts < cutoff]
        for n in expired:
            del self._seen[n]

    def check(self, nonce: str, now: float | None = None) -> bool:
        """True if the nonce is fresh (records it); False if replayed."""
        ts = time.time() if now is None else float(now)
        self._prune(ts)
        if nonce in self._seen:
            return False
        self._seen[nonce] = ts
        return True


def verify_message(
    msg: SignedMessage,
    sender_pubkey: bytes,
    *,
    max_age_seconds: float = 300.0,
    now: float | None = None,
    nonce_tracker: NonceTracker | None = None,
) -> bool:
    """Verify a signed inter-agent message.

    Checks: signature, timestamp freshness, nonce uniqueness (when a
    tracker is supplied). False on any defect; never raises.
    """
    try:
        if not isinstance(sender_pubkey, (bytes, bytearray)) or len(sender_pubkey) != 32:
            return False
        if len(msg.signature) != 128:
            return False
        signature = bytes.fromhex(msg.signature)
        try:
            from ed25519 import verify as ed_verify
        except ImportError:
            return False
        body = json.dumps(msg._signing_body(), sort_keys=True).encode()
        if not bool(ed_verify(bytes(sender_pubkey), body, signature)):
            return False
        ts = time.time() if now is None else float(now)
        if abs(ts - msg.timestamp) > max_age_seconds:
            return False
        if nonce_tracker is not None and not nonce_tracker.check(msg.nonce, now=ts):
            return False
        return True
    except (ValueError, TypeError):
        return False
