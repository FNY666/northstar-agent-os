"""Push notification service interface (APNs / FCM shaped, simulated).

Research motivation: mobile and desktop agents deliver time-critical
information -- approvals that are about to expire, incident pages,
human-review prompts -- through push notification services. Apple
Push Notification service (APNs) and Firebase Cloud Messaging (FCM)
both reduce to the same three bookkeeping primitives:

- *device token registry*: a (device_id, platform) pair owns exactly
  one push token; the OS rotates tokens, so re-registration refreshes
  the stored token for that device, but the same token may never be
  owned by two devices (that is either a bug or token theft);
- *send*: a message (title, body, optional badge count and data
  payload) is addressed to a registered device and recorded with a
  digest pin; the send *decision* is booked, delivery itself is owned
  by the host/provider;
- *badge*: the app icon badge number is a separate primitive on
  Apple platforms -- it can be set without a visible message.

This module is the *bookkeeping* half of that shape, pinned so the
runtime's notification plumbing speaks one dialect:

- ``PushService`` -- owns the token registry and the message ledger.
  ``register()`` admits or refreshes a device token,
  ``unregister()`` removes a device, ``send()`` records a message,
  ``badge()`` records a badge update, ``report_invalid_token()``
  marks a token as dead (provider feedback channel), and the view
  helpers ``token()`` / ``tokens()`` / ``message()`` read back the
  ledger.
- ``push_service_audit_event(kind, ...)`` -- ``audit.ndjson/1``
  records (``registered`` / ``unregistered`` / ``sent`` / ``badged`` /
  ``invalid-reported`` / ``rejected``); caller-supplied seqs only.

Fail-closed edges (fail loudly, never guess):

- ``device_id`` is a non-empty ``str``; ``platform`` is one of
  ``apns`` / ``fcm``; ``push_token`` is a non-empty ``str``.
- Re-registering a device refreshes its token; registering a token
  already owned by a *different* device raises
  ``DuplicateTokenError`` -- tokens are per-device credentials, not
  shared handles.
- ``send()`` to an unknown device raises ``UnknownDeviceError``; to
  a device whose token was reported invalid raises
  ``InvalidTokenError``. A notification never goes to a guess.
- Title and body are non-empty ``str``; ``badge`` is an ``int``
  (not bool) >= 0 when supplied; the data payload is a mapping of
  non-empty ``str`` -> ``str`` and the serialized (title, body, data)
  envelope is bounded at 4096 bytes (the APNs payload ceiling) --
  ``PayloadTooLargeError`` above it.
- Mutating calls consume strictly increasing caller-supplied int
  seqs (no wall-clock); rewinds raise ``SeqOrderError``.

Honest scope:

- This module books *send decisions*, not deliveries. It cannot prove
  a device displayed anything, nor that a provider accepted the
  envelope -- ``sent`` means "the runtime decided to send", never
  "the user saw it". A lying host gets a lying send ledger.
- Invalid-token feedback is host-reported; the module trusts the
  provider channel that feeds it.
- In-memory only: pair with the durable audit writer if the send
  history must survive a restart. ``main()`` self-checks the shape.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any, Mapping, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json, jcs_sha256_hex
except Exception:  # pragma: no cover - module must stay importable standalone
    import hashlib as _hashlib
    import json as _json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return _json.dumps(obj, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=True).encode("utf-8")

    def jcs_sha256_hex(obj: Any) -> str:  # type: ignore[no-redef]
        return _hashlib.sha256(jcs_canonical_json(obj)).hexdigest()


#: Version pin for this module's record shape.
PUSH_SERVICE_VERSION = "push-service.v1"

#: Schema pin carried by records and audit events.
PUSH_SERVICE_SCHEMA = "northstar.push-service.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Supported push platforms.
APNS = "apns"
FCM = "fcm"
_PLATFORMS = (APNS, FCM)

#: APNs payload ceiling, in bytes of the serialized envelope.
MAX_PAYLOAD_BYTES = 4096

#: Audit event kinds.
KIND_REGISTERED = "registered"
KIND_UNREGISTERED = "unregistered"
KIND_SENT = "sent"
KIND_BADGED = "badged"
KIND_INVALID_REPORTED = "invalid-reported"
_KINDS = (
    KIND_REGISTERED,
    KIND_UNREGISTERED,
    KIND_SENT,
    KIND_BADGED,
    KIND_INVALID_REPORTED,
)


class PushServiceError(Exception):
    """Base error for the push service."""


class UnknownDeviceError(PushServiceError):
    """Device id is not known to the registry."""


class InvalidTokenError(PushServiceError):
    """The device's push token was reported invalid by the provider."""


class DuplicateTokenError(PushServiceError):
    """This push token is already owned by a different device."""


class BadPayloadError(PushServiceError):
    """Title, body, badge, or data payload is malformed."""


class PayloadTooLargeError(PushServiceError):
    """The serialized notification envelope exceeds 4096 bytes."""


class SeqOrderError(PushServiceError):
    """Caller seqs must be strictly increasing across mutations."""


def _check_seq(seq: Any, what: str = "seq") -> int:
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
        raise PushServiceError(f"{what} must be an int >= 0 (not bool)")
    return seq


def _check_str(value: Any, what: str) -> str:
    if not isinstance(value, str) or not value:
        raise PushServiceError(f"{what} must be a non-empty str")
    return value


def _check_str_map(value: Any, what: str) -> Tuple[Tuple[str, str], ...]:
    if not isinstance(value, Mapping):
        raise PushServiceError(f"{what} must be a mapping of str -> str")
    items = []
    for k, v in value.items():
        if not isinstance(k, str) or not k:
            raise PushServiceError(f"{what} keys must be non-empty str")
        if not isinstance(v, str):
            raise PushServiceError(f"{what} values must be str")
        items.append((k, v))
    return tuple(sorted(items))


def _check_badge(value: Any, what: str = "badge") -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise PushServiceError(f"{what} must be an int >= 0 (not bool)")
    return value


def _pin(*parts: Any) -> str:
    return "sha256:" + jcs_sha256_hex(list(parts))


@dataclass(frozen=True)
class TokenRecord:
    """One registered device token, digest-pinned."""

    device_id: str
    platform: str
    push_token: str
    seq: int
    invalid: bool
    digest: str
    version: str = PUSH_SERVICE_VERSION
    schema: str = PUSH_SERVICE_SCHEMA


@dataclass(frozen=True)
class SendRecord:
    """One recorded push send, digest-pinned."""

    message_id: str
    device_id: str
    title: str
    body: str
    badge: Optional[int]
    data: Tuple[Tuple[str, str], ...]
    seq: int
    digest: str
    version: str = PUSH_SERVICE_VERSION
    schema: str = PUSH_SERVICE_SCHEMA


@dataclass(frozen=True)
class BadgeRecord:
    """One badge-number update, digest-pinned."""

    device_id: str
    count: int
    seq: int
    digest: str
    version: str = PUSH_SERVICE_VERSION
    schema: str = PUSH_SERVICE_SCHEMA


@dataclass(frozen=True)
class InvalidTokenRecord:
    """One provider invalid-token report, digest-pinned."""

    push_token: str
    seq: int
    digest: str
    version: str = PUSH_SERVICE_VERSION
    schema: str = PUSH_SERVICE_SCHEMA


@dataclass(frozen=True)
class UnregisterRecord:
    """One device unregistration, digest-pinned."""

    device_id: str
    seq: int
    digest: str
    version: str = PUSH_SERVICE_VERSION
    schema: str = PUSH_SERVICE_SCHEMA


class PushService:
    """APNs/FCM-shaped push notification bookkeeping, single host."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._tokens: dict[str, TokenRecord] = {}      # device_id -> record
        self._token_owner: dict[str, str] = {}         # push_token -> device_id
        self._messages: dict[str, SendRecord] = {}     # message_id -> record
        self._order: list[str] = []                     # send order
        self._next_message = 0
        self._last_seq = -1

    # -- internal ---------------------------------------------------

    def _consume_seq(self, seq: int) -> None:
        _check_seq(seq)
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq {seq} is not strictly greater than last seq {self._last_seq}"
            )
        self._last_seq = seq

    # -- token registry ---------------------------------------------

    def register(
        self, device_id: str, platform: str, push_token: str, seq: int
    ) -> TokenRecord:
        """Admit or refresh a device's push token (idempotent refresh)."""
        _check_str(device_id, "device_id")
        if platform not in _PLATFORMS:
            raise PushServiceError(
                f"platform must be one of {_PLATFORMS}"
            )
        _check_str(push_token, "push_token")
        with self._lock:
            self._consume_seq(seq)
            owner = self._token_owner.get(push_token)
            if owner is not None and owner != device_id:
                raise DuplicateTokenError(
                    f"push token is already owned by device {owner!r}"
                )
            old = self._tokens.get(device_id)
            if old is not None and old.push_token != push_token:
                # Token rotation: release the old token's ownership.
                del self._token_owner[old.push_token]
            digest = _pin(["token", device_id, platform, push_token, seq])
            record = TokenRecord(
                device_id=device_id,
                platform=platform,
                push_token=push_token,
                seq=seq,
                invalid=False,
                digest=digest,
            )
            self._tokens[device_id] = record
            self._token_owner[push_token] = device_id
            return record

    def unregister(self, device_id: str, seq: int) -> UnregisterRecord:
        """Remove a device from the registry."""
        _check_str(device_id, "device_id")
        with self._lock:
            self._consume_seq(seq)
            record = self._tokens.pop(device_id, None)
            if record is None:
                raise UnknownDeviceError(f"unknown device {device_id!r}")
            del self._token_owner[record.push_token]
            digest = _pin(["unregister", device_id, seq])
            return UnregisterRecord(device_id=device_id, seq=seq, digest=digest)

    def token(self, device_id: str) -> TokenRecord:
        """The token record for a device (raises on unknown)."""
        _check_str(device_id, "device_id")
        with self._lock:
            record = self._tokens.get(device_id)
            if record is None:
                raise UnknownDeviceError(f"unknown device {device_id!r}")
            return record

    def tokens(self) -> Tuple[TokenRecord, ...]:
        """All token records, sorted by device id."""
        with self._lock:
            return tuple(sorted(self._tokens.values(), key=lambda r: r.device_id))

    # -- provider feedback ------------------------------------------

    def report_invalid_token(self, push_token: str, seq: int) -> InvalidTokenRecord:
        """Mark a push token invalid (provider feedback channel)."""
        _check_str(push_token, "push_token")
        with self._lock:
            self._consume_seq(seq)
            owner = self._token_owner.get(push_token)
            if owner is None:
                raise PushServiceError("reported token is not registered")
            record = self._tokens[owner]
            self._tokens[owner] = TokenRecord(
                device_id=record.device_id,
                platform=record.platform,
                push_token=record.push_token,
                seq=record.seq,
                invalid=True,
                digest=record.digest,
            )
            digest = _pin(["invalid", push_token, seq])
            return InvalidTokenRecord(push_token=push_token, seq=seq, digest=digest)

    # -- sending ----------------------------------------------------

    @staticmethod
    def _envelope_bytes(title: str, body: str,
                        data: Tuple[Tuple[str, str], ...]) -> bytes:
        return jcs_canonical_json(
            {"title": title, "body": body, "data": [list(p) for p in data]}
        )

    def send(
        self,
        device_id: str,
        title: str,
        body: str,
        seq: int,
        badge: Optional[int] = None,
        data: Optional[Mapping[str, str]] = None,
    ) -> SendRecord:
        """Record a push send to a registered, valid device."""
        _check_str(device_id, "device_id")
        _check_str(title, "title")
        _check_str(body, "body")
        badge_value = None if badge is None else _check_badge(badge)
        data_items = _check_str_map(data or {}, "data")
        envelope = self._envelope_bytes(title, body, data_items)
        if len(envelope) > MAX_PAYLOAD_BYTES:
            raise PayloadTooLargeError(
                f"notification envelope is {len(envelope)} bytes, "
                f"ceiling is {MAX_PAYLOAD_BYTES}"
            )
        with self._lock:
            self._consume_seq(seq)
            record = self._tokens.get(device_id)
            if record is None:
                raise UnknownDeviceError(f"unknown device {device_id!r}")
            if record.invalid:
                raise InvalidTokenError(
                    f"push token for device {device_id!r} was reported invalid"
                )
            self._next_message += 1
            message_id = f"msg-{self._next_message}"
            digest = _pin(["send", message_id, device_id, title, body,
                           badge_value, [list(data_items)], seq])
            send_record = SendRecord(
                message_id=message_id,
                device_id=device_id,
                title=title,
                body=body,
                badge=badge_value,
                data=data_items,
                seq=seq,
                digest=digest,
            )
            self._messages[message_id] = send_record
            self._order.append(message_id)
            return send_record

    def badge(self, device_id: str, count: int, seq: int) -> BadgeRecord:
        """Record a badge-number update for a registered device."""
        _check_str(device_id, "device_id")
        _check_badge(count, "count")
        with self._lock:
            self._consume_seq(seq)
            record = self._tokens.get(device_id)
            if record is None:
                raise UnknownDeviceError(f"unknown device {device_id!r}")
            if record.invalid:
                raise InvalidTokenError(
                    f"push token for device {device_id!r} was reported invalid"
                )
            digest = _pin(["badge", device_id, count, seq])
            return BadgeRecord(device_id=device_id, count=count, seq=seq,
                               digest=digest)

    def message(self, message_id: str) -> SendRecord:
        """A recorded send, by id."""
        _check_str(message_id, "message_id")
        with self._lock:
            record = self._messages.get(message_id)
            if record is None:
                raise PushServiceError(f"unknown message {message_id!r}")
            return record

    def messages(self) -> Tuple[SendRecord, ...]:
        """All recorded sends, in send order."""
        with self._lock:
            return tuple(self._messages[mid] for mid in self._order)


def push_service_audit_event(kind: str, seq: int, **fields: Any) -> Mapping[str, Any]:
    """Shape an ``audit.ndjson/1`` record for a push-service event."""
    if kind not in _KINDS:
        raise PushServiceError(f"unknown audit kind {kind!r}")
    _check_seq(seq)
    for key in ("push_token", "secret", "raw_token"):
        if key in fields:
            raise PushServiceError(f"field {key!r} must not cross the audit boundary")
    event = {
        "kind": kind,
        "seq": seq,
        "schema": AUDIT_SCHEMA,
        "module": PUSH_SERVICE_SCHEMA,
    }
    event.update({k: v for k, v in fields.items()})
    return event


def main() -> None:
    ps = PushService()
    r = ps.register("dev-1", APNS, "tok-aaa", 1)
    assert r.invalid is False
    # Re-registration refreshes the token (OS rotation).
    r2 = ps.register("dev-1", APNS, "tok-bbb", 2)
    assert ps.token("dev-1").push_token == "tok-bbb"
    # Same token on a second device is refused.
    try:
        ps.register("dev-2", FCM, "tok-bbb", 3)
    except DuplicateTokenError:
        pass
    else:  # pragma: no cover
        raise AssertionError("expected DuplicateTokenError")
    m = ps.send("dev-1", "Approval needed", "Run #42 expires soon", 4,
                badge=1, data={"run": "42"})
    assert m.message_id == "msg-1" and m.badge == 1
    b = ps.badge("dev-1", 0, 5)
    assert b.count == 0
    inv = ps.report_invalid_token("tok-bbb", 6)
    assert inv.push_token == "tok-bbb"
    try:
        ps.send("dev-1", "Hi", "there", 7)
    except InvalidTokenError:
        pass
    else:  # pragma: no cover
        raise AssertionError("expected InvalidTokenError")
    push_service_audit_event(KIND_SENT, 8, message_id=m.message_id)
    print("push-service OK: register, rotate, dedup, send, badge, invalid, audit")


if __name__ == "__main__":
    main()
