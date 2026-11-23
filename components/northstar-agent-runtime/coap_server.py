"""CoAP server: simulated RFC 7252 constrained-application-protocol ledger.

Research motivation: agents that command constrained devices (sensors,
actuators, edge microcontrollers) need a UDP-friendly, low-overhead
request/response protocol. CoAP (RFC 7252) is the IETF answer -- a
binary protocol over UDP with 4-byte fixed headers, a compact method
code space (0.01-0.04 plus FETCH/PATCH/iPATCH from RFC 8132), a dotted
response-code taxonomy (2.xx/4.xx/5.xx), and extensions for exactly
the problems constrained networks create: observe (RFC 7641 --
subscribe to resource changes instead of polling) and block-wise
transfer (RFC 7959 -- chunk payloads into MTU-safe blocks).

This module pins down the *server* side of that contract: resource
registration, observation bookkeeping, and block-wise transfer
continuity. It is deliberately distinct from ``http_client.py``
(TCP request/response, headers, status lines) and
``message_queue.py`` (at-least-once pub/sub): here the load-bearing
semantics are the observe sequence contract (24-bit monotonically
increasing, modulo 2^24) and block-transfer continuity (each block
NUM must advance the in-flight transfer by exactly one).

Public API:

- ``CoAPServer`` -- RLock-guarded resource ledger.
  ``resource(path, seq, methods=("GET",), content_format="",
  observe_allowed=False)`` registers a path (returns a frozen
  ``ResourceRecord``). ``observe(path, observer_id, seq)`` books an
  RFC 7641 registration (returns a frozen ``Observation`` with
  ``observe_seq=0``). ``cancel_observe(path, observer_id, seq)``
  books deregistration. ``notify(path, seq, payload=None,
  msg_type=MSG_NON)`` emits a notification to every active
  observation of ``path`` (returns a frozen ``NotificationReport``).
  ``block(path, seq, block_no=0, more=False, block_size=1024,
  payload=None)`` books one block-wise arrival and enforces
  continuity (returns a frozen ``BlockRecord``; ``state`` is data:
  ``"in-progress"`` or ``"complete"``). ``resources()`` /
  ``observations(path=None)`` / ``stats()`` views.
- ``ResourceRecord`` / ``Observation`` / ``ObserveCancelRecord`` /
  ``Notification`` / ``NotificationReport`` / ``BlockRecord`` --
  frozen records with ``sha256:`` digest pins.
- ``coap_server_audit_event(kind, seq, ...)`` -- ``audit.ndjson/1``
  records, fixed kind vocabulary: ``"resource-registered"``,
  ``"observed"``, ``"observation-cancelled"``, ``"notified"``,
  ``"block-received"``, ``"block-completed"``, ``"rejected"``.

Honest scope:

- Simulated -- no UDP, no sockets, no wire bytes, no retransmission
  timers. The server books *reported* requests; a host that lies
  about arrivals gets a perfectly consistent ledger of lies (same
  GIGO boundary as every other bookkeeping module in this tree).
- Message IDs are server-issued and monotonic modulo 2^16. They
  book order, never uniqueness across the network: without a real
  UDP layer there is no congestion window, no ACK bookkeeping, no
  duplicate detection. CON messages are *marked* confirmable, not
  retransmitted -- pair with ``timeout_manager`` for real timeouts.
- Observe notifications are fan-out records, not delivery proof: a
  ``Notification`` means the server declared the state change, never
  that the observer received it. An observer that never cancels keeps
  a consistent -- and growing -- notification ledger.
- Block digests bind block content and NUM order, not reassembly: a
  ``complete`` state means every NUM in [0..N] was booked exactly
  once, never that the reassembled bytes are meaningful. The server
  stores payload digests, not payloads beyond the pinned size
  guardrail.
- MAX_AGE / ETag / conditional requests (RFC 7252 section 5.10) are
  not booked here; response freshness lives in ``cache_manager`` if
  needed.

Version pin: ``coap-server.v1`` / schema pin
``northstar.coap-server.v1``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

#: Module version.
COAP_SERVER_VERSION = "coap-server.v1"

#: Schema pin for records produced by this module.
SCHEMA_PIN = "northstar.coap-server.v1"

#: Version pin carried inside audit records.
AUDIT_FORMAT = "audit.ndjson/1"

#: Fixed vocabulary for audit event kinds.
_AUDIT_KINDS = frozenset(
    {
        "resource-registered",
        "observed",
        "observation-cancelled",
        "notified",
        "block-received",
        "block-completed",
        "rejected",
    }
)

#: Digest domain prefix; keeps pins distinct from sibling modules.
_DIGEST_DOMAIN = b"northstar-coap-server.v1\x00"

#: RFC 7252 methods plus RFC 8132 extensions this server books.
METHOD_GET = "GET"
METHOD_POST = "POST"
METHOD_PUT = "PUT"
METHOD_DELETE = "DELETE"
METHOD_FETCH = "FETCH"
METHOD_PATCH = "PATCH"
METHOD_IPATCH = "iPATCH"
_METHODS = frozenset(
    {
        METHOD_GET,
        METHOD_POST,
        METHOD_PUT,
        METHOD_DELETE,
        METHOD_FETCH,
        METHOD_PATCH,
        METHOD_IPATCH,
    }
)

#: Methods that are safe (RFC 7252 section 5.8.1): no state change implied.
_SAFE_METHODS = frozenset({METHOD_GET, METHOD_FETCH})

#: Methods that are idempotent: repeating the booking changes nothing.
_IDEMPOTENT_METHODS = frozenset(
    {METHOD_GET, METHOD_PUT, METHOD_DELETE, METHOD_FETCH, METHOD_IPATCH}
)

#: CoAP message types (RFC 7252 section 4).
MSG_CON = "CON"
MSG_NON = "NON"
MSG_ACK = "ACK"
MSG_RST = "RST"
_MSG_TYPES = frozenset({MSG_CON, MSG_NON, MSG_ACK, MSG_RST})

#: Response-code vocabulary we book (dotted classes per RFC 7252).
RESP_201_CREATED = "2.01"
RESP_202_DELETED = "2.02"
RESP_203_VALID = "2.03"
RESP_204_CHANGED = "2.04"
RESP_205_CONTENT = "2.05"
RESP_400_BAD_REQUEST = "4.00"
RESP_404_NOT_FOUND = "4.04"
RESP_405_METHOD_NOT_ALLOWED = "4.05"
RESP_408_REQUEST_ENTITY_INCOMPLETE = "4.08"
_RESPONSES = frozenset(
    {
        RESP_201_CREATED,
        RESP_202_DELETED,
        RESP_203_VALID,
        RESP_204_CHANGED,
        RESP_205_CONTENT,
        RESP_400_BAD_REQUEST,
        RESP_404_NOT_FOUND,
        RESP_405_METHOD_NOT_ALLOWED,
        RESP_408_REQUEST_ENTITY_INCOMPLETE,
    }
)

#: RFC 7959 block sizes (SZX 0..6 -> 16..1024 bytes).
_BLOCK_SIZES = frozenset({16, 32, 64, 128, 256, 512, 1024})

#: RFC 7959 NUM field is 20 bits.
_MAX_BLOCK_NO = (1 << 20) - 1

#: RFC 7641 observe option sequence number is 24 bits and wraps.
_OBSERVE_SEQ_MOD = 1 << 24

#: CoAP message ID is 16 bits and wraps (bookkeeping only).
_MSG_ID_MOD = 1 << 16

#: Guardrails.
_MAX_PATH_LEN = 255
_MAX_OBSERVER_ID_LEN = 256
_MAX_PAYLOAD_BYTES = 64 * 1024
_MAX_RESOURCES = 10_000
_MAX_OBSERVATIONS = 100_000


class CoAPServerError(Exception):
    """Base error for CoAP server failures. Fail-closed, never silent."""


class DuplicateResourceError(CoAPServerError):
    """Raised when registering a path that already exists."""


class UnknownResourceError(CoAPServerError):
    """Raised when operating on a path that was never registered."""


class BadResourceError(CoAPServerError):
    """Raised on path/method validation failures."""


class ObserveNotAllowedError(CoAPServerError):
    """Raised when observing a resource registered without observe support."""


class DuplicateObservationError(CoAPServerError):
    """Raised when an active observation already exists for (path, observer)."""


class UnknownObservationError(CoAPServerError):
    """Raised when cancelling or notifying an observation that does not exist."""


class BadBlockError(CoAPServerError):
    """Raised on block-wise transfer violations (bad NUM/size/continuity)."""


class BadResponseError(CoAPServerError):
    """Raised on unknown response codes or message types."""


def _check_seq(seq: object) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise TypeError(f"seq must be int, got {type(seq).__name__}")
    if seq < 0:
        raise ValueError("seq must be non-negative")
    return seq


def _check_path(path: object) -> str:
    if isinstance(path, bool) or not isinstance(path, str):
        raise TypeError(f"path must be str, got {type(path).__name__}")
    if not path:
        raise BadResourceError("path must be non-empty")
    if not path.startswith("/"):
        raise BadResourceError("path must start with '/'")
    if len(path) > _MAX_PATH_LEN:
        raise BadResourceError(f"path exceeds {_MAX_PATH_LEN} chars")
    if any(c.isspace() for c in path):
        raise BadResourceError("path must not contain whitespace")
    for segment in path.split("/")[1:]:
        if not segment:
            raise BadResourceError("path must not have empty segments")
        if segment in (".", ".."):
            raise BadResourceError("path segments must not be '.' or '..'")
    return path


def _check_methods(methods: object) -> Tuple[str, ...]:
    if isinstance(methods, (str, bytes)):
        raise TypeError("methods must be an iterable of method names, not a string")
    try:
        items = tuple(methods)  # type: ignore[arg-type]
    except TypeError:
        raise TypeError("methods must be an iterable of method names")
    if not items:
        raise BadResourceError("methods must be non-empty")
    for m in items:
        if isinstance(m, bool) or not isinstance(m, str):
            raise TypeError(f"method must be str, got {type(m).__name__}")
        if m not in _METHODS:
            raise BadResourceError(f"unknown CoAP method: {m!r}")
    return tuple(sorted(set(items)))


def _check_msg_type(msg_type: object) -> str:
    if isinstance(msg_type, bool) or not isinstance(msg_type, str):
        raise TypeError(f"msg_type must be str, got {type(msg_type).__name__}")
    if msg_type not in _MSG_TYPES:
        raise BadResponseError(f"unknown message type: {msg_type!r}")
    return msg_type


def _check_response_code(code: object) -> str:
    if isinstance(code, bool) or not isinstance(code, str):
        raise TypeError(f"code must be str, got {type(code).__name__}")
    if code not in _RESPONSES:
        raise BadResponseError(f"unknown response code: {code!r}")
    return code


def _check_observer_id(observer_id: object) -> str:
    if isinstance(observer_id, bool) or not isinstance(observer_id, str):
        raise TypeError(f"observer_id must be str, got {type(observer_id).__name__}")
    if not observer_id:
        raise ValueError("observer_id must be non-empty")
    if len(observer_id) > _MAX_OBSERVER_ID_LEN:
        raise ValueError(f"observer_id exceeds {_MAX_OBSERVER_ID_LEN} chars")
    return observer_id


def _check_content_format(content_format: object) -> str:
    if isinstance(content_format, bool) or not isinstance(content_format, str):
        raise TypeError(
            f"content_format must be str, got {type(content_format).__name__}"
        )
    return content_format


def _check_observe_allowed(observe_allowed: object) -> bool:
    if not isinstance(observe_allowed, bool):
        raise TypeError(
            f"observe_allowed must be bool, got {type(observe_allowed).__name__}"
        )
    return observe_allowed


def _check_block_no(block_no: object) -> int:
    if isinstance(block_no, bool) or not isinstance(block_no, int):
        raise TypeError(f"block_no must be int, got {type(block_no).__name__}")
    if not (0 <= block_no <= _MAX_BLOCK_NO):
        raise BadBlockError(f"block_no outside 0..{_MAX_BLOCK_NO}")
    return block_no


def _check_block_size(block_size: object) -> int:
    if isinstance(block_size, bool) or not isinstance(block_size, int):
        raise TypeError(f"block_size must be int, got {type(block_size).__name__}")
    if block_size not in _BLOCK_SIZES:
        raise BadBlockError(f"block_size must be one of {sorted(_BLOCK_SIZES)}")
    return block_size


def _check_more(more: object) -> bool:
    if not isinstance(more, bool):
        raise TypeError(f"more must be bool, got {type(more).__name__}")
    return more


def _canonicalize(value: Any) -> str:
    """Canonical string form for digesting. Fail-closed on ambiguity.

    Same JCS caveat as the rest of the batch line: ints are exact,
    integral floats beyond 2**53 are refused, bools encode distinctly
    from ints, dict keys must be str and are sorted.
    """
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise ValueError("NaN/inf are not canonicalizable")
        if value.is_integer() and abs(value) > 2**53:
            raise ValueError("integral float beyond 2**53 loses precision")
        return repr(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=True)
    if isinstance(value, bytes):
        return "bytes:" + value.hex()
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_canonicalize(v) for v in value) + "]"
    if isinstance(value, dict):
        for k in value.keys():
            if not isinstance(k, str):
                raise TypeError("dict keys must be str")
        items = sorted(value.items(), key=lambda kv: kv[0])
        return (
            "{"
            + ",".join(
                json.dumps(k, ensure_ascii=True) + ":" + _canonicalize(v)
                for k, v in items
            )
            + "}"
        )
    raise TypeError(f"unsupported value type: {type(value).__name__}")


def _check_payload(payload: Any) -> Any:
    """Validate that a payload is canonicalizable and within the guardrail."""
    body = _canonicalize(payload)  # raises fail-closed on junk
    if len(body.encode("utf-8")) > _MAX_PAYLOAD_BYTES:
        raise ValueError(f"payload exceeds {_MAX_PAYLOAD_BYTES} bytes")
    return payload


def _pin(*parts: str) -> str:
    body = "\x00".join(parts)
    return "sha256:" + hashlib.sha256(
        _DIGEST_DOMAIN + body.encode("utf-8")
    ).hexdigest()


def _digest_resource(
    path: str, methods: Tuple[str, ...], content_format: str, observe_allowed: bool, seq: int
) -> str:
    return _pin(
        "resource",
        json.dumps(path, ensure_ascii=True),
        json.dumps(list(methods), ensure_ascii=True),
        json.dumps(content_format, ensure_ascii=True),
        "observe" if observe_allowed else "no-observe",
        str(seq),
    )


def _digest_observation(
    path: str, observer_id: str, observe_seq: int, seq: int
) -> str:
    return _pin(
        "observation",
        json.dumps(path, ensure_ascii=True),
        json.dumps(observer_id, ensure_ascii=True),
        str(observe_seq),
        str(seq),
    )


def _digest_notification(
    path: str,
    observer_id: str,
    observe_seq: int,
    msg_id: int,
    msg_type: str,
    code: str,
    payload: Any,
    seq: int,
) -> str:
    return _pin(
        "notification",
        json.dumps(path, ensure_ascii=True),
        json.dumps(observer_id, ensure_ascii=True),
        str(observe_seq),
        str(msg_id),
        msg_type,
        code,
        _canonicalize(payload),
        str(seq),
    )


def _digest_block(
    path: str,
    block_no: int,
    more: bool,
    block_size: int,
    payload: Any,
    seq: int,
) -> str:
    return _pin(
        "block",
        json.dumps(path, ensure_ascii=True),
        str(block_no),
        "more" if more else "last",
        str(block_size),
        _canonicalize(payload),
        str(seq),
    )


@dataclass(frozen=True)
class ResourceRecord:
    """A registered CoAP resource path."""

    path: str
    methods: Tuple[str, ...]
    content_format: str
    observe_allowed: bool
    seq: int
    digest: str
    version: str = COAP_SERVER_VERSION
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        if not isinstance(self.digest, str) or not self.digest.startswith("sha256:"):
            raise TypeError("digest must be a 'sha256:' pin")

    def as_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "methods": list(self.methods),
            "content_format": self.content_format,
            "observe_allowed": self.observe_allowed,
            "seq": self.seq,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class Observation:
    """One active RFC 7641 observation (path, observer) pair."""

    path: str
    observer_id: str
    observe_seq: int
    active: bool
    seq: int
    digest: str
    version: str = COAP_SERVER_VERSION
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        if not isinstance(self.digest, str) or not self.digest.startswith("sha256:"):
            raise TypeError("digest must be a 'sha256:' pin")
        if (
            isinstance(self.observe_seq, bool)
            or not isinstance(self.observe_seq, int)
            or not (0 <= self.observe_seq < _OBSERVE_SEQ_MOD)
        ):
            raise ValueError("observe_seq must be an int in [0, 2**24)")

    def as_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "observer_id": self.observer_id,
            "observe_seq": self.observe_seq,
            "active": self.active,
            "seq": self.seq,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class ObserveCancelRecord:
    """Terminal record for a cancelled observation."""

    path: str
    observer_id: str
    seq: int
    digest: str
    version: str = COAP_SERVER_VERSION
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        if not isinstance(self.digest, str) or not self.digest.startswith("sha256:"):
            raise TypeError("digest must be a 'sha256:' pin")


@dataclass(frozen=True)
class Notification:
    """One observe notification booked for a single observer."""

    path: str
    observer_id: str
    observe_seq: int
    msg_id: int
    msg_type: str
    code: str
    payload: Any
    seq: int
    digest: str
    version: str = COAP_SERVER_VERSION
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        if not isinstance(self.digest, str) or not self.digest.startswith("sha256:"):
            raise TypeError("digest must be a 'sha256:' pin")

    def as_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "observer_id": self.observer_id,
            "observe_seq": self.observe_seq,
            "msg_id": self.msg_id,
            "msg_type": self.msg_type,
            "code": self.code,
            "payload": self.payload,
            "seq": self.seq,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class NotificationReport:
    """Fan-out summary for one ``notify()`` call (data, not delivery proof)."""

    path: str
    observer_ids: Tuple[str, ...]
    notifications: Tuple[Notification, ...]
    seq: int
    digest: str
    version: str = COAP_SERVER_VERSION
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        if not isinstance(self.digest, str) or not self.digest.startswith("sha256:"):
            raise TypeError("digest must be a 'sha256:' pin")


@dataclass(frozen=True)
class BlockRecord:
    """One booked RFC 7959 block arrival. ``state`` is data."""

    path: str
    block_no: int
    more: bool
    block_size: int
    payload: Any
    state: str
    blocks_received: int
    seq: int
    digest: str
    version: str = COAP_SERVER_VERSION
    schema: str = SCHEMA_PIN

    def __post_init__(self) -> None:
        if not isinstance(self.digest, str) or not self.digest.startswith("sha256:"):
            raise TypeError("digest must be a 'sha256:' pin")
        if self.state not in ("in-progress", "complete"):
            raise ValueError(f"unknown block state: {self.state!r}")

    def as_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "block_no": self.block_no,
            "more": self.more,
            "block_size": self.block_size,
            "payload": self.payload,
            "state": self.state,
            "blocks_received": self.blocks_received,
            "seq": self.seq,
            "digest": self.digest,
            "version": self.version,
            "schema": self.schema,
        }


class CoAPServer:
    """Deterministic CoAP resource/observe/block-wise ledger.

    All state mutations take a caller-supplied ``seq`` (monotonic
    logical time); no wall-clock is read anywhere. Failed mutations
    consume their seq (fail-closed ledger position).
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        # path -> {"record": ResourceRecord, "observers": {observer_id: {"seq": int, "active": bool}}}
        self._resources: Dict[str, Dict[str, Any]] = {}
        # (path) -> {"next": int, "size": int} for the in-flight block transfer
        self._blocks: Dict[str, Dict[str, int]] = {}
        self._msg_id = 0

    # -- resources ------------------------------------------------------

    def resource(
        self,
        path: object,
        seq: object,
        methods: object = ("GET",),
        content_format: object = "",
        observe_allowed: object = False,
    ) -> ResourceRecord:
        """Register a resource path. Duplicate paths raise fail-closed."""
        p = _check_path(path)
        s = _check_seq(seq)
        m = _check_methods(methods)
        cf = _check_content_format(content_format)
        oa = _check_observe_allowed(observe_allowed)
        with self._lock:
            if p in self._resources:
                raise DuplicateResourceError(f"already registered: {p!r}")
            if len(self._resources) >= _MAX_RESOURCES:
                raise CoAPServerError(
                    f"resource limit {_MAX_RESOURCES} reached"
                )
            record = ResourceRecord(
                path=p,
                methods=m,
                content_format=cf,
                observe_allowed=oa,
                seq=s,
                digest=_digest_resource(p, m, cf, oa, s),
            )
            self._resources[p] = {"record": record, "observers": {}}
            return record

    def resource_record(self, path: object) -> ResourceRecord:
        """Return the record for a registered path."""
        p = _check_path(path)
        with self._lock:
            entry = self._resources.get(p)
            if entry is None:
                raise UnknownResourceError(f"unknown resource: {p!r}")
            return entry["record"]

    def resources(self) -> Tuple[str, ...]:
        """Sorted registered paths."""
        with self._lock:
            return tuple(sorted(self._resources))

    # -- observe (RFC 7641) ----------------------------------------------

    def observe(
        self, path: object, observer_id: object, seq: object
    ) -> Observation:
        """Book an observe registration. Initial ``observe_seq`` is 0."""
        p = _check_path(path)
        oid = _check_observer_id(observer_id)
        s = _check_seq(seq)
        with self._lock:
            entry = self._resources.get(p)
            if entry is None:
                raise UnknownResourceError(f"unknown resource: {p!r}")
            if not entry["record"].observe_allowed:
                raise ObserveNotAllowedError(
                    f"resource does not allow observe: {p!r}"
                )
            observers = entry["observers"]
            state = observers.get(oid)
            if state is not None and state["active"]:
                raise DuplicateObservationError(
                    f"already observing: {p!r} by {oid!r}"
                )
            if len([o for e in self._resources.values() for o in e["observers"].values() if o["active"]]) >= _MAX_OBSERVATIONS:
                raise CoAPServerError(
                    f"observation limit {_MAX_OBSERVATIONS} reached"
                )
            observers[oid] = {"seq": 0, "active": True}
            return Observation(
                path=p,
                observer_id=oid,
                observe_seq=0,
                active=True,
                seq=s,
                digest=_digest_observation(p, oid, 0, s),
            )

    def cancel_observe(
        self, path: object, observer_id: object, seq: object
    ) -> ObserveCancelRecord:
        """Book an observe deregistration. Terminal for the (path, observer)."""
        p = _check_path(path)
        oid = _check_observer_id(observer_id)
        s = _check_seq(seq)
        with self._lock:
            entry = self._resources.get(p)
            if entry is None:
                raise UnknownResourceError(f"unknown resource: {p!r}")
            state = entry["observers"].get(oid)
            if state is None or not state["active"]:
                raise UnknownObservationError(
                    f"no active observation: {p!r} by {oid!r}"
                )
            state["active"] = False
            return ObserveCancelRecord(
                path=p,
                observer_id=oid,
                seq=s,
                digest=_pin(
                    "observe-cancelled",
                    json.dumps(p, ensure_ascii=True),
                    json.dumps(oid, ensure_ascii=True),
                    str(s),
                ),
            )

    def observation(
        self, path: object, observer_id: object
    ) -> Observation:
        """Return the current observation record (pure view)."""
        p = _check_path(path)
        oid = _check_observer_id(observer_id)
        with self._lock:
            entry = self._resources.get(p)
            if entry is None:
                raise UnknownResourceError(f"unknown resource: {p!r}")
            state = entry["observers"].get(oid)
            if state is None:
                raise UnknownObservationError(
                    f"no observation: {p!r} by {oid!r}"
                )
            return Observation(
                path=p,
                observer_id=oid,
                observe_seq=state["seq"],
                active=state["active"],
                seq=state.get("last_seq", 0),
                digest=_digest_observation(p, oid, state["seq"], state.get("last_seq", 0)),
            )

    def observations(self, path: object = None) -> Tuple[Observation, ...]:
        """Active observations, optionally filtered to one path."""
        with self._lock:
            if path is not None:
                p = _check_path(path)
                entries = (
                    [(p, self._resources[p])]
                    if p in self._resources
                    else []
                )
            else:
                entries = sorted(self._resources.items())
            out: List[Observation] = []
            for rp, entry in entries:
                for oid in sorted(entry["observers"]):
                    st = entry["observers"][oid]
                    if st["active"]:
                        out.append(
                            Observation(
                                path=rp,
                                observer_id=oid,
                                observe_seq=st["seq"],
                                active=True,
                                seq=st.get("last_seq", 0),
                                digest=_digest_observation(
                                    rp, oid, st["seq"], st.get("last_seq", 0)
                                ),
                            )
                        )
            return tuple(out)

    def notify(
        self,
        path: object,
        seq: object,
        payload: Any = None,
        msg_type: object = MSG_NON,
        code: object = RESP_205_CONTENT,
    ) -> NotificationReport:
        """Emit a notification to every active observer of ``path``.

        Each observer's 24-bit ``observe_seq`` advances by one modulo
        2**24. Observers are sorted for determinism. Returns a frozen
        fan-out report; notifications are data, not delivery proof.
        """
        p = _check_path(path)
        s = _check_seq(seq)
        mt = _check_msg_type(msg_type)
        c = _check_response_code(code)
        _check_payload(payload)
        with self._lock:
            entry = self._resources.get(p)
            if entry is None:
                raise UnknownResourceError(f"unknown resource: {p!r}")
            active = sorted(
                oid
                for oid, st in entry["observers"].items()
                if st["active"]
            )
            notifications: List[Notification] = []
            for oid in active:
                st = entry["observers"][oid]
                st["seq"] = (st["seq"] + 1) % _OBSERVE_SEQ_MOD
                st["last_seq"] = s
                msg_id = self._msg_id
                self._msg_id = (self._msg_id + 1) % _MSG_ID_MOD
                notifications.append(
                    Notification(
                        path=p,
                        observer_id=oid,
                        observe_seq=st["seq"],
                        msg_id=msg_id,
                        msg_type=mt,
                        code=c,
                        payload=payload,
                        seq=s,
                        digest=_digest_notification(
                            p, oid, st["seq"], msg_id, mt, c, payload, s
                        ),
                    )
                )
            pin = _pin(
                "notification-report",
                json.dumps(p, ensure_ascii=True),
                ",".join(active),
                str(s),
            )
            return NotificationReport(
                path=p,
                observer_ids=tuple(active),
                notifications=tuple(notifications),
                seq=s,
                digest=pin,
            )

    # -- block-wise transfer (RFC 7959) ------------------------------------

    def block(
        self,
        path: object,
        seq: object,
        block_no: object = 0,
        more: object = False,
        block_size: object = 1024,
        payload: Any = None,
    ) -> BlockRecord:
        """Book one block arrival and enforce NUM continuity.

        A transfer is in-flight while a ``more=True`` block is open for
        the path: the next booked block must have NUM exactly one above
        the last. Booking ``more=False`` completes the transfer (any
        size) and clears the in-flight state. A ``more=True`` block
        when none is in flight must start at NUM 0.
        """
        p = _check_path(path)
        s = _check_seq(seq)
        n = _check_block_no(block_no)
        m = _check_more(more)
        sz = _check_block_size(block_size)
        _check_payload(payload)
        with self._lock:
            if p not in self._resources:
                raise UnknownResourceError(f"unknown resource: {p!r}")
            inflight = self._blocks.get(p)
            if inflight is None:
                if m:
                    if n != 0:
                        raise BadBlockError(
                            f"new block-wise transfer must start at NUM 0, got {n}"
                        )
                    self._blocks[p] = {"next": 1, "count": 1, "size": sz}
                    state = "in-progress"
                    count = 1
                else:
                    # Single-block transfer: complete immediately.
                    state = "complete"
                    count = 1
            else:
                if inflight["size"] != sz:
                    raise BadBlockError(
                        f"block_size changed mid-transfer: {inflight['size']} -> {sz}"
                    )
                if n != inflight["next"]:
                    raise BadBlockError(
                        f"expected block NUM {inflight['next']}, got {n}"
                    )
                inflight["next"] += 1
                inflight["count"] += 1
                count = inflight["count"]
                if m:
                    state = "in-progress"
                else:
                    state = "complete"
                    del self._blocks[p]
            return BlockRecord(
                path=p,
                block_no=n,
                more=m,
                block_size=sz,
                payload=payload,
                state=state,
                blocks_received=count,
                seq=s,
                digest=_digest_block(p, n, m, sz, payload, s),
            )

    def block_state(self, path: object) -> Optional[Dict[str, Any]]:
        """In-flight block transfer state for a path (pure view)."""
        p = _check_path(path)
        with self._lock:
            if p not in self._resources:
                raise UnknownResourceError(f"unknown resource: {p!r}")
            st = self._blocks.get(p)
            if st is None:
                return None
            return {"path": p, "next_block_no": st["next"], "block_size": st["size"], "blocks_received": st["count"]}

    # -- views --------------------------------------------------------------

    def stats(self) -> Dict[str, Any]:
        """Server-wide counters."""
        with self._lock:
            n_obs = sum(
                1
                for e in self._resources.values()
                for st in e["observers"].values()
                if st["active"]
            )
            return {
                "resources": len(self._resources),
                "active_observations": n_obs,
                "in_flight_block_transfers": len(self._blocks),
                "msg_id": self._msg_id,
            }


def coap_server_audit_event(kind: object, seq: object, **detail: Any) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for a CoAP server event.

    ``detail`` carries pins/ids/counts only -- never raw payloads or
    paths with PII (paths are ids here, but payload bytes are banned).
    """
    if isinstance(kind, bool) or not isinstance(kind, str):
        raise TypeError(f"kind must be str, got {type(kind).__name__}")
    if kind not in _AUDIT_KINDS:
        raise ValueError(f"unknown audit kind: {kind!r}")
    s = _check_seq(seq)
    for key in detail:
        if not isinstance(key, str):
            raise TypeError("audit detail keys must be str")
    return {
        "format": AUDIT_FORMAT,
        "kind": kind,
        "seq": s,
        "module": COAP_SERVER_VERSION,
        "schema": SCHEMA_PIN,
        "detail": dict(detail),
    }


def main() -> None:
    srv = CoAPServer()
    r = srv.resource("/s/temp", 0, methods=("GET", "PUT"), observe_allowed=True)
    assert r.path == "/s/temp" and r.methods == ("GET", "PUT")
    o = srv.observe("/s/temp", "obs-1", 1)
    assert o.observe_seq == 0 and o.active
    rep = srv.notify("/s/temp", 2, payload={"t": 21.5})
    assert rep.observer_ids == ("obs-1",)
    assert rep.notifications[0].observe_seq == 1
    assert rep.notifications[0].msg_id == 0
    b = srv.block("/s/temp", 3, block_no=0, more=True, block_size=64, payload="part0")
    assert b.state == "in-progress"
    b2 = srv.block("/s/temp", 4, block_no=1, more=False, block_size=64, payload="part1")
    assert b2.state == "complete" and b2.blocks_received == 2
    c = srv.cancel_observe("/s/temp", "obs-1", 5)
    assert c.observer_id == "obs-1"
    # Re-observe after cancel is allowed (state was terminal).
    o2 = srv.observe("/s/temp", "obs-1", 6)
    assert o2.observe_seq == 0 and o2.active
    # Double observe while active is refused.
    try:
        srv.observe("/s/temp", "obs-1", 7)
    except DuplicateObservationError:
        pass
    else:
        raise AssertionError("double observe must fail")
    rep2 = srv.notify("/s/temp", 8)
    assert rep2.observer_ids == ("obs-1",)
    assert rep2.notifications[0].observe_seq == 1
    print("coap-server OK: resource, observe, notify, block-wise, cancel")


if __name__ == "__main__":
    main()
