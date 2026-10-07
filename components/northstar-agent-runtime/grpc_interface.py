"""gRPC interface: simulated service/method registry with unary and streaming RPCs.

A single-host bookkeeping shape for gRPC stubs (proto-style
``service.Method`` dispatch). ``GRPCInterface.register`` declares one
service method with its streaming cardinality; ``call`` performs a unary
request/response round trip through the host-supplied handler; ``stream``
drives the three streaming shapes (server-streaming, client-streaming,
bidirectional).

Streaming conventions (deterministic, host-executed, no network):

- ``unary`` -- ``handler(request) -> response``; only ``call`` may use it.
- ``server-streaming`` -- ``handler(request) -> iterable of responses``.
- ``client-streaming`` -- ``handler(iterable of requests) -> response``.
- ``bidirectional`` -- ``handler(iterable of requests) -> iterable of responses``.

Load-bearing rules:

- A service method is named by ``(service, method)``; registering the same
  pair twice raises ``DuplicateMethodError`` fail-closed -- two stubs
  bound to one method is a configuration bug, never a merge.
- ``call`` refuses streaming methods with ``StreamingCallError``; a unary
  method driven through ``stream`` raises the same way. Cardinality is
  part of the contract, not a runtime negotiation.
- Request and response payloads are pinned by ``sha256:`` digests of
  canonical JSON; payloads that cannot be canonicalized (NaN/inf, non-str
  dict keys, arbitrary objects) are rejected fail-closed rather than
  pinned ambiguously. Integral floats above 2**53 lose precision through
  ``json.dumps`` and can pin to the same digest as a different integer --
  the same JCS caveat documented in ``secure_aggregation``.
- Deadlines are caller-recorded budgets only (``deadline_ms`` is pinned
  into the result record); the module has no timers and never sleeps, so
  it cannot *enforce* a deadline -- it can only report what was declared.
  Error codes follow the gRPC status shape (``INVALID_ARGUMENT``,
  ``UNIMPLEMENTED``, ``NOT_FOUND``, ``FAILED_PRECONDITION``) as plain
  strings; this is a ledger, not a wire implementation.

House style: frozen dataclasses, no wall-clock (caller-supplied int
seqs), fail-closed validation, stdlib-only, deterministic, version and
schema pins, ``main()`` self-check.

Honest scope: this is a *host-reported* RPC ledger. It records that a
handler was invoked for a ``(service, method)`` pair with a given request
digest and what response digest it produced; it cannot prove anything
traversed a network, that the handler ran in another process, or that
HTTP/2 framing or TLS was involved. A call record means "this pinned
handler produced this pinned response for this pinned request", never
"the remote peer behaved correctly".

Version pin: grpc-interface.v1
Schema pin: northstar.grpc-interface.v1
"""

from __future__ import annotations

import hashlib
import json
import math
import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Optional, Tuple

GRPC_INTERFACE_VERSION = "grpc-interface.v1"
SCHEMA_PIN = "northstar.grpc-interface.v1"

_MAX_NAME_LEN = 256
_MAX_MESSAGES = 4096

# gRPC status codes as plain strings (ledger, not wire).
CODE_OK = "OK"
CODE_INVALID_ARGUMENT = "INVALID_ARGUMENT"
CODE_NOT_FOUND = "NOT_FOUND"
CODE_UNIMPLEMENTED = "UNIMPLEMENTED"
CODE_FAILED_PRECONDITION = "FAILED_PRECONDITION"
CODE_ALREADY_EXISTS = "ALREADY_EXISTS"


class MethodType:
    """Cardinality constants for registered service methods."""

    UNARY = "unary"
    SERVER_STREAMING = "server-streaming"
    CLIENT_STREAMING = "client-streaming"
    BIDIRECTIONAL = "bidirectional"

    ALL = (UNARY, SERVER_STREAMING, CLIENT_STREAMING, BIDIRECTIONAL)

    STREAMING = (SERVER_STREAMING, CLIENT_STREAMING, BIDIRECTIONAL)


# Module-level aliases matching the CODE_* style.
UNARY = MethodType.UNARY
SERVER_STREAMING = MethodType.SERVER_STREAMING
CLIENT_STREAMING = MethodType.CLIENT_STREAMING
BIDIRECTIONAL = MethodType.BIDIRECTIONAL


_AUDIT_KINDS = (
    "registered",
    "called",
    "streamed",
    "rejected",
)


class GRPCInterfaceError(Exception):
    """Base class for gRPC interface errors."""


class DuplicateMethodError(GRPCInterfaceError):
    """Raised when the same (service, method) is registered twice."""


class UnknownMethodError(GRPCInterfaceError):
    """Raised when calling or streaming an unregistered (service, method)."""


class StreamingCallError(GRPCInterfaceError):
    """Raised when the wrong entry point is used for a method's cardinality.

    ``call`` only drives ``unary`` methods; ``stream`` only drives the
    three streaming shapes. Cardinality is pinned at registration.
    """


class PayloadError(GRPCInterfaceError):
    """Raised when a request/response payload cannot be canonicalized."""


def _require_name(value: Any, what: str) -> str:
    if isinstance(value, bool) or not isinstance(value, str):
        raise TypeError(f"{what} must be a str, got {type(value).__name__}")
    if not value:
        raise ValueError(f"{what} must be non-empty")
    if len(value) > _MAX_NAME_LEN:
        raise ValueError(f"{what} must be at most {_MAX_NAME_LEN} chars")
    if "/" in value or value.strip() != value:
        raise ValueError(f"{what} must not contain '/' or surrounding whitespace")
    return value


def _require_method_type(method_type: Any) -> str:
    if isinstance(method_type, bool) or not isinstance(method_type, str):
        raise TypeError(
            f"method_type must be a str, got {type(method_type).__name__}"
        )
    if method_type not in MethodType.ALL:
        raise ValueError(f"method_type must be one of {sorted(MethodType.ALL)}")
    return method_type


def _require_seq(seq: Any) -> int:
    if isinstance(seq, bool) or not isinstance(seq, int):
        raise TypeError(f"seq must be an int, got {type(seq).__name__}")
    if seq < 0:
        raise ValueError("seq must be non-negative")
    return seq


def _require_handler(handler: Any) -> Callable[..., Any]:
    if not callable(handler):
        raise TypeError(
            f"handler must be callable, got {type(handler).__name__}"
        )
    return handler


def _require_deadline(deadline_ms: Any) -> Optional[int]:
    if deadline_ms is None:
        return None
    if isinstance(deadline_ms, bool) or not isinstance(deadline_ms, int):
        raise TypeError(
            f"deadline_ms must be an int or None, got {type(deadline_ms).__name__}"
        )
    if deadline_ms <= 0:
        raise ValueError("deadline_ms must be positive when given")
    return deadline_ms


def _require_metadata(metadata: Any) -> Tuple[Tuple[str, str], ...]:
    if metadata is None:
        return ()
    if not isinstance(metadata, dict):
        raise TypeError(
            f"metadata must be a dict or None, got {type(metadata).__name__}"
        )
    items = []
    for k, v in metadata.items():
        if isinstance(k, bool) or not isinstance(k, str) or not k:
            raise TypeError("metadata keys must be non-empty str")
        if isinstance(v, bool) or not isinstance(v, str):
            raise TypeError("metadata values must be str")
        items.append((k, v))
    return tuple(sorted(items))


def _canonical(value: Any) -> bytes:
    """Canonical JSON bytes for digesting; rejects non-canonicalizable input."""
    if value is None or isinstance(value, bool):
        pass
    elif isinstance(value, int):
        pass
    elif isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise PayloadError("payload must not contain NaN or infinity")
    elif isinstance(value, str):
        pass
    elif isinstance(value, (list, tuple)):
        for item in value:
            _canonical(item)
    elif isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                raise PayloadError("dict keys must be str for canonicalization")
            _canonical(v)
    else:
        raise PayloadError(
            f"value of type {type(value).__name__} is not JSON-canonicalizable"
        )
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _iter_messages(messages: Any, what: str) -> Tuple[Any, ...]:
    if not isinstance(messages, (list, tuple)):
        raise TypeError(f"{what} must be a list or tuple")
    if not messages:
        raise ValueError(f"{what} must be non-empty")
    if len(messages) > _MAX_MESSAGES:
        raise ValueError(f"{what} must have at most {_MAX_MESSAGES} messages")
    for m in messages:
        _canonical(m)  # validates each message now, fail-fast
    return tuple(messages)


@dataclass(frozen=True)
class ServiceDescriptor:
    """Pinned registration of one service method."""

    service: str
    method: str
    method_type: str
    handler_name: str
    descriptor_digest: str
    version: str = GRPC_INTERFACE_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> dict:
        return {
            "service": self.service,
            "method": self.method,
            "method_type": self.method_type,
            "handler_name": self.handler_name,
            "descriptor_digest": self.descriptor_digest,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class CallResult:
    """Pinned outcome of one unary ``call``."""

    service: str
    method: str
    code: str
    request_digest: str
    response_digest: str
    metadata: Tuple[Tuple[str, str], ...] = ()
    deadline_ms: Optional[int] = None
    seq: int = 0
    version: str = GRPC_INTERFACE_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> dict:
        return {
            "service": self.service,
            "method": self.method,
            "code": self.code,
            "request_digest": self.request_digest,
            "response_digest": self.response_digest,
            "metadata": [list(pair) for pair in self.metadata],
            "deadline_ms": self.deadline_ms,
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }


@dataclass(frozen=True)
class StreamResult:
    """Pinned outcome of one ``stream`` drive."""

    service: str
    method: str
    method_type: str
    code: str
    request_digest: str
    response_count: int
    response_digest: str
    metadata: Tuple[Tuple[str, str], ...] = ()
    deadline_ms: Optional[int] = None
    seq: int = 0
    version: str = GRPC_INTERFACE_VERSION
    schema: str = SCHEMA_PIN

    def as_dict(self) -> dict:
        return {
            "service": self.service,
            "method": self.method,
            "method_type": self.method_type,
            "code": self.code,
            "request_digest": self.request_digest,
            "response_count": self.response_count,
            "response_digest": self.response_digest,
            "metadata": [list(pair) for pair in self.metadata],
            "deadline_ms": self.deadline_ms,
            "seq": self.seq,
            "version": self.version,
            "schema": self.schema,
        }


class GRPCInterface:
    """Simulated gRPC service/method registry and RPC ledger."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._handlers: dict[Tuple[str, str], Callable[..., Any]] = {}
        self._descriptors: dict[Tuple[str, str], ServiceDescriptor] = {}
        self._calls = 0
        self._streams = 0

    def register(
        self,
        service: str,
        method: str,
        method_type: str,
        handler: Callable[..., Any],
        seq: int,
        *,
        handler_name: str = "",
    ) -> ServiceDescriptor:
        """Register one ``service.method`` with its streaming cardinality.

        Returns the frozen descriptor. The same pair twice raises
        ``DuplicateMethodError``; an unknown ``method_type`` raises
        ``ValueError``.
        """
        service = _require_name(service, "service")
        method = _require_name(method, "method")
        method_type = _require_method_type(method_type)
        _require_handler(handler)
        _require_seq(seq)
        if handler_name and (
            isinstance(handler_name, bool) or not isinstance(handler_name, str)
        ):
            raise TypeError("handler_name must be a str when given")
        name = handler_name or getattr(handler, "__name__", "handler")
        key = (service, method)
        with self._lock:
            if key in self._handlers:
                raise DuplicateMethodError(
                    f"{service}.{method} is already registered"
                )
            descriptor = ServiceDescriptor(
                service=service,
                method=method,
                method_type=method_type,
                handler_name=name,
                descriptor_digest=_digest(
                    {
                        "service": service,
                        "method": method,
                        "method_type": method_type,
                        "handler_name": name,
                    }
                ),
            )
            self._handlers[key] = handler
            self._descriptors[key] = descriptor
            return descriptor

    def _lookup(
        self, service: str, method: str
    ) -> Tuple[ServiceDescriptor, Callable[..., Any]]:
        service = _require_name(service, "service")
        method = _require_name(method, "method")
        key = (service, method)
        with self._lock:
            descriptor = self._descriptors.get(key)
            handler = self._handlers.get(key)
        if descriptor is None or handler is None:
            raise UnknownMethodError(f"{service}.{method} is not registered")
        return descriptor, handler

    def call(
        self,
        service: str,
        method: str,
        request: Any,
        seq: int,
        *,
        metadata: Optional[dict] = None,
        deadline_ms: Optional[int] = None,
    ) -> Tuple[Any, CallResult]:
        """Drive a unary RPC: ``handler(request) -> response``.

        Only ``unary`` methods are accepted; anything else raises
        ``StreamingCallError``. Returns ``(response, result)``; the frozen
        result pins the request/response digests for the audit trail.
        """
        descriptor, handler = self._lookup(service, method)
        _require_seq(seq)
        metadata = _require_metadata(metadata)
        deadline_ms = _require_deadline(deadline_ms)
        if descriptor.method_type != MethodType.UNARY:
            raise StreamingCallError(
                f"{service}.{method} is {descriptor.method_type}; "
                "use stream() instead of call()"
            )
        request_digest = _digest(request)  # fail-closed on bad payloads
        response = handler(request)
        result = CallResult(
            service=descriptor.service,
            method=descriptor.method,
            code=CODE_OK,
            request_digest=request_digest,
            response_digest=_digest(response),
            metadata=metadata,
            deadline_ms=deadline_ms,
            seq=seq,
        )
        with self._lock:
            self._calls += 1
        return response, result

    def stream(
        self,
        service: str,
        method: str,
        requests: Any,
        seq: int,
        *,
        metadata: Optional[dict] = None,
        deadline_ms: Optional[int] = None,
    ) -> Tuple[Tuple[Any, ...], StreamResult]:
        """Drive a streaming RPC per the method's registered cardinality.

        ``requests`` is a list/tuple of request messages (for
        ``server-streaming`` pass a single-element sequence). Returns
        ``(responses, result)``; the frozen result pins the aggregated
        request digest, the response count, and the aggregated response
        digest.
        """
        descriptor, handler = self._lookup(service, method)
        _require_seq(seq)
        metadata = _require_metadata(metadata)
        deadline_ms = _require_deadline(deadline_ms)
        method_type = descriptor.method_type
        if method_type == MethodType.UNARY:
            raise StreamingCallError(
                f"{service}.{method} is unary; use call() instead of stream()"
            )
        messages = _iter_messages(requests, "requests")
        if method_type == MethodType.SERVER_STREAMING:
            if len(messages) != 1:
                raise ValueError(
                    "server-streaming takes exactly one request message"
                )
            produced = handler(messages[0])
            responses = self._collect(produced, "handler output")
        elif method_type == MethodType.CLIENT_STREAMING:
            produced = handler(iter(messages))
            responses = (produced,)
        else:  # BIDIRECTIONAL
            produced = handler(iter(messages))
            responses = self._collect(produced, "handler output")
        result = StreamResult(
            service=descriptor.service,
            method=descriptor.method,
            method_type=method_type,
            code=CODE_OK,
            request_digest=_digest(list(messages)),
            response_count=len(responses),
            response_digest=_digest(list(responses)),
            metadata=metadata,
            deadline_ms=deadline_ms,
            seq=seq,
        )
        with self._lock:
            self._streams += 1
        return responses, result

    @staticmethod
    def _collect(produced: Any, what: str) -> Tuple[Any, ...]:
        if isinstance(produced, (str, bytes)) or not isinstance(
            produced, Iterable
        ):
            raise TypeError(
                f"{what} must be an iterable of response messages"
            )
        responses = tuple(produced)
        if not responses:
            raise ValueError(f"{what} must yield at least one response")
        if len(responses) > _MAX_MESSAGES:
            raise ValueError(
                f"{what} must yield at most {_MAX_MESSAGES} responses"
            )
        for r in responses:
            _canonical(r)  # fail-closed on bad payloads
        return responses

    def descriptor(self, service: str, method: str) -> ServiceDescriptor:
        """Return the frozen descriptor for a registered method."""
        descriptor, _ = self._lookup(service, method)
        return descriptor

    def services(self) -> Tuple[str, ...]:
        """Sorted names of all registered services."""
        with self._lock:
            return tuple(sorted({s for s, _ in self._descriptors}))

    def methods(self, service: str) -> Tuple[str, ...]:
        """Sorted method names registered under ``service``."""
        service = _require_name(service, "service")
        with self._lock:
            return tuple(
                sorted(m for s, m in self._descriptors if s == service)
            )

    def call_count(self) -> int:
        with self._lock:
            return self._calls

    def stream_count(self) -> int:
        with self._lock:
            return self._streams


def grpc_interface_audit_event(
    kind: str,
    seq: int,
    service: Optional[str] = None,
    method: Optional[str] = None,
    code: str = CODE_OK,
) -> dict:
    """Build an ``audit.ndjson/1``-shaped record for a gRPC step.

    ``kind`` is one of ``registered`` / ``called`` / ``streamed`` /
    ``rejected``. Only service/method names and the status code are
    emitted -- payloads never leave as raw values, only as digests pinned
    in the frozen result records.
    """
    if kind not in _AUDIT_KINDS:
        raise ValueError(f"kind must be one of {sorted(_AUDIT_KINDS)}")
    _require_seq(seq)
    record: dict[str, Any] = {
        "event": f"grpc-interface-{kind}",
        "audit_seq": seq,
        "code": code,
        "schema": SCHEMA_PIN,
    }
    if service is not None:
        record["service"] = _require_name(service, "service")
    if method is not None:
        record["method"] = _require_name(method, "method")
    return record


def main() -> None:
    iface = GRPCInterface()

    iface.register(
        "greeter", "SayHello", MethodType.UNARY, lambda req: {"hello": req["name"]}, seq=0
    )
    iface.register(
        "greeter",
        "StreamHellos",
        MethodType.SERVER_STREAMING,
        lambda req: ({"hello": req["name"], "n": i} for i in range(3)),
        seq=1,
    )
    iface.register(
        "collector",
        "Collect",
        MethodType.CLIENT_STREAMING,
        lambda reqs: {"count": sum(1 for _ in reqs)},
        seq=2,
    )
    iface.register(
        "chat",
        "Chat",
        MethodType.BIDIRECTIONAL,
        lambda reqs: ({"echo": r["msg"]} for r in reqs),
        seq=3,
    )

    resp, res = iface.call("greeter", "SayHello", {"name": "ada"}, seq=4)
    assert resp == {"hello": "ada"} and res.code == CODE_OK
    assert iface.call_count() == 1

    responses, sres = iface.stream(
        "greeter", "StreamHellos", [{"name": "ada"}], seq=5
    )
    assert len(responses) == 3 and sres.response_count == 3

    responses, sres = iface.stream(
        "collector", "Collect", [{"x": 1}, {"x": 2}], seq=6
    )
    assert responses == ({"count": 2},)

    responses, sres = iface.stream(
        "chat", "Chat", [{"msg": "a"}, {"msg": "b"}], seq=7
    )
    assert responses == ({"echo": "a"}, {"echo": "b"})

    try:
        iface.call("greeter", "StreamHellos", {"name": "ada"}, seq=8)
    except StreamingCallError:
        pass
    else:
        raise AssertionError("streaming via call() should raise")

    try:
        iface.stream("greeter", "SayHello", [{"name": "ada"}], seq=8)
    except StreamingCallError:
        pass
    else:
        raise AssertionError("unary via stream() should raise")

    try:
        iface.call("greeter", "Nope", {"name": "ada"}, seq=8)
    except UnknownMethodError:
        pass
    else:
        raise AssertionError("unknown method should raise")

    try:
        iface.register(
            "greeter", "SayHello", MethodType.UNARY, lambda r: r, seq=9
        )
    except DuplicateMethodError:
        pass
    else:
        raise AssertionError("duplicate registration should raise")

    try:
        iface.call("greeter", "SayHello", {"n": float("nan")}, seq=10)
    except PayloadError:
        pass
    else:
        raise AssertionError("NaN payload should raise")

    assert iface.services() == ("chat", "collector", "greeter")
    assert iface.methods("greeter") == ("SayHello", "StreamHellos")
    ev = grpc_interface_audit_event(
        "called", seq=11, service="greeter", method="SayHello"
    )
    assert ev["event"] == "grpc-interface-called"

    print("grpc-interface OK: register, call, stream, cardinality, refusals")


if __name__ == "__main__":
    main()
