"""gRPC-Gateway: HTTP/JSON-to-gRPC transcoding bindings and stream sessions.

A ``GRPCGateway`` books gRPC-Gateway-style reverse-proxy decisions as a
deterministic single-host state machine:

- ``service(service_id, proto_digest, seq)`` pins a gRPC service by its
  proto descriptor digest (digest-only; descriptor bytes never enter a
  record).
- ``transcode(transcode_id, service_id, http_method, http_path,
  grpc_service, grpc_method, seq, streaming=None)`` pins one
  HTTP/JSON -> gRPC binding (a ``google.api.http``-shaped mapping):
  one HTTP method + path template dispatches to one ``grpc_service``
  / ``grpc_method`` pair. ``streaming`` is ``None`` (unary),
  ``"server"``, ``"client"`` or ``"bidi"``.
- ``stream(session_id, transcode_id, seq)`` opens a streamed HTTP
  session pinned to a transcode binding; ``close_stream(session_id,
  seq, status="completed")`` terminally closes it with a host-reported
  status. Statuses are *data*, never raised.
- Views: ``service_record()`` / ``service_ids()`` / ``transcode()``
  lookup / ``transcode_ids()`` / ``transcode_for_service()`` /
  ``session()`` / ``session_ids()`` / ``sessions_for()`` / ``stats()``
  / ``audit_log()``.

House style: frozen dataclasses, caller-supplied strictly increasing
int seqs (no wall-clock), RLock-guarded, fail-closed taxonomy,
stdlib-only plus the standard ``canonical_json`` try/except fallback,
``sha256:`` digest pins, ``audit.ndjson/1`` events, version pin
``grpc-gateway.v1``, schema pin ``northstar.grpc-gateway.v1``,
``main()`` self-check.

Honest scope: this module books *declared* transcoding bindings and
host-reported stream sessions; it cannot prove a proxy actually
transcoded a wire request, cannot verify that the descriptor behind a
proto digest matches the declared methods, and cannot observe
HTTP/JSON payloads (request/response bytes never cross the module
boundary or the audit boundary). A transcode record means "this host
declared this mapping", never "traffic flowed through it".
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Tuple

try:  # the single canonicalizer
    from canonical_json import jcs_canonical_json
except ImportError:  # pragma: no cover - fallback for standalone import
    import json

    def jcs_canonical_json(obj: Any) -> bytes:  # type: ignore[no-redef]
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


#: Version pin for this module's record shape.
GRPC_GATEWAY_VERSION = "grpc-gateway.v1"

#: Schema pin carried by records and audit events.
GRPC_GATEWAY_SCHEMA = "northstar.grpc-gateway.v1"

#: Schema pin carried by audit events.
AUDIT_SCHEMA = "audit.ndjson/1"

#: Pinned HTTP method vocabulary for transcoding bindings.
_HTTP_METHODS = ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS")

#: Pinned streaming shapes for a binding (None = unary).
_STREAMING_NONE = None
_STREAMING_SERVER = "server"
_STREAMING_CLIENT = "client"
_STREAMING_BIDI = "bidi"
_STREAMINGS = (_STREAMING_SERVER, _STREAMING_CLIENT, _STREAMING_BIDI)

#: Pinned stream-session statuses (host-reported, data only).
_STATUS_COMPLETED = "completed"
_STATUS_CANCELLED = "cancelled"
_STATUS_ERROR = "error"
_STATUSES = (_STATUS_COMPLETED, _STATUS_CANCELLED, _STATUS_ERROR)


# ---------------------------------------------------------------------------
# Errors (fail-closed taxonomy)
# ---------------------------------------------------------------------------


class GRPCGatewayError(ValueError):
    """Base for all gRPC-gateway structural problems and refused transitions."""


class BadServiceError(GRPCGatewayError):
    """Service definition is malformed (bad id, bad proto digest)."""


class DuplicateServiceError(GRPCGatewayError):
    """A service id is already pinned."""


class UnknownServiceError(GRPCGatewayError):
    """No service with that id."""


class BadTranscodeError(GRPCGatewayError):
    """Transcode binding is malformed (bad id, method, path, target)."""


class DuplicateTranscodeError(GRPCGatewayError):
    """A transcode id is already pinned."""


class UnknownTranscodeError(GRPCGatewayError):
    """No transcode binding with that id."""


class BadStreamError(GRPCGatewayError):
    """Stream session input is malformed (bad id, status)."""


class DuplicateStreamError(GRPCGatewayError):
    """A stream session id is already pinned."""


class UnknownStreamError(GRPCGatewayError):
    """No stream session with that id."""


class AlreadyClosedError(GRPCGatewayError):
    """The stream session is already closed."""


class SeqOrderError(GRPCGatewayError):
    """Caller seq did not strictly increase."""


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _check_seq(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise SeqOrderError(f"{name} must be a non-negative int")
    return value


def _check_nonempty_str(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise GRPCGatewayError(f"{name} must be a non-empty string")
    return value.strip()


def _check_service_id(value: Any) -> str:
    service_id = _check_nonempty_str(value, "service_id")
    if len(service_id) > 128:
        raise BadServiceError("service_id must be <= 128 chars")
    return service_id


def _check_proto_digest(value: Any) -> str:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        raise BadServiceError(
            "proto_digest must be a 'sha256:' + 64-hex digest pin"
        )
    hexpart = value[len("sha256:"):]
    if len(hexpart) != 64 or any(c not in "0123456789abcdef" for c in hexpart):
        raise BadServiceError(
            "proto_digest must be a 'sha256:' + 64-hex digest pin"
        )
    return value


def _check_transcode_id(value: Any) -> str:
    transcode_id = _check_nonempty_str(value, "transcode_id")
    if len(transcode_id) > 128:
        raise BadTranscodeError("transcode_id must be <= 128 chars")
    return transcode_id


def _check_http_method(value: Any) -> str:
    if value not in _HTTP_METHODS:
        raise BadTranscodeError(f"http_method must be one of {_HTTP_METHODS}")
    return value


def _check_http_path(value: Any) -> str:
    """Validate an HTTP path template like ``/v1/things/{thing_id}``."""
    if not isinstance(value, str) or not value.strip():
        raise BadTranscodeError("http_path must be a non-empty string")
    path = value.strip()
    if len(path) > 512:
        raise BadTranscodeError("http_path must be <= 512 chars")
    if not path.startswith("/"):
        raise BadTranscodeError("http_path must start with '/'")
    if any(c.isspace() for c in path):
        raise BadTranscodeError("http_path must not contain whitespace")
    if "://" in path:
        raise BadTranscodeError("http_path must not carry a URL scheme")
    for segment in path.split("/")[1:]:
        if not segment:
            raise BadTranscodeError(
                f"http_path has an empty segment: {path!r}"
            )
        if segment.startswith("{") != segment.endswith("}"):
            raise BadTranscodeError(
                f"http_path has an unbalanced template segment: {segment!r}"
            )
        if segment.startswith("{") and len(segment) < 3:
            raise BadTranscodeError(
                f"http_path has an empty template name: {segment!r}"
            )
    return path


def _check_grpc_service(value: Any) -> str:
    service = _check_nonempty_str(value, "grpc_service")
    if len(service) > 256:
        raise BadTranscodeError("grpc_service must be <= 256 chars")
    if any(c.isspace() for c in service):
        raise BadTranscodeError("grpc_service must not contain whitespace")
    return service


def _check_grpc_method(value: Any) -> str:
    method = _check_nonempty_str(value, "grpc_method")
    if len(method) > 128:
        raise BadTranscodeError("grpc_method must be <= 128 chars")
    if any(c.isspace() for c in method):
        raise BadTranscodeError("grpc_method must not contain whitespace")
    return method


def _check_streaming(value: Any) -> Optional[str]:
    if value is None:
        return None
    if value not in _STREAMINGS:
        raise BadTranscodeError(
            f"streaming must be None or one of {_STREAMINGS}"
        )
    return value


def _check_session_id(value: Any) -> str:
    session_id = _check_nonempty_str(value, "session_id")
    if len(session_id) > 128:
        raise BadStreamError("session_id must be <= 128 chars")
    return session_id


def _check_status(value: Any) -> str:
    if value not in _STATUSES:
        raise BadStreamError(f"status must be one of {_STATUSES}")
    return value


def _pin(*parts: Any) -> str:
    digest = hashlib.sha256(
        jcs_canonical_json([GRPC_GATEWAY_VERSION, *parts])
    ).hexdigest()
    return f"sha256:{digest}"


# ---------------------------------------------------------------------------
# Frozen records
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ServiceRecord:
    """One pinned gRPC service (frozen); descriptor pinned by digest only."""

    service_id: str
    proto_digest: str
    seq: int
    digest: str
    schema: str = GRPC_GATEWAY_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "service", self.service_id, self.proto_digest, self.seq
        )


@dataclass(frozen=True)
class TranscodeRecord:
    """One pinned HTTP/JSON -> gRPC binding (frozen)."""

    transcode_id: str
    service_id: str
    http_method: str
    http_path: str
    grpc_service: str
    grpc_method: str
    streaming: Optional[str]
    seq: int
    digest: str
    schema: str = GRPC_GATEWAY_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "transcode", self.transcode_id, self.service_id,
            self.http_method, self.http_path, self.grpc_service,
            self.grpc_method, self.streaming or "", self.seq,
        )


@dataclass(frozen=True)
class StreamSession:
    """One stream session pinned to a transcode binding (frozen).

    ``closed`` is replaced on close; the record's digest re-pins the
    current lifecycle state.
    """

    session_id: str
    transcode_id: str
    seq: int
    closed: bool
    digest: str
    schema: str = GRPC_GATEWAY_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "stream", self.session_id, self.transcode_id, self.seq,
            self.closed,
        )


@dataclass(frozen=True)
class StreamCloseRecord:
    """One terminal stream-session close (frozen). Status is data."""

    session_id: str
    status: str
    seq: int
    digest: str
    schema: str = GRPC_GATEWAY_SCHEMA

    def verify(self) -> bool:
        return self.digest == _pin(
            "close", self.session_id, self.status, self.seq
        )


# ---------------------------------------------------------------------------
# Audit events
# ---------------------------------------------------------------------------

KIND_SERVICE_REGISTERED = "grpc-gateway.service-registered"
KIND_TRANSCODE_BOUND = "grpc-gateway.transcode-bound"
KIND_STREAM_OPENED = "grpc-gateway.stream-opened"
KIND_STREAM_CLOSED = "grpc-gateway.stream-closed"
KIND_REJECTED = "grpc-gateway.rejected"
_AUDIT_KINDS = (
    KIND_SERVICE_REGISTERED, KIND_TRANSCODE_BOUND, KIND_STREAM_OPENED,
    KIND_STREAM_CLOSED, KIND_REJECTED,
)


def grpc_gateway_audit_event(
    kind: str, detail: Mapping[str, Any], seq: int
) -> Dict[str, Any]:
    """Shape an ``audit.ndjson/1`` record for the grpc-gateway module."""
    if kind not in _AUDIT_KINDS:
        raise GRPCGatewayError(f"unknown audit kind: {kind!r}")
    _check_seq(seq, "seq")
    if not isinstance(detail, Mapping):
        raise GRPCGatewayError("detail must be a mapping")
    # Request/response bytes never cross the audit boundary; ids and
    # digest pins only.
    banned = {
        "request", "response", "payload", "body", "proto_bytes",
        "descriptor",
    }
    if any(k in detail for k in banned):
        raise GRPCGatewayError("detail carries banned keys")
    return {
        "schema": AUDIT_SCHEMA,
        "kind": kind,
        "module": GRPC_GATEWAY_VERSION,
        "detail": dict(detail),
        "seq": seq,
    }


# ---------------------------------------------------------------------------
# The gateway ledger
# ---------------------------------------------------------------------------


class GRPCGateway:
    """Deterministic gRPC-Gateway transcoding ledger.

    All state mutations take a caller-supplied ``seq`` (monotonic
    logical time); no wall-clock is read anywhere. Failed mutations
    consume their seq (fail-closed ledger position).
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._last_seq = 0
        self._services: Dict[str, ServiceRecord] = {}
        self._transcodes: Dict[str, TranscodeRecord] = {}
        self._sessions: Dict[str, StreamSession] = {}
        self._closes: Dict[str, StreamCloseRecord] = {}
        self._audit: List[Dict[str, Any]] = []

    # -- internal helpers -------------------------------------------------

    def _consume_seq(self, seq: Any) -> int:
        seq = _check_seq(seq, "seq")
        if seq <= self._last_seq:
            raise SeqOrderError(
                f"seq must strictly increase (last={self._last_seq})"
            )
        self._last_seq = seq
        return seq

    def _emit(self, kind: str, seq: int, **detail: Any) -> None:
        self._audit.append(grpc_gateway_audit_event(kind, detail, seq))

    def _reject(self, seq: int, op: str, error: str) -> None:
        self._emit(KIND_REJECTED, seq, op=op, error=error)

    # -- services ----------------------------------------------------------

    def service(
        self, service_id: Any, proto_digest: Any, seq: Any
    ) -> ServiceRecord:
        """Pin a gRPC service by proto-descriptor digest.

        Duplicate ids are refused fail-closed.
        """
        with self._lock:
            seq = self._consume_seq(seq)
            try:
                service_id = _check_service_id(service_id)
                proto_digest = _check_proto_digest(proto_digest)
                if service_id in self._services:
                    raise DuplicateServiceError(
                        f"service already pinned: {service_id!r}"
                    )
            except GRPCGatewayError as exc:
                self._reject(seq, "service", type(exc).__name__)
                raise
            record = ServiceRecord(
                service_id=service_id,
                proto_digest=proto_digest,
                seq=seq,
                digest=_pin("service", service_id, proto_digest, seq),
            )
            self._services[service_id] = record
            self._emit(
                KIND_SERVICE_REGISTERED, seq, service_id=service_id,
                proto_digest=proto_digest,
            )
            return record

    # -- transcoding bindings -----------------------------------------------

    def transcode(
        self,
        transcode_id: Any,
        service_id: Any,
        http_method: Any,
        http_path: Any,
        grpc_service: Any,
        grpc_method: Any,
        seq: Any,
        streaming: Any = None,
    ) -> TranscodeRecord:
        """Pin an HTTP/JSON -> gRPC transcoding binding.

        Duplicate transcode ids and unknown services are refused
        fail-closed.
        """
        with self._lock:
            seq = self._consume_seq(seq)
            try:
                transcode_id = _check_transcode_id(transcode_id)
                service_id = _check_service_id(service_id)
                http_method = _check_http_method(http_method)
                http_path = _check_http_path(http_path)
                grpc_service = _check_grpc_service(grpc_service)
                grpc_method = _check_grpc_method(grpc_method)
                streaming = _check_streaming(streaming)
                if service_id not in self._services:
                    raise UnknownServiceError(
                        f"unknown service: {service_id!r}"
                    )
                if transcode_id in self._transcodes:
                    raise DuplicateTranscodeError(
                        f"transcode already pinned: {transcode_id!r}"
                    )
            except GRPCGatewayError as exc:
                self._reject(seq, "transcode", type(exc).__name__)
                raise
            record = TranscodeRecord(
                transcode_id=transcode_id,
                service_id=service_id,
                http_method=http_method,
                http_path=http_path,
                grpc_service=grpc_service,
                grpc_method=grpc_method,
                streaming=streaming,
                seq=seq,
                digest=_pin(
                    "transcode", transcode_id, service_id, http_method,
                    http_path, grpc_service, grpc_method,
                    streaming or "", seq,
                ),
            )
            self._transcodes[transcode_id] = record
            self._emit(
                KIND_TRANSCODE_BOUND, seq, transcode_id=transcode_id,
                service_id=service_id, http_method=http_method,
                grpc_service=grpc_service, grpc_method=grpc_method,
                streaming=streaming or "",
            )
            return record

    # -- stream sessions ----------------------------------------------------

    def stream(
        self, session_id: Any, transcode_id: Any, seq: Any
    ) -> StreamSession:
        """Open a streamed HTTP session pinned to a transcode binding.

        Duplicate session ids and unknown transcode bindings are refused
        fail-closed.
        """
        with self._lock:
            seq = self._consume_seq(seq)
            try:
                session_id = _check_session_id(session_id)
                transcode_id = _check_transcode_id(transcode_id)
                if transcode_id not in self._transcodes:
                    raise UnknownTranscodeError(
                        f"unknown transcode: {transcode_id!r}"
                    )
                if session_id in self._sessions:
                    raise DuplicateStreamError(
                        f"session already pinned: {session_id!r}"
                    )
            except GRPCGatewayError as exc:
                self._reject(seq, "stream", type(exc).__name__)
                raise
            record = StreamSession(
                session_id=session_id,
                transcode_id=transcode_id,
                seq=seq,
                closed=False,
                digest=_pin("stream", session_id, transcode_id, seq, False),
            )
            self._sessions[session_id] = record
            self._emit(
                KIND_STREAM_OPENED, seq, session_id=session_id,
                transcode_id=transcode_id,
            )
            return record

    def close_stream(
        self, session_id: Any, seq: Any, status: str = _STATUS_COMPLETED
    ) -> StreamCloseRecord:
        """Terminally close a stream session. Status is data, never raised."""
        with self._lock:
            seq = self._consume_seq(seq)
            try:
                session_id = _check_session_id(session_id)
                status = _check_status(status)
                session = self._sessions.get(session_id)
                if session is None:
                    raise UnknownStreamError(
                        f"unknown session: {session_id!r}"
                    )
                if session.closed:
                    raise AlreadyClosedError(
                        f"session already closed: {session_id!r}"
                    )
            except GRPCGatewayError as exc:
                self._reject(seq, "close_stream", type(exc).__name__)
                raise
            record = StreamCloseRecord(
                session_id=session_id,
                status=status,
                seq=seq,
                digest=_pin("close", session_id, status, seq),
            )
            self._closes[session_id] = record
            self._sessions[session_id] = StreamSession(
                session_id=session.session_id,
                transcode_id=session.transcode_id,
                seq=session.seq,
                closed=True,
                digest=_pin(
                    "stream", session.session_id, session.transcode_id,
                    session.seq, True,
                ),
            )
            self._emit(
                KIND_STREAM_CLOSED, seq, session_id=session_id,
                status=status,
            )
            return record

    # -- views --------------------------------------------------------------

    def service_record(self, service_id: Any) -> ServiceRecord:
        """Return a pinned service; unknown ids raise."""
        with self._lock:
            service_id = _check_nonempty_str(service_id, "service_id")
            record = self._services.get(service_id)
            if record is None:
                raise UnknownServiceError(f"unknown service: {service_id!r}")
            return record

    def service_ids(self) -> Tuple[str, ...]:
        """All pinned service ids, sorted."""
        with self._lock:
            return tuple(sorted(self._services))

    def transcode_record(self, transcode_id: Any) -> TranscodeRecord:
        """Return a pinned transcode binding; unknown ids raise."""
        with self._lock:
            transcode_id = _check_nonempty_str(transcode_id, "transcode_id")
            record = self._transcodes.get(transcode_id)
            if record is None:
                raise UnknownTranscodeError(
                    f"unknown transcode: {transcode_id!r}"
                )
            return record

    def transcode_ids(self) -> Tuple[str, ...]:
        """All pinned transcode ids, sorted."""
        with self._lock:
            return tuple(sorted(self._transcodes))

    def transcodes_for_service(self, service_id: Any) -> Tuple[str, ...]:
        """Transcode ids pinned to one service, sorted."""
        with self._lock:
            service_id = _check_nonempty_str(service_id, "service_id")
            return tuple(
                tid for tid in sorted(self._transcodes)
                if self._transcodes[tid].service_id == service_id
            )

    def session(self, session_id: Any) -> StreamSession:
        """Return a stream session; unknown ids raise."""
        with self._lock:
            session_id = _check_nonempty_str(session_id, "session_id")
            record = self._sessions.get(session_id)
            if record is None:
                raise UnknownStreamError(f"unknown session: {session_id!r}")
            return record

    def session_ids(self) -> Tuple[str, ...]:
        """All pinned session ids, sorted."""
        with self._lock:
            return tuple(sorted(self._sessions))

    def sessions_for(self, transcode_id: Any) -> Tuple[str, ...]:
        """Session ids pinned to one transcode binding, sorted."""
        with self._lock:
            transcode_id = _check_nonempty_str(transcode_id, "transcode_id")
            return tuple(
                sid for sid in sorted(self._sessions)
                if self._sessions[sid].transcode_id == transcode_id
            )

    def close_record(self, session_id: Any) -> StreamCloseRecord:
        """Return the terminal close record; unknown ids raise."""
        with self._lock:
            session_id = _check_nonempty_str(session_id, "session_id")
            record = self._closes.get(session_id)
            if record is None:
                raise UnknownStreamError(
                    f"no close record for session: {session_id!r}"
                )
            return record

    def stats(self) -> Dict[str, int]:
        """Pure read view: counts of services, bindings, sessions, closes."""
        with self._lock:
            sessions = list(self._sessions.values())
            return {
                "services": len(self._services),
                "transcodes": len(self._transcodes),
                "sessions": len(sessions),
                "open": sum(1 for s in sessions if not s.closed),
                "closed": len(self._closes),
            }

    def audit_log(self) -> Tuple[Dict[str, Any], ...]:
        """All audit events, in seq order."""
        with self._lock:
            return tuple(self._audit)


# ---------------------------------------------------------------------------
# Self-check
# ---------------------------------------------------------------------------


def main() -> None:
    """Exercise the happy path; exits non-zero on failure."""
    gateway = GRPCGateway()
    digest = "sha256:" + "ab" * 32
    svc = gateway.service("svc1", digest, 1)
    assert svc.verify()
    bind = gateway.transcode(
        "t1", "svc1", "POST", "/v1/things/{thing_id}",
        "example.ThingService", "CreateThing", 2, streaming="bidi",
    )
    assert bind.verify()
    session = gateway.stream("s1", "t1", 3)
    assert session.verify()
    assert not session.closed
    assert gateway.sessions_for("t1") == ("s1",)
    closed = gateway.close_stream("s1", 4, "completed")
    assert closed.verify()
    assert closed.status == "completed"
    assert gateway.session("s1").closed
    assert gateway.stats()["open"] == 0
    assert gateway.stats()["closed"] == 1
    print("grpc-gateway OK: service, transcode, stream, close, audit")


if __name__ == "__main__":
    main()
