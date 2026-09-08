"""Authenticated JSON-lines control/replay transport for durable runs.

This is a deliberately narrow Profile B building block, not a hosted
scheduler.  A worker can expose the existing :class:`DurableRunner` control
and :class:`EventStore` replay surfaces over one request per TCP connection.
Every frame is authenticated by a channel HMAC, and every request also carries
host-issued binding and authorization tokens.  The server binds to loopback by
default and refuses a non-loopback listener; deployment-grade mTLS, workspace
materialisation, step execution and fleet scheduling remain outside this
module.

The transport never accepts Python actions or arbitrary filesystem paths.  Its
operations are ``status``, ``history``, ``pause``, ``resume`` and ``cancel``.
Step execution continues to require a local ``StepPlan`` and therefore cannot
be smuggled through a serialized network payload.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import socket
import socketserver
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from authorization import verify_authorization
from binding import verify_binding
from control_receipt import (
    CONTROL_RECEIPT_SCHEMA_VERSION,
    ControlReceipt,
    digest_state,
)
from durable_contract import RunContract
from event_store import EventStore
from runner import DurableRunner

TRANSPORT_SCHEMA_VERSION = "northstar.durable-transport.v1"
MAX_FRAME_BYTES = 1_000_000
MAX_HISTORY_EVENTS = 10_000
MAX_TOKEN_CHARS = 16_384
MAX_ERROR_CHARS = 512
MAX_REQUEST_ID_CHARS = 128
MIN_CHANNEL_SECRET_BYTES = 32

OPERATIONS = frozenset({"status", "history", "pause", "resume", "cancel"})
RESPONSE_STATUSES = frozenset({"ok", "rejected", "business_error", "internal_error"})
READ_CAPABILITY = "durable:read"
CONTROL_CAPABILITY = "durable:control"
_ID_RE = re.compile(r"^[^\s/\\\x00]+$")
_MAC_RE = re.compile(r"^[0-9a-f]{64}$")
_REQUEST_FIELDS = frozenset(
    {
        "schema_version",
        "request_id",
        "operation",
        "workspace_id",
        "run_contract",
        "binding_token",
        "authorization_token",
        "payload",
        "mac",
    }
)
_RESPONSE_FIELDS = frozenset(
    {"schema_version", "request_id", "status", "data", "error", "mac"}
)


class DurableTransportError(RuntimeError):
    """Transport or response failure with a bounded status label."""

    def __init__(self, message: str, *, status: str = "transport_unavailable") -> None:
        super().__init__(message)
        self.status = status


class _Rejected(ValueError):
    """An authenticated request that is invalid or outside its grant."""


@dataclass(frozen=True)
class _AuthorizedRequest:
    request_id: str
    operation: str
    workspace_id: str
    run: RunContract
    actor_id: str
    policy_revision: str
    payload: dict[str, Any]


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _secret(value: bytes, field: str) -> bytes:
    if not isinstance(value, bytes) or not MIN_CHANNEL_SECRET_BYTES <= len(value) <= 128:
        raise ValueError(f"{field} must be {MIN_CHANNEL_SECRET_BYTES}..128 non-empty bytes")
    return value


def _id(value: Any, field: str, *, maximum: int = MAX_REQUEST_ID_CHARS) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or not _ID_RE.fullmatch(value):
        raise _Rejected(f"{field} is invalid")
    return value


def _mac(body: dict[str, Any], secret: bytes) -> str:
    return hmac.new(secret, _canonical(body), hashlib.sha256).hexdigest()


def _with_mac(body: dict[str, Any], secret: bytes) -> dict[str, Any]:
    result = dict(body)
    result["mac"] = _mac(result, secret)
    return result


def _error_text(error: object) -> str:
    text = str(error).strip() or "request failed"
    return text[:MAX_ERROR_CHARS]


def _validate_payload(operation: str, payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise _Rejected("payload must be an object")
    if operation == "pause":
        if set(payload) != {"reason"}:
            raise _Rejected("pause payload must contain only reason")
        reason = payload["reason"]
        if not isinstance(reason, str) or not reason.strip() or len(reason) > 512:
            raise _Rejected("pause reason is invalid")
        return {"reason": reason.strip()}
    if payload:
        raise _Rejected(f"{operation} payload must be empty")
    return {}


def _empty_state(run_id: str) -> dict[str, Any]:
    return {"run_id": run_id, "status": "planned", "sequence": 0, "steps": {}}


class DurableWorkerServer:
    """Loopback-only authenticated server for durable control and replay."""

    def __init__(
        self,
        event_path: str | Path,
        *,
        lease_path: str | Path,
        binding_secret: bytes,
        authorization_secret: bytes,
        channel_secret: bytes,
        policy_revision: str | None = None,
        host: str = "127.0.0.1",
        port: int = 0,
        lease_ttl_seconds: int = 60,
    ) -> None:
        if host not in {"127.0.0.1", "::1"}:
            raise ValueError("DurableWorkerServer only permits loopback listeners")
        if isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65_535:
            raise ValueError("port must be an integer between 0 and 65535")
        if not isinstance(lease_ttl_seconds, int) or isinstance(lease_ttl_seconds, bool) or lease_ttl_seconds <= 0:
            raise ValueError("lease_ttl_seconds must be a positive integer")
        if policy_revision is not None:
            _id(policy_revision, "policy_revision")
        self.event_path = Path(event_path).absolute()
        self.lease_path = Path(lease_path).absolute()
        self.binding_secret = _secret(binding_secret, "binding_secret")
        self.authorization_secret = _secret(authorization_secret, "authorization_secret")
        self.channel_secret = _secret(channel_secret, "channel_secret")
        self.policy_revision = policy_revision
        self.host = host
        self.port = port
        self.lease_ttl_seconds = lease_ttl_seconds
        self.store = EventStore(self.event_path)
        self._server: socketserver.ThreadingTCPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def address(self) -> tuple[str, int]:
        """The bound loopback address, available after :meth:`start`."""
        if self._server is None:
            raise RuntimeError("worker server has not been started")
        address = self._server.server_address
        return str(address[0]), int(address[1])

    def start(self) -> "DurableWorkerServer":
        """Bind a loopback listener and serve requests in a daemon thread."""
        if self._server is not None:
            raise RuntimeError("worker server is already started")
        owner = self

        class _Handler(socketserver.StreamRequestHandler):
            def handle(self) -> None:
                line = self.rfile.readline(MAX_FRAME_BYTES + 1)
                response = owner.handle_wire_line(line)
                self.wfile.write(response + b"\n")
                self.wfile.flush()

        if self.host == "::1":
            class _Server(socketserver.ThreadingTCPServer):
                address_family = socket.AF_INET6
                allow_reuse_address = False
                daemon_threads = True
        else:
            class _Server(socketserver.ThreadingTCPServer):
                allow_reuse_address = False
                daemon_threads = True

        try:
            self._server = _Server((self.host, self.port), _Handler)
        except OSError as error:
            raise DurableTransportError(f"worker listener could not start: {error}") from error
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="northstar-durable-worker-server",
            daemon=True,
        )
        self._thread.start()
        return self

    def stop(self) -> None:
        """Stop the listener; no event or lease files are modified by shutdown."""
        server = self._server
        if server is None:
            return
        server.shutdown()
        server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        self._server = None
        self._thread = None

    def __enter__(self) -> "DurableWorkerServer":
        return self.start()

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.stop()

    def handle_wire_line(self, line: bytes) -> bytes:
        """Decode one bounded JSON line and return one signed JSON response."""
        if not isinstance(line, bytes) or len(line) > MAX_FRAME_BYTES:
            return _canonical(self._response("", "rejected", {}, "frame exceeds maximum size"))
        try:
            text = line.decode("utf-8")
            value = json.loads(text)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            return _canonical(self._response("", "rejected", {}, f"invalid JSON frame: {_error_text(error)}"))
        return _canonical(self.handle_frame(value))

    def handle_frame(self, frame: Any, *, now: int | None = None) -> dict[str, Any]:
        """Handle one request without opening a socket; always returns a signed response."""
        request_id = frame.get("request_id", "") if isinstance(frame, dict) else ""
        if not isinstance(request_id, str) or len(request_id) > MAX_REQUEST_ID_CHARS:
            request_id = ""
        current = int(time.time()) if now is None else now
        if isinstance(current, bool) or not isinstance(current, int) or current <= 0:
            return self._response(request_id, "rejected", {}, "server time is invalid")
        try:
            request = self._authorize(frame, now=current)
            data = self._dispatch(request, now=current)
            return self._response(request.request_id, "ok", data, None)
        except _Rejected as error:
            return self._response(request_id, "rejected", {}, _error_text(error))
        except ValueError as error:
            return self._response(request_id, "business_error", {}, _error_text(error))
        except Exception:
            # Do not turn unexpected implementation details into a remote data
            # leak. The event store remains the authority for diagnosis.
            return self._response(request_id, "internal_error", {}, "worker transport internal error")

    def _response(
        self,
        request_id: str,
        status: str,
        data: dict[str, Any],
        error: str | None,
    ) -> dict[str, Any]:
        body = {
            "schema_version": TRANSPORT_SCHEMA_VERSION,
            "request_id": request_id,
            "status": status,
            "data": data,
            "error": error,
        }
        response = _with_mac(body, self.channel_secret)
        if len(_canonical(response)) + 1 <= MAX_FRAME_BYTES:
            return response
        fallback = {
            "schema_version": TRANSPORT_SCHEMA_VERSION,
            "request_id": request_id,
            "status": "business_error",
            "data": {},
            "error": "worker response exceeds maximum frame size",
        }
        return _with_mac(fallback, self.channel_secret)

    def _authorize(self, frame: Any, *, now: int) -> _AuthorizedRequest:
        if not isinstance(frame, dict):
            raise _Rejected("request frame must be an object")
        missing = sorted(_REQUEST_FIELDS - set(frame))
        unknown = sorted(set(frame) - _REQUEST_FIELDS)
        if missing or unknown:
            raise _Rejected(
                "request fields are not exact"
                + (f"; missing: {', '.join(missing)}" if missing else "")
                + (f"; unknown: {', '.join(unknown)}" if unknown else "")
            )
        supplied_mac = frame.get("mac")
        body = dict(frame)
        body.pop("mac", None)
        if not isinstance(supplied_mac, str) or not _MAC_RE.fullmatch(supplied_mac):
            raise _Rejected("request authentication failed")
        if not hmac.compare_digest(supplied_mac, _mac(body, self.channel_secret)):
            raise _Rejected("request authentication failed")
        if frame.get("schema_version") != TRANSPORT_SCHEMA_VERSION:
            raise _Rejected(f"schema_version must be {TRANSPORT_SCHEMA_VERSION}")
        request_id = _id(frame.get("request_id"), "request_id")
        operation = frame.get("operation")
        if operation not in OPERATIONS:
            raise _Rejected("operation is not permitted")
        workspace_id = _id(frame.get("workspace_id"), "workspace_id")
        try:
            run = RunContract.from_dict(frame.get("run_contract"))
        except ValueError as error:
            raise _Rejected(f"run_contract is invalid: {_error_text(error)}") from error
        if now >= run.deadline_at:
            raise _Rejected("run contract deadline has expired")
        binding_token = frame.get("binding_token")
        authorization_token = frame.get("authorization_token")
        if (
            not isinstance(binding_token, str)
            or not binding_token
            or len(binding_token) > MAX_TOKEN_CHARS
            or not isinstance(authorization_token, str)
            or not authorization_token
            or len(authorization_token) > MAX_TOKEN_CHARS
        ):
            raise _Rejected("binding or authorization token is invalid")
        binding = verify_binding(binding_token, self.binding_secret, now=now)
        if not binding.ok or binding.binding is None:
            raise _Rejected("binding verification failed")
        authorization = verify_authorization(
            authorization_token, self.authorization_secret, now=now
        )
        if not authorization.ok or authorization.authorization is None:
            raise _Rejected("authorization verification failed")
        binding_claims = binding.binding
        authorization_claims = authorization.authorization
        if binding_claims["run_id"] != run.run_id or authorization_claims["run_id"] != run.run_id:
            raise _Rejected("authorization run_id does not match the durable run")
        if binding_claims["actor_id"] != authorization_claims["actor_id"]:
            raise _Rejected("binding and authorization actor_id differ")
        if binding_claims["workspace_id"] != workspace_id or authorization_claims["workspace_id"] != workspace_id:
            raise _Rejected("workspace_id does not match the host claims")
        if self.policy_revision is not None and authorization_claims["policy_revision"] != self.policy_revision:
            raise _Rejected("authorization policy revision is not current")
        capabilities = set(authorization_claims["capabilities"])
        if not set(run.scope_snapshot).issubset(capabilities):
            raise _Rejected("durable run scope exceeds the authorization grant")
        required = READ_CAPABILITY if operation in {"status", "history"} else CONTROL_CAPABILITY
        if required not in capabilities:
            raise _Rejected(f"authorization lacks {required}")
        payload = _validate_payload(operation, frame.get("payload"))
        return _AuthorizedRequest(
            request_id=request_id,
            operation=operation,
            workspace_id=workspace_id,
            run=run,
            actor_id=authorization_claims["actor_id"],
            policy_revision=authorization_claims["policy_revision"],
            payload=payload,
        )

    def _dispatch(self, request: _AuthorizedRequest, *, now: int) -> dict[str, Any]:
        run_id = request.run.run_id
        if request.operation == "status":
            events = self.store.read_history(run_id)
            state = self.store.replay(run_id) if events else _empty_state(run_id)
            return {
                "run_id": run_id,
                "event_count": len(events),
                "last_event": events[-1].to_dict() if events else None,
                "state": state,
            }
        if request.operation == "history":
            events = self.store.read_history(run_id)
            if len(events) > MAX_HISTORY_EVENTS:
                raise ValueError("event history exceeds transport response limit")
            return {"run_id": run_id, "events": [event.to_dict() for event in events]}

        before_events = self.store.read_history(run_id)
        before_state = self.store.replay(run_id) if before_events else _empty_state(run_id)
        runner = DurableRunner(
            request.run,
            self.store,
            lease_path=self.lease_path,
            lease_ttl_seconds=self.lease_ttl_seconds,
        )
        if request.operation == "pause":
            state = runner.pause(
                owner_id=request.actor_id,
                now=now,
                reason=request.payload["reason"],
            )
        elif request.operation == "resume":
            state = runner.resume(owner_id=request.actor_id, now=now)
        else:
            state = runner.cancel(owner_id=request.actor_id, now=now)
        after_events = self.store.read_history(run_id)
        new_events = after_events[len(before_events) :]
        receipt = ControlReceipt(
            schema_version=CONTROL_RECEIPT_SCHEMA_VERSION,
            receipt_id=f"remote-{uuid.uuid4().hex}",
            command_id=request.request_id,
            run_id=run_id,
            actor_id=request.actor_id,
            operation=request.operation,
            requested_at=now,
            outcome="applied" if new_events else "noop",
            before_status=before_state["status"],
            after_status=state["status"],
            before_sequence=before_state["sequence"],
            after_sequence=state["sequence"],
            event_ids=tuple(event.event_id for event in new_events),
            event_sequences=tuple(event.sequence for event in new_events),
            state_digest=digest_state(state),
        )
        return {"run_id": run_id, "state": state, "receipt": receipt.to_dict()}


class DurableWorkerClient:
    """One-request-per-connection client for :class:`DurableWorkerServer`."""

    def __init__(
        self,
        host: str,
        port: int,
        *,
        workspace_id: str,
        run_contract: RunContract,
        binding_token: str,
        authorization_token: str,
        channel_secret: bytes,
        timeout_s: float = 10.0,
    ) -> None:
        if not isinstance(host, str) or not host or len(host) > 255 or any(
            char.isspace() or char == "\x00" for char in host
        ):
            raise ValueError("host is invalid")
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65_535:
            raise ValueError("port must be an integer between 1 and 65535")
        if not isinstance(run_contract, RunContract):
            raise ValueError("run_contract must be a RunContract")
        if not isinstance(binding_token, str) or not binding_token or len(binding_token) > MAX_TOKEN_CHARS:
            raise ValueError("binding_token is invalid")
        if not isinstance(authorization_token, str) or not authorization_token or len(authorization_token) > MAX_TOKEN_CHARS:
            raise ValueError("authorization_token is invalid")
        try:
            timeout = float(timeout_s)
        except (TypeError, ValueError) as error:
            raise ValueError("timeout_s must be a number") from error
        if timeout <= 0 or timeout > 300:
            raise ValueError("timeout_s must be greater than zero and at most 300")
        self.host = host
        self.port = port
        self.workspace_id = _id(workspace_id, "workspace_id")
        self.run_contract = run_contract
        self.binding_token = binding_token
        self.authorization_token = authorization_token
        self.channel_secret = _secret(channel_secret, "channel_secret")
        self.timeout_s = timeout

    def build_frame(
        self,
        operation: str,
        *,
        payload: dict[str, Any] | None = None,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        """Build an authenticated request for tests or a custom socket loop."""
        if operation not in OPERATIONS:
            raise ValueError("operation is not permitted")
        rid = request_id or f"req-{uuid.uuid4().hex}"
        _id(rid, "request_id")
        body = {
            "schema_version": TRANSPORT_SCHEMA_VERSION,
            "request_id": rid,
            "operation": operation,
            "workspace_id": self.workspace_id,
            "run_contract": self.run_contract.to_dict(),
            "binding_token": self.binding_token,
            "authorization_token": self.authorization_token,
            "payload": {} if payload is None else payload,
        }
        if not isinstance(body["payload"], dict):
            raise ValueError("payload must be an object")
        return _with_mac(body, self.channel_secret)

    def request(
        self,
        operation: str,
        *,
        payload: dict[str, Any] | None = None,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        """Send one request and verify the signed response envelope."""
        frame = self.build_frame(operation, payload=payload, request_id=request_id)
        line = _canonical(frame) + b"\n"
        if len(line) > MAX_FRAME_BYTES:
            raise DurableTransportError("durable worker request exceeds maximum frame size", status="protocol_error")
        try:
            with socket.create_connection((self.host, self.port), timeout=self.timeout_s) as connection:
                connection.settimeout(self.timeout_s)
                connection.sendall(line)
                reader = connection.makefile("rb")
                try:
                    response_line = reader.readline(MAX_FRAME_BYTES + 1)
                finally:
                    reader.close()
        except (OSError, TimeoutError) as error:
            raise DurableTransportError(
                f"durable worker transport unavailable: {error}",
                status="transport_unavailable",
            ) from error
        if not response_line or len(response_line) > MAX_FRAME_BYTES:
            raise DurableTransportError("durable worker returned no bounded response", status="protocol_error")
        try:
            response = json.loads(response_line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise DurableTransportError("durable worker returned invalid JSON", status="protocol_error") from error
        self._validate_response(response, expected_request_id=frame["request_id"])
        return response

    def request_ok(
        self,
        operation: str,
        *,
        payload: dict[str, Any] | None = None,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        """Send a request and raise for a signed rejected/business/internal response."""
        response = self.request(operation, payload=payload, request_id=request_id)
        if response["status"] != "ok":
            raise DurableTransportError(
                response.get("error") or "durable worker rejected the request",
                status=response["status"],
            )
        return response["data"]

    def _validate_response(self, response: Any, *, expected_request_id: str) -> None:
        if not isinstance(response, dict) or set(response) != _RESPONSE_FIELDS:
            raise DurableTransportError("durable worker response envelope is invalid", status="protocol_error")
        if response["schema_version"] != TRANSPORT_SCHEMA_VERSION:
            raise DurableTransportError("durable worker response schema is unsupported", status="protocol_error")
        if response["request_id"] != expected_request_id:
            raise DurableTransportError("durable worker response request_id does not match", status="protocol_error")
        if response["status"] not in RESPONSE_STATUSES:
            raise DurableTransportError("durable worker response status is invalid", status="protocol_error")
        if not isinstance(response["data"], dict):
            raise DurableTransportError("durable worker response data is invalid", status="protocol_error")
        if response["error"] is not None and not isinstance(response["error"], str):
            raise DurableTransportError("durable worker response error is invalid", status="protocol_error")
        supplied_mac = response["mac"]
        body = dict(response)
        body.pop("mac")
        if not isinstance(supplied_mac, str) or not _MAC_RE.fullmatch(supplied_mac):
            raise DurableTransportError("durable worker response authentication is invalid", status="protocol_error")
        if not hmac.compare_digest(supplied_mac, _mac(body, self.channel_secret)):
            raise DurableTransportError("durable worker response authentication failed", status="protocol_error")


__all__ = [
    "DurableTransportError",
    "DurableWorkerClient",
    "DurableWorkerServer",
    "MAX_FRAME_BYTES",
    "TRANSPORT_SCHEMA_VERSION",
]
