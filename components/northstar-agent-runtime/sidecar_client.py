"""Client for the Northstar Codex sidecar's Unix socket.

Division of labour: this runtime does the reasoning and the policy, the sidecar
does the execution and the sandboxing. The runtime never spawns a model CLI and
never holds model credentials - it hands a prompt to
``components/northstar-codex-sidecar`` over a private Unix socket and reads one
bounded JSON response back.

The wire contract is mirrored here deliberately rather than imported: the sidecar
component is zero-dependency and standalone, so a hard ``import sidecar`` would
couple the two in the wrong direction. The limits below are the sidecar's own,
restated so that an out-of-contract request is refused locally with the sidecar's
verdict instead of a confusing transport error.

One request per connection, exactly as ``sidecar_socket.serve`` expects: connect,
send one JSON line, read one JSON line, close. No TCP listener exists and none is
ever attempted here.
"""
from __future__ import annotations

import json
import errno
import os
import select
import socket
import time
from dataclasses import dataclass, field
from typing import Any, Iterable

from contract_bridge import WIRE_FIELDS, BridgeError, build_request, cross_check

SIDECAR_MAX_PROMPT_CHARS = 100_000
SIDECAR_MIN_TIMEOUT_MS = 1_000
SIDECAR_MAX_TIMEOUT_MS = 300_000
SIDECAR_MAX_REQUEST_ID_CHARS = 128
#: Mirrors ``sidecar.FALLBACK_STATUSES``: conditions a host may recover from.
FALLBACK_STATUSES: frozenset[str] = frozenset({"transport_unavailable", "timeout"})
#: Statuses the sidecar itself may return; anything else is a protocol breach.
SIDECAR_STATUSES: frozenset[str] = frozenset(
    {"ok", "rejected", "timeout", "internal_error", "codex_error", "protocol_error"}
)
#: Local-only statuses produced by this client before a response was understood.
LOCAL_STATUSES: frozenset[str] = frozenset({"transport_unavailable", "protocol_error", "rejected"})
SOCKET_FILENAME = "sidecar.sock"
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
#: One escaped BMP char is 6 bytes and one astral char is 12; 12 per char covers
#: the worst case for a prompt the validator accepts, with framing headroom.
MAX_REQUEST_BYTES = 12 * SIDECAR_MAX_PROMPT_CHARS + 65_536
#: Sourced from the contract bridge so there is exactly one definition of the
#: boundary shared by the runtime, ``northstar-run-contract``, and the sidecar.
REQUEST_FIELDS: frozenset[str] = WIRE_FIELDS
CONNECT_ATTEMPTS = 3
CONNECT_RETRY_DELAY = 0.1


@dataclass(frozen=True)
class SidecarValidation:
    ok: bool
    errors: tuple[str, ...] = ()


def validate_request(request: Any) -> SidecarValidation:
    """Same verdict ``sidecar.classify_request`` gives, computed locally."""
    if not isinstance(request, dict):
        return SidecarValidation(False, ("request must be an object",))
    unknown = sorted(set(request) - set(REQUEST_FIELDS))
    if unknown:
        return SidecarValidation(False, (f"unknown request fields: {', '.join(unknown)}",))
    errors: list[str] = []
    request_id = request.get("request_id")
    prompt = request.get("prompt")
    timeout_ms = request.get("timeout_ms")
    if not isinstance(request_id, str) or not request_id.strip():
        errors.append("request_id must be a non-empty string")
    elif len(request_id) > SIDECAR_MAX_REQUEST_ID_CHARS:
        errors.append("request_id is too long")
    if not isinstance(prompt, str) or not prompt.strip():
        errors.append("prompt must be a non-empty string")
    elif len(prompt) > SIDECAR_MAX_PROMPT_CHARS:
        errors.append("prompt exceeds maximum size")
    if not isinstance(timeout_ms, int) or isinstance(timeout_ms, bool):
        errors.append("timeout_ms must be an integer")
    elif not SIDECAR_MIN_TIMEOUT_MS <= timeout_ms <= SIDECAR_MAX_TIMEOUT_MS:
        errors.append("timeout_ms is outside the permitted range")
    return SidecarValidation(not errors, tuple(errors))


def validate_socket_path(value: str, *, require_canonical_name: bool = True) -> SidecarValidation:
    """The socket must be a real filesystem path named ``sidecar.sock``.

    The directory is intentionally not pinned here: the sidecar pins it (see
    ``service.validate_socket_path``) and hosts legitimately relocate the runtime
    directory in development. A caller that wants the full contract should import
    the sidecar's validator.
    """
    if not isinstance(value, str) or not value.strip():
        return SidecarValidation(False, ("sidecar socket path must be a non-empty string",))
    path = socket_path_text(value)
    if not path.startswith("/"):
        return SidecarValidation(False, ("sidecar socket path must be absolute",))
    if require_canonical_name and os.path.basename(path.rstrip("/")) != SOCKET_FILENAME:
        return SidecarValidation(False, (f"sidecar socket filename must be {SOCKET_FILENAME}",))
    return SidecarValidation(True)


def socket_path_text(value: str | os.PathLike[str]) -> str:
    return os.fspath(value) if not isinstance(value, str) else value


def fallback_allowed(status: str) -> bool:
    return status in FALLBACK_STATUSES


@dataclass(frozen=True)
class SidecarResult:
    """Structured outcome of one sidecar round trip. Failures are data, not raises."""

    request_id: str = ""
    status: str = "internal_error"
    text: str = ""
    error: str = ""
    errors: tuple[str, ...] = ()
    latency_ms: int = 0
    bytes_read: int = 0
    truncated: bool = False
    raw: dict[str, Any] = field(default_factory=dict)
    #: ``unchecked`` (no host binding configured) | ``contract-verified`` (the run
    #: was re-derived through the contract and agreed) | ``unavailable``.
    wire_mode: str = "unchecked"

    @property
    def ok(self) -> bool:
        return self.status == "ok"

    @property
    def may_fall_back(self) -> bool:
        return fallback_allowed(self.status)

    def as_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "request_id": self.request_id,
            "status": self.status,
            "latency_ms": self.latency_ms,
            "fallback_allowed": self.may_fall_back,
        }
        if self.ok:
            payload["text"] = self.text
            payload["chars"] = len(self.text)
        if self.error:
            payload["error"] = self.error
        if self.errors:
            payload["errors"] = list(self.errors)
        if self.truncated:
            payload["truncated"] = True
        if self.wire_mode != "unchecked":
            payload["wire_mode"] = self.wire_mode
        return payload

    @property
    def report(self) -> str:
        if self.ok:
            return self.text
        parts = [f"sidecar status={self.status}"]
        if self.errors:
            parts.append("; ".join(self.errors))
        if self.error:
            parts.append(self.error)
        return " | ".join(parts)


class SidecarClient:
    """One-connection-per-request Unix socket client for the sidecar."""

    def __init__(
        self,
        socket_path: str | os.PathLike[str],
        *,
        timeout_ms: int = 30_000,
        connect_timeout_s: float = 5.0,
        read_grace_s: float = 10.0,
        request_id_prefix: str = "nsar",
        max_response_bytes: int = MAX_RESPONSE_BYTES,
        require_canonical_name: bool = True,
        transport: Any | None = None,
        run_id: str | None = None,
        run_document: dict[str, Any] | None = None,
    ) -> None:
        self.socket_path = socket_path_text(socket_path)
        checked = validate_socket_path(self.socket_path, require_canonical_name=require_canonical_name)
        if not checked.ok:
            raise ValueError("refusing to build a sidecar client: " + "; ".join(checked.errors))
        if not SIDECAR_MIN_TIMEOUT_MS <= int(timeout_ms) <= SIDECAR_MAX_TIMEOUT_MS:
            raise ValueError(
                f"timeout_ms must be between {SIDECAR_MIN_TIMEOUT_MS} and {SIDECAR_MAX_TIMEOUT_MS}"
            )
        self.timeout_ms = int(timeout_ms)
        self.connect_timeout_s = float(connect_timeout_s)
        self.read_grace_s = float(read_grace_s)
        self.request_id_prefix = request_id_prefix
        #: Correlation id for every request from this client (see contract_bridge).
        self.run_id = run_id
        #: Optional Run Request document, used only when a host binding is present.
        self.run_document = run_document
        self.max_response_bytes = int(max_response_bytes)
        #: Test seam: an object with connect()/send()/recvall()/close() semantics.
        self._transport = transport

    # -- public API --------------------------------------------------------
    def new_request_id(self) -> str:
        """The run's id when the operator set one, else a generated legacy-form id."""
        from contract_bridge import derive_request_id

        return derive_request_id(self.run_id, prefix=self.request_id_prefix)

    def execute(self, prompt: str, *, timeout_ms: int | None = None, request_id: str | None = None) -> SidecarResult:
        """Run one prompt. Never raises for an expected condition."""
        try:
            rid = request_id or self.new_request_id()
        except BridgeError as error:
            return SidecarResult(request_id="", status="rejected", errors=(str(error),))
        effective_timeout = self.timeout_ms if timeout_ms is None else int(timeout_ms)
        try:
            request: dict[str, Any] = build_request(prompt, run_id=rid, timeout_ms=effective_timeout)
        except BridgeError as error:
            return SidecarResult(request_id=rid, status="rejected", errors=(str(error),))
        checked = validate_request(request)
        if not checked.ok:
            return SidecarResult(request_id=rid, status="rejected", errors=checked.errors)
        # Contract cross-check: with a host binding in the environment the request
        # must be re-derivable from the verified run, or the call does not happen.
        report = cross_check(request, run=self.run_document)
        if not report.ok:
            return SidecarResult(
                request_id=rid,
                status="rejected",
                errors=tuple(f"run contract: {e}" for e in report.errors),
                wire_mode=report.mode,
            )
        started = time.monotonic()
        try:
            line, bytes_read, truncated = self._round_trip(request)
        except SidecarSocketMissingError as error:
            return self._failure(rid, "transport_unavailable", f"sidecar socket is not present: {error}", started)
        except (TimeoutError, socket.timeout) as error:
            return self._failure(rid, "transport_unavailable", f"sidecar did not answer within the read deadline: {error}", started)
        except OSError as error:
            return self._failure(rid, "transport_unavailable", f"sidecar transport failed: {error}", started)
        except SidecarProtocolError as error:
            return self._failure(rid, "protocol_error", str(error), started)
        latency_ms = int((time.monotonic() - started) * 1000)
        try:
            payload = json.loads(line)
        except (TypeError, json.JSONDecodeError) as error:
            return self._failure(rid, "protocol_error", f"sidecar returned a non-JSON response: {error}", started)
        try:
            result = self._normalise(payload, expected_request_id=rid)
        except SidecarProtocolError as error:
            # A peer that answers with the wrong shape is an expected condition: the
            # docstring above promises no raises, so honour it here too.
            return self._failure(rid, "protocol_error", str(error), started)
        return SidecarResult(
            request_id=result.request_id or rid,
            status=result.status,
            text=result.text,
            error=result.error,
            errors=result.errors,
            latency_ms=latency_ms,
            bytes_read=bytes_read,
            truncated=bool(truncated or result.truncated),
            raw=payload if isinstance(payload, dict) else {},
            wire_mode=report.mode,
        )

    def execute_tool(self, *, prompt: Any, timeout_ms: Any = None) -> Any:
        """Adapter used by the ``CodexReadOnly`` tool handler."""
        from tools import ToolResult

        if not isinstance(prompt, str):
            return ToolResult.error(f"prompt must be a string, got {type(prompt).__name__}")
        if timeout_ms is not None and (isinstance(timeout_ms, bool) or not isinstance(timeout_ms, int)):
            return ToolResult.error("timeout_ms must be an integer when provided")
        result = self.execute(prompt, timeout_ms=timeout_ms)
        content = {"status": result.status, "request_id": result.request_id}
        if result.ok:
            content["text"] = result.text
        else:
            content["report"] = result.report
        if result.error:
            content["error"] = result.error
        if result.errors:
            content["errors"] = list(result.errors)
        return ToolResult(
            content=content,
            is_error=not result.ok,
            truncated=result.truncated,
            data={
                "status": result.status,
                "latency_ms": result.latency_ms,
                "fallback_allowed": result.may_fall_back,
                "chars": len(result.text) if result.ok else 0,
            },
        )

    def probe(self) -> SidecarResult:
        """Health check the CLI can call without spending a run turn."""
        return self.execute("Reply with OK", timeout_ms=max(SIDECAR_MIN_TIMEOUT_MS, min(self.timeout_ms, 10_000)))

    # -- transport ---------------------------------------------------------
    def _round_trip(self, request: dict[str, Any]) -> tuple[str, int, bool]:
        payload = (json.dumps(request, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
        if len(payload) > MAX_REQUEST_BYTES:
            raise SidecarProtocolError("request is larger than the sidecar wire cap")
        if self._transport is not None:
            line, bytes_read, truncated = self._transport(payload)
            return line, bytes_read, truncated
        if not os.path.exists(self.socket_path):
            raise SidecarSocketMissingError(self.socket_path)
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            connection.setblocking(False)
            connect_deadline = time.monotonic() + self.connect_timeout_s
            last_connect_error: OSError | None = None
            for attempt in range(CONNECT_ATTEMPTS):
                try:
                    connection.connect(self.socket_path)
                    last_connect_error = None
                    break
                except BlockingIOError:
                    last_connect_error = None
                    break
                except (ConnectionRefusedError, FileNotFoundError) as error:
                    last_connect_error = error
                    if attempt + 1 < CONNECT_ATTEMPTS:
                        time.sleep(CONNECT_RETRY_DELAY)
                        continue
                    raise
            if last_connect_error is not None:
                raise last_connect_error
            while True:
                remaining = connect_deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("sidecar connect deadline exceeded")
                _, writable, exceptional = select.select([], [connection], [connection], remaining)
                if not writable and not exceptional:
                    raise TimeoutError("sidecar connect deadline exceeded")
                error = connection.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
                if error:
                    raise OSError(error, errno.errorcode.get(error, "sidecar connect failed"))
                break
            # Use an explicit select deadline rather than relying on platform-specific
            # blocking recv timeout semantics for connected Unix peers.
            connection.setblocking(False)
            deadline = time.monotonic() + self.timeout_ms / 1000.0 + self.read_grace_s
            view = memoryview(payload)
            while view:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("sidecar write deadline exceeded")
                _, writable, _ = select.select([], [connection], [], remaining)
                if not writable:
                    raise TimeoutError("sidecar write deadline exceeded")
                try:
                    view = view[connection.send(view):]
                except BlockingIOError:
                    continue
            try:
                connection.shutdown(socket.SHUT_WR)
            except OSError:  # pragma: no cover - peer already gone
                pass
            chunks: list[bytes] = []
            total = 0
            truncated = False
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("sidecar read deadline exceeded")
                readable, _, _ = select.select([connection], [], [], remaining)
                if not readable:
                    raise TimeoutError("sidecar read deadline exceeded")
                try:
                    chunk = connection.recv(65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    break
                newline = chunk.find(b"\n")
                if newline >= 0:
                    chunks.append(chunk[: newline + 1])
                    total += newline + 1
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > self.max_response_bytes:
                    truncated = True
                    break
            if not chunks:
                raise SidecarProtocolError("sidecar closed the connection without a response")
            raw = b"".join(chunks)[: self.max_response_bytes]
            return raw.decode("utf-8", "replace"), total, truncated
        finally:
            try:
                connection.close()
            except OSError:  # pragma: no cover - best effort
                pass

    @staticmethod
    def _normalise(payload: Any, *, expected_request_id: str) -> SidecarResult:
        if not isinstance(payload, dict):
            raise SidecarProtocolError("sidecar response is not a JSON object")
        status = payload.get("status")
        if not isinstance(status, str) or not status:
            raise SidecarProtocolError("sidecar response has no status field")
        text = payload.get("text", "")
        if not isinstance(text, str):
            raise SidecarProtocolError("sidecar text field is not a string")
        if status == "ok" and not text:
            raise SidecarProtocolError("sidecar reported ok without an agent message")
        errors = payload.get("errors")
        normalised_errors = tuple(str(item) for item in errors) if isinstance(errors, (list, tuple)) else ()
        request_id = payload.get("request_id")
        if isinstance(request_id, str) and request_id and request_id != expected_request_id:
            raise SidecarProtocolError(
                f"sidecar answered for request {request_id!r} while {expected_request_id!r} was pending"
            )
        return SidecarResult(
            request_id=request_id if isinstance(request_id, str) else expected_request_id,
            status=status,
            text=text if status == "ok" else "",
            error=payload.get("error") if isinstance(payload.get("error"), str) else "",
            errors=normalised_errors,
            raw=dict(payload),
        )

    def _failure(self, request_id: str, status: str, message: str, started: float) -> SidecarResult:
        return SidecarResult(
            request_id=request_id,
            status=status,
            error=message,
            latency_ms=int((time.monotonic() - started) * 1000),
        )


class SidecarSocketMissingError(FileNotFoundError):
    """The socket path was absent before attempting transport."""


class SidecarProtocolError(RuntimeError):
    """Response framing the runtime cannot trust."""


def known_statuses() -> Iterable[str]:
    return sorted(SIDECAR_STATUSES | LOCAL_STATUSES)


__all__ = [
    "FALLBACK_STATUSES",
    "MAX_REQUEST_BYTES",
    "SIDECAR_MAX_PROMPT_CHARS",
    "SIDECAR_MAX_TIMEOUT_MS",
    "SIDECAR_MIN_TIMEOUT_MS",
    "SIDECAR_STATUSES",
    "SOCKET_FILENAME",
    "SidecarClient",
    "SidecarProtocolError",
    "SidecarResult",
    "SidecarValidation",
    "fallback_allowed",
    "known_statuses",
    "validate_request",
    "validate_socket_path",
]
