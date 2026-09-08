"""Host-controlled local app-server for background Northstar runs.

This is an intentionally narrow T25 surface, not a scheduler or a remote
execution service. A host constructs :class:`RunManager` with a
``runtime_factory``; the wire protocol can submit only a bounded prompt and
observe/cancel that host-owned run. It cannot choose a provider, workspace,
Python callable, tool, or filesystem path.

The optional Unix-socket server adds a small versioned JSON-lines protocol:
``run.start``, ``run.status``, ``run.events``, ``run.wait`` and ``run.cancel``.
Every request and response is HMAC-authenticated, request ids are idempotent,
event pages are
bounded, and the socket is private to the local filesystem. Runtime cancellation
is cooperative: a provider or tool already in progress is allowed to finish and
the loop stops at its next governed boundary.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import socket
import socketserver
import threading
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping

from events import event_to_dict

APP_PROTOCOL = "northstar.agent-app.v1"
MAX_PROMPT_CHARS = 128_000
MAX_FRAME_BYTES = 1_048_576
MAX_EVENT_PAGE = 256
DEFAULT_EVENT_RETENTION = 512
DEFAULT_ACTIVE_RUNS = 8
DEFAULT_WAIT_MS = 10_000
MAX_WAIT_MS = 30_000
_RESERVED_CLIENT_FIELDS = frozenset({"protocol", "op", "request_id", "actor_id", "auth"})
_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


class AppServerError(RuntimeError):
    """A protocol, authorization, idempotency, or local app-server failure."""

    def __init__(self, code: str, message: str, *, details: Mapping[str, Any] | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.details = dict(details or {})

    def as_dict(self) -> dict[str, Any]:
        return {"code": self.code, "message": str(self), **self.details}


@dataclass
class _RunRecord:
    run_id: str
    request_id: str
    actor_id: str
    fingerprint: str
    prompt: str
    status: str = "queued"
    created_at: float = 0.0
    started_at: float | None = None
    finished_at: float | None = None
    cancel_requested: bool = False
    runtime: Any | None = None
    result: dict[str, Any] | None = None
    events: list[dict[str, Any]] = field(default_factory=list)
    first_sequence: int = 0
    next_sequence: int = 0
    thread: threading.Thread | None = None

    @property
    def terminal(self) -> bool:
        return self.status in {"success", "failed", "cancelled"}


class RunManager:
    """Bounded in-process background run manager.

    ``runtime_factory`` is a host seam, not a wire-controlled callback. It must
    return a configured runtime for each run. The manager owns no provider
    credentials and does not deserialize actions or execution plans from the
    client.
    """

    def __init__(
        self,
        runtime_factory: Callable[[], Any],
        *,
        max_active_runs: int = DEFAULT_ACTIVE_RUNS,
        max_event_retention: int = DEFAULT_EVENT_RETENTION,
        clock: Callable[[], float] | None = None,
    ) -> None:
        if not callable(runtime_factory):
            raise TypeError("runtime_factory must be callable")
        if isinstance(max_active_runs, bool) or not isinstance(max_active_runs, int) or max_active_runs < 1:
            raise ValueError("max_active_runs must be a positive integer")
        if isinstance(max_event_retention, bool) or not isinstance(max_event_retention, int) or max_event_retention < 1:
            raise ValueError("max_event_retention must be a positive integer")
        self.runtime_factory = runtime_factory
        self.max_active_runs = max_active_runs
        self.max_event_retention = max_event_retention
        self.clock = clock or time.time
        self._lock = threading.RLock()
        self._changed = threading.Condition(self._lock)
        self._records: OrderedDict[str, _RunRecord] = OrderedDict()
        self._request_index: OrderedDict[str, tuple[str, str]] = OrderedDict()

    # -- validation and projections --------------------------------------
    @staticmethod
    def _id(value: Any, *, field_name: str) -> str:
        if not isinstance(value, str) or not _ID_PATTERN.fullmatch(value):
            raise AppServerError(
                "invalid_request",
                f"{field_name} must match {_ID_PATTERN.pattern!r}",
            )
        return value

    @staticmethod
    def _prompt(prompt: Any) -> str:
        if not isinstance(prompt, str) or not prompt.strip():
            raise AppServerError("invalid_request", "prompt must be non-empty text")
        if len(prompt) > MAX_PROMPT_CHARS:
            raise AppServerError("request_too_large", f"prompt exceeds {MAX_PROMPT_CHARS} characters")
        return prompt

    @staticmethod
    def _fingerprint(*, prompt: str, actor_id: str) -> str:
        payload = json.dumps(
            {"actor_id": actor_id, "prompt": prompt},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return "sha256:" + hashlib.sha256(payload).hexdigest()

    def _require_record(self, run_id: Any, actor_id: str) -> _RunRecord:
        run_key = self._id(run_id, field_name="run_id")
        with self._lock:
            record = self._records.get(run_key)
            if record is None:
                raise AppServerError("not_found", f"unknown run_id {run_key!r}")
            if not hmac.compare_digest(record.actor_id, actor_id):
                raise AppServerError("authorization_denied", "run is bound to a different actor")
            return record

    def _active_count(self) -> int:
        return sum(1 for record in self._records.values() if record.status in {"queued", "running"})

    def _prune(self) -> None:
        # Keep a bounded idempotency projection. Active records are never
        # evicted; terminal records can be inspected while their request key is
        # retained, then oldest terminal entries are dropped first even when an
        # active record happens to be older than them.
        while len(self._records) > self.max_active_runs + 128:
            candidate = next(
                ((run_id, record) for run_id, record in self._records.items() if record.terminal),
                None,
            )
            if candidate is None:
                break
            run_id, record = candidate
            self._records.pop(run_id, None)
            self._request_index.pop(record.request_id, None)
        while len(self._request_index) > 256:
            candidate = next(
                (
                    (request_id, run_id)
                    for request_id, (run_id, _fingerprint) in self._request_index.items()
                    if self._records.get(run_id) is None or self._records[run_id].terminal
                ),
                None,
            )
            if candidate is None:
                break
            request_id, run_id = candidate
            self._request_index.pop(request_id, None)
            self._records.pop(run_id, None)

    def _status_dict(self, record: _RunRecord, *, replayed: bool = False) -> dict[str, Any]:
        with self._lock:
            result = dict(record.result) if record.result is not None else None
            return {
                "run_id": record.run_id,
                "request_id": record.request_id,
                "actor_id": record.actor_id,
                "status": record.status,
                "created_at": record.created_at,
                "started_at": record.started_at,
                "finished_at": record.finished_at,
                "cancel_requested": record.cancel_requested,
                "event_count": record.next_sequence,
                "first_sequence": record.first_sequence,
                "next_sequence": record.next_sequence,
                "result": result,
                "replayed": replayed,
            }

    # -- lifecycle --------------------------------------------------------
    def start(self, *, request_id: str, actor_id: str, prompt: str) -> dict[str, Any]:
        request_key = self._id(request_id, field_name="request_id")
        actor_key = self._id(actor_id, field_name="actor_id")
        prompt_text = self._prompt(prompt)
        fingerprint = self._fingerprint(prompt=prompt_text, actor_id=actor_key)
        thread: threading.Thread
        with self._lock:
            existing = self._request_index.get(request_key)
            if existing is not None:
                run_id, old_fingerprint = existing
                record = self._records.get(run_id)
                if record is None:
                    raise AppServerError("idempotency_lost", "request index points to a missing run")
                if not hmac.compare_digest(old_fingerprint, fingerprint):
                    raise AppServerError(
                        "idempotency_conflict",
                        "request_id was already used with different claims or prompt",
                    )
                return self._status_dict(record, replayed=True)
            if self._active_count() >= self.max_active_runs:
                raise AppServerError("capacity_exhausted", "maximum active background runs reached")
            now = float(self.clock())
            run_id = "app-" + uuid.uuid4().hex
            record = _RunRecord(
                run_id=run_id,
                request_id=request_key,
                actor_id=actor_key,
                fingerprint=fingerprint,
                prompt=prompt_text,
                created_at=now,
            )
            self._records[run_id] = record
            self._request_index[request_key] = (run_id, fingerprint)
            thread = threading.Thread(
                target=self._execute,
                args=(record,),
                name=f"northstar-app-{run_id[-12:]}",
                daemon=True,
            )
            record.thread = thread
            self._prune()
        thread.start()
        return self._status_dict(record)

    def _failure_result(self, message: str) -> dict[str, Any]:
        return {
            "type": "result",
            "subtype": "error_during_execution",
            "is_error": True,
            "num_turns": 0,
            "duration_ms": 0,
            "total_cost_usd": 0.0,
            "total_usage": {
                "input_tokens": 0,
                "output_tokens": 0,
                "cache_read_input_tokens": 0,
                "cache_creation_input_tokens": 0,
            },
            "session_id": "",
            "pricing_estimated": False,
            "context_windows": 1,
            "context_overflow_retries": 0,
            "errors": [message],
            "permission_denials": [],
        }

    def _append_event(self, record: _RunRecord, event: dict[str, Any]) -> None:
        with self._lock:
            entry = {"sequence": record.next_sequence, "event": event}
            record.next_sequence += 1
            record.events.append(entry)
            while len(record.events) > self.max_event_retention:
                record.events.pop(0)
                record.first_sequence += 1
            if event.get("type") == "result":
                record.result = dict(event)
            self._changed.notify_all()

    def _execute(self, record: _RunRecord) -> None:
        with self._lock:
            record.status = "running"
            record.started_at = float(self.clock())
            self._changed.notify_all()
        try:
            runtime = self.runtime_factory()
            with self._lock:
                record.runtime = runtime
                cancel_requested = record.cancel_requested
            if cancel_requested:
                request_cancel = getattr(runtime, "request_cancel", None)
                if callable(request_cancel):
                    request_cancel()
            run_method = getattr(runtime, "run", None)
            if not callable(run_method):
                raise TypeError("runtime_factory must return an object with run(prompt)")
            for event in run_method(record.prompt):
                self._append_event(record, event_to_dict(event))
            with self._lock:
                if record.result is None:
                    record.result = self._failure_result("runtime ended without a terminal result event")
                    self._append_event(record, record.result)
        except Exception as error:  # noqa: BLE001 - app-server must remain an event surface
            failure = self._failure_result(f"background runtime failure: {type(error).__name__}: {error}")
            self._append_event(record, failure)
        finally:
            with self._lock:
                record.finished_at = float(self.clock())
                subtype = str((record.result or {}).get("subtype", "error_during_execution"))
                record.status = "cancelled" if subtype == "error_cancelled" else ("success" if subtype == "success" else "failed")
                self._prune()
                self._changed.notify_all()

    def status(self, *, run_id: str, actor_id: str) -> dict[str, Any]:
        actor_key = self._id(actor_id, field_name="actor_id")
        return self._status_dict(self._require_record(run_id, actor_key))

    def events(self, *, run_id: str, actor_id: str, from_sequence: int = 0, limit: int = MAX_EVENT_PAGE) -> dict[str, Any]:
        actor_key = self._id(actor_id, field_name="actor_id")
        record = self._require_record(run_id, actor_key)
        if isinstance(from_sequence, bool) or not isinstance(from_sequence, int) or from_sequence < 0:
            raise AppServerError("invalid_request", "from_sequence must be a non-negative integer")
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1 or limit > MAX_EVENT_PAGE:
            raise AppServerError("invalid_request", f"limit must be between 1 and {MAX_EVENT_PAGE}")
        with self._lock:
            if from_sequence < record.first_sequence:
                raise AppServerError(
                    "cursor_expired",
                    "event cursor is older than the bounded in-memory retention window",
                    details={"first_sequence": record.first_sequence},
                )
            if from_sequence > record.next_sequence:
                raise AppServerError("invalid_request", "from_sequence is beyond the event cursor")
            selected = [entry for entry in record.events if entry["sequence"] >= from_sequence][:limit]
            next_sequence = selected[-1]["sequence"] + 1 if selected else from_sequence
            return {
                "run_id": record.run_id,
                "events": [dict(entry) for entry in selected],
                "has_more": next_sequence < record.next_sequence,
                "next_sequence": next_sequence,
                "first_sequence": record.first_sequence,
                "event_count": record.next_sequence,
            }

    def cancel(self, *, run_id: str, actor_id: str) -> dict[str, Any]:
        actor_key = self._id(actor_id, field_name="actor_id")
        record = self._require_record(run_id, actor_key)
        runtime: Any | None
        with self._lock:
            if record.terminal:
                return self._status_dict(record)
            record.cancel_requested = True
            runtime = record.runtime
            self._changed.notify_all()
        if runtime is not None:
            request_cancel = getattr(runtime, "request_cancel", None)
            if callable(request_cancel):
                request_cancel()
        return self._status_dict(record)

    def wait(self, *, run_id: str, actor_id: str, timeout: float = 10.0) -> dict[str, Any]:
        actor_key = self._id(actor_id, field_name="actor_id")
        record = self._require_record(run_id, actor_key)
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout < 0:
            raise AppServerError("invalid_request", "timeout must be a non-negative number")
        deadline = time.monotonic() + float(timeout)
        with self._changed:
            while not record.terminal:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self._changed.wait(timeout=remaining)
            return self._status_dict(record)

    def shutdown(self, *, timeout: float = 10.0) -> list[dict[str, Any]]:
        """Request cooperative cancellation for active runs and wait boundedly.

        This is an explicit host lifecycle operation, not a wire operation. It
        never force-kills a provider, tool or Python thread. Runs that do not
        reach a governed cancellation boundary before ``timeout`` are returned
        with their current non-terminal status.
        """
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout < 0:
            raise AppServerError("invalid_request", "timeout must be a non-negative number")
        with self._lock:
            active = [record for record in self._records.values() if not record.terminal]
            runtimes = [record.runtime for record in active]
            for record in active:
                record.cancel_requested = True
            self._changed.notify_all()
        for runtime in runtimes:
            request_cancel = getattr(runtime, "request_cancel", None)
            if callable(request_cancel):
                request_cancel()
        deadline = time.monotonic() + float(timeout)
        with self._changed:
            while any(not record.terminal for record in active):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self._changed.wait(timeout=remaining)
            return [self._status_dict(record) for record in active]


# -- authenticated wire protocol ------------------------------------------


def _canonical_payload(payload: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(
            dict(payload),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise AppServerError("invalid_request", f"request is not canonical JSON: {error}") from error


def _mac(payload: Mapping[str, Any], secret: bytes) -> str:
    return "hmac-sha256:" + hmac.new(secret, _canonical_payload(payload), hashlib.sha256).hexdigest()


def _without_auth(payload: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in payload.items() if key != "auth"}


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AppServerError("invalid_request", f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _secret(value: bytes) -> bytes:
    if not isinstance(value, bytes) or len(value) < 16:
        raise ValueError("channel_secret must be at least 16 bytes")
    return value


class AppServer:
    """Authenticated dispatcher plus an optional private Unix socket."""

    def __init__(
        self,
        manager: RunManager,
        *,
        channel_secret: bytes,
        socket_path: str | os.PathLike[str] | None = None,
        max_frame_bytes: int = MAX_FRAME_BYTES,
    ) -> None:
        if not isinstance(manager, RunManager):
            raise TypeError("manager must be a RunManager")
        if isinstance(max_frame_bytes, bool) or not isinstance(max_frame_bytes, int) or max_frame_bytes < 1024:
            raise ValueError("max_frame_bytes must be >= 1024")
        self.manager = manager
        self.channel_secret = _secret(channel_secret)
        self.socket_path = _socket_path(socket_path) if socket_path is not None else None
        self.max_frame_bytes = max_frame_bytes
        self._server: socketserver.ThreadingUnixStreamServer | None = None
        self._server_thread: threading.Thread | None = None
        self._owned_socket: Path | None = None
        self._lifecycle_lock = threading.RLock()
        self._stop_requested = threading.Event()
        self._ready = threading.Event()
        self._startup_error: BaseException | None = None

    def _response(self, *, request_id: str, ok: bool, **fields: Any) -> dict[str, Any]:
        response: dict[str, Any] = {
            "protocol": APP_PROTOCOL,
            "request_id": request_id,
            "ok": ok,
            **fields,
        }
        response["auth"] = _mac(response, self.channel_secret)
        if len(_json_line(response)) > self.max_frame_bytes:
            raise AppServerError("frame_too_large", "app-server response exceeds the configured bound")
        return response

    def _error(self, request_id: str, error: AppServerError) -> dict[str, Any]:
        return self._response(request_id=request_id, ok=False, error=error.as_dict())

    def handle_wire_line(self, line: bytes | str) -> dict[str, Any]:
        if isinstance(line, bytes):
            if len(line) > self.max_frame_bytes:
                return self._error("", AppServerError("frame_too_large", "request frame exceeds the configured bound"))
            try:
                text = line.decode("utf-8")
            except UnicodeDecodeError:
                return self._error("", AppServerError("invalid_request", "request must be UTF-8 JSON"))
        elif isinstance(line, str):
            if len(line.encode("utf-8")) > self.max_frame_bytes:
                return self._error("", AppServerError("frame_too_large", "request frame exceeds the configured bound"))
            text = line
        else:
            return self._error("", AppServerError("invalid_request", "request must be bytes or text"))
        request_id = ""
        try:
            raw = json.loads(text, object_pairs_hook=_strict_object)
            if not isinstance(raw, dict):
                raise AppServerError("invalid_request", "request must be a JSON object")
            request_id = str(raw.get("request_id", "")) if isinstance(raw.get("request_id", ""), str) else ""
            if raw.get("protocol") != APP_PROTOCOL:
                raise AppServerError("protocol_mismatch", f"protocol must be {APP_PROTOCOL}")
            request_auth = raw.get("auth")
            if not isinstance(request_auth, str):
                raise AppServerError("authentication_failed", "request HMAC is required")
            unsigned = _without_auth(raw)
            expected = _mac(unsigned, self.channel_secret)
            if not hmac.compare_digest(request_auth, expected):
                raise AppServerError("authentication_failed", "request HMAC is invalid")
            request_id = RunManager._id(raw.get("request_id"), field_name="request_id")
            actor_id = RunManager._id(raw.get("actor_id"), field_name="actor_id")
            operation = raw.get("op")
            if operation == "run.start":
                allowed = {"protocol", "auth", "request_id", "actor_id", "op", "prompt"}
                _reject_unknown(raw, allowed)
                result = self.manager.start(request_id=request_id, actor_id=actor_id, prompt=raw.get("prompt"))
                result.pop("request_id", None)
                return self._response(request_id=request_id, ok=True, op=operation, **result)
            if operation == "run.status":
                allowed = {"protocol", "auth", "request_id", "actor_id", "op", "run_id"}
                _reject_unknown(raw, allowed)
                result = self.manager.status(run_id=raw.get("run_id"), actor_id=actor_id)
                result.pop("request_id", None)
                return self._response(request_id=request_id, ok=True, op=operation, **result)
            if operation == "run.events":
                allowed = {"protocol", "auth", "request_id", "actor_id", "op", "run_id", "from_sequence", "limit"}
                _reject_unknown(raw, allowed)
                result = self.manager.events(
                    run_id=raw.get("run_id"),
                    actor_id=actor_id,
                    from_sequence=raw.get("from_sequence", 0),
                    limit=raw.get("limit", MAX_EVENT_PAGE),
                )
                return self._response(request_id=request_id, ok=True, op=operation, **result)
            if operation == "run.cancel":
                allowed = {"protocol", "auth", "request_id", "actor_id", "op", "run_id"}
                _reject_unknown(raw, allowed)
                result = self.manager.cancel(run_id=raw.get("run_id"), actor_id=actor_id)
                result.pop("request_id", None)
                return self._response(request_id=request_id, ok=True, op=operation, **result)
            if operation == "run.wait":
                allowed = {"protocol", "auth", "request_id", "actor_id", "op", "run_id", "timeout_ms"}
                _reject_unknown(raw, allowed)
                timeout_ms = raw.get("timeout_ms", DEFAULT_WAIT_MS)
                if isinstance(timeout_ms, bool) or not isinstance(timeout_ms, int) or timeout_ms < 0 or timeout_ms > MAX_WAIT_MS:
                    raise AppServerError("invalid_request", f"timeout_ms must be between 0 and {MAX_WAIT_MS}")
                result = self.manager.wait(
                    run_id=raw.get("run_id"),
                    actor_id=actor_id,
                    timeout=timeout_ms / 1000,
                )
                result.pop("request_id", None)
                return self._response(request_id=request_id, ok=True, op=operation, **result)
            raise AppServerError("invalid_request", "op must be one of run.start, run.status, run.events, run.cancel, run.wait")
        except json.JSONDecodeError as error:
            return self._error(request_id, AppServerError("invalid_request", f"invalid JSON: {error.msg}"))
        except AppServerError as error:
            return self._error(request_id, error)
        except Exception as error:  # noqa: BLE001 - malformed wire input is an error response
            return self._error(request_id, AppServerError("internal_error", f"app-server failure: {type(error).__name__}: {error}"))

    # -- Unix socket lifecycle -------------------------------------------
    def serve_forever(self) -> None:
        server: socketserver.ThreadingUnixStreamServer | None = None
        path = self.socket_path
        try:
            if path is None:
                raise AppServerError("configuration_error", "socket_path is required for serve_forever")
            if os.name == "nt":
                raise AppServerError("configuration_error", "the experimental app-server requires Unix domain sockets")
            _prepare_socket_parent(path.parent)
            if path.exists() or path.is_symlink():
                raise AppServerError("socket_exists", f"refusing to overwrite existing socket path {path}")
            app = self

            class _Server(socketserver.ThreadingUnixStreamServer):
                daemon_threads = True
                allow_reuse_address = False

            class _Handler(socketserver.StreamRequestHandler):
                def handle(self) -> None:
                    line = self.rfile.readline(app.max_frame_bytes + 1)
                    if len(line) > app.max_frame_bytes:
                        response = app._error("", AppServerError("frame_too_large", "request frame exceeds the configured bound"))
                    elif not line:
                        return
                    else:
                        response = app.handle_wire_line(line)
                    self.wfile.write(_json_line(response))
                    self.wfile.flush()

            server = _Server(str(path), _Handler)
            with self._lifecycle_lock:
                self._owned_socket = path
            os.chmod(path, 0o600)
            with self._lifecycle_lock:
                if self._stop_requested.is_set():
                    self._owned_socket = path
                    self._ready.set()
                    return
                self._server = server
                self._owned_socket = path
                self._ready.set()
            server.serve_forever(poll_interval=0.1)
        except BaseException as error:
            with self._lifecycle_lock:
                if not self._ready.is_set():
                    self._startup_error = error
                    self._ready.set()
            raise
        finally:
            if server is not None:
                server.server_close()
            with self._lifecycle_lock:
                if self._server is server:
                    self._server = None
                if path is not None and self._owned_socket == path:
                    try:
                        path.unlink()
                    except FileNotFoundError:
                        pass
                    self._owned_socket = None

    def _serve_background(self) -> None:
        # ``wait_ready`` exposes startup failures to the host; do not emit an
        # uncaught background-thread traceback for an expected bind rejection.
        try:
            self.serve_forever()
        except Exception:
            return

    def start(self) -> threading.Thread:
        with self._lifecycle_lock:
            if self._server_thread is not None and self._server_thread.is_alive():
                return self._server_thread
            self._stop_requested.clear()
            self._ready.clear()
            self._startup_error = None
            thread = threading.Thread(target=self._serve_background, name="northstar-app-server", daemon=True)
            self._server_thread = thread
            thread.start()
            return thread

    def wait_ready(self, *, timeout: float = 5.0) -> None:
        """Wait for ``start()`` to bind its socket or report startup failure."""
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout < 0:
            raise AppServerError("invalid_request", "timeout must be a non-negative number")
        if not self._ready.wait(timeout=float(timeout)):
            raise AppServerError("startup_timeout", "app-server did not become ready before the deadline")
        with self._lifecycle_lock:
            error = self._startup_error
        if error is None:
            return
        if isinstance(error, AppServerError):
            raise error
        raise AppServerError("startup_failed", f"app-server startup failed: {type(error).__name__}: {error}") from error

    def close(self) -> None:
        with self._lifecycle_lock:
            self._stop_requested.set()
            server = self._server
            thread = self._server_thread
        if server is not None and thread is not threading.current_thread():
            server.shutdown()
        if thread is not None and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=2.0)
        with self._lifecycle_lock:
            if self._server_thread is thread and (thread is None or not thread.is_alive()):
                self._server_thread = None


def _reject_unknown(raw: Mapping[str, Any], allowed: set[str]) -> None:
    unknown = sorted(set(raw) - allowed)
    if unknown:
        raise AppServerError("invalid_request", f"unknown request field(s): {', '.join(unknown)}")


def _socket_path(value: str | os.PathLike[str]) -> Path:
    path = Path(value)
    if not path.is_absolute() or path.name in {"", ".", ".."}:
        raise ValueError("socket_path must be an absolute non-directory path")
    if path.name != "app.sock":
        raise ValueError("socket_path filename must be app.sock")
    return path


def _prepare_socket_parent(parent: Path) -> None:
    if parent != parent.resolve(strict=False):
        raise AppServerError("insecure_socket_directory", "socket parent must not traverse a symlink")
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    mode = os.stat(parent).st_mode & 0o777
    if mode & 0o077:
        raise AppServerError("insecure_socket_directory", "socket parent directory must be owner-only")


def _json_line(payload: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(
            dict(payload),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


class AppClient:
    """Small authenticated client for the experimental Unix app-server."""

    def __init__(self, socket_path: str | os.PathLike[str], *, channel_secret: bytes, timeout: float = 5.0) -> None:
        self.socket_path = _socket_path(socket_path)
        self.channel_secret = _secret(channel_secret)
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("timeout must be positive")
        self.timeout = float(timeout)

    def call(self, operation: str, *, request_id: str, actor_id: str, **fields: Any) -> dict[str, Any]:
        reserved = _RESERVED_CLIENT_FIELDS.intersection(fields)
        if reserved:
            raise ValueError(f"client fields cannot override reserved wire fields: {', '.join(sorted(reserved))}")
        request: dict[str, Any] = {
            "protocol": APP_PROTOCOL,
            "op": operation,
            "request_id": request_id,
            "actor_id": actor_id,
            **fields,
        }
        request["auth"] = _mac(request, self.channel_secret)
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(self.timeout)
                connection.connect(str(self.socket_path))
                connection.sendall(_json_line(request))
                with connection.makefile("rb") as stream:
                    response_line = stream.readline(MAX_FRAME_BYTES + 1)
        except OSError as error:
            raise AppServerError("transport_unavailable", f"app-server socket unavailable: {error}") from error
        if len(response_line) > MAX_FRAME_BYTES:
            raise AppServerError("frame_too_large", "app-server response exceeds the configured bound")
        try:
            response = json.loads(response_line)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise AppServerError("invalid_response", "app-server response is not valid JSON") from error
        if not isinstance(response, dict) or response.get("protocol") != APP_PROTOCOL:
            raise AppServerError("protocol_mismatch", "app-server response protocol is invalid")
        response_auth = response.get("auth")
        if not isinstance(response_auth, str) or not hmac.compare_digest(response_auth, _mac(_without_auth(response), self.channel_secret)):
            raise AppServerError("authentication_failed", "app-server response HMAC is invalid")
        if response.get("request_id") != request_id:
            raise AppServerError("invalid_response", "app-server response request_id does not match")
        if not response.get("ok"):
            error = response.get("error")
            if isinstance(error, dict):
                raise AppServerError(str(error.get("code", "remote_error")), str(error.get("message", "app-server request failed")), details=error)
            raise AppServerError("remote_error", "app-server request failed")
        return response

    def start(self, *, request_id: str, actor_id: str, prompt: str) -> dict[str, Any]:
        return self.call("run.start", request_id=request_id, actor_id=actor_id, prompt=prompt)

    def status(self, *, request_id: str, actor_id: str, run_id: str) -> dict[str, Any]:
        return self.call("run.status", request_id=request_id, actor_id=actor_id, run_id=run_id)

    def events(self, *, request_id: str, actor_id: str, run_id: str, from_sequence: int = 0, limit: int = MAX_EVENT_PAGE) -> dict[str, Any]:
        return self.call(
            "run.events",
            request_id=request_id,
            actor_id=actor_id,
            run_id=run_id,
            from_sequence=from_sequence,
            limit=limit,
        )

    def cancel(self, *, request_id: str, actor_id: str, run_id: str) -> dict[str, Any]:
        return self.call("run.cancel", request_id=request_id, actor_id=actor_id, run_id=run_id)

    def wait(
        self,
        *,
        request_id: str,
        actor_id: str,
        run_id: str,
        timeout_ms: int = DEFAULT_WAIT_MS,
    ) -> dict[str, Any]:
        return self.call(
            "run.wait",
            request_id=request_id,
            actor_id=actor_id,
            run_id=run_id,
            timeout_ms=timeout_ms,
        )


__all__ = [
    "APP_PROTOCOL",
    "AppClient",
    "AppServer",
    "AppServerError",
    "DEFAULT_ACTIVE_RUNS",
    "DEFAULT_EVENT_RETENTION",
    "DEFAULT_WAIT_MS",
    "MAX_EVENT_PAGE",
    "MAX_WAIT_MS",
    "MAX_FRAME_BYTES",
    "MAX_PROMPT_CHARS",
    "RunManager",
]
