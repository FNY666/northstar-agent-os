"""Agent-side client for the egress sidecar.

The only network the agent may touch: a Unix-socket request to the sidecar
daemon, which owns every credential and every outbound connection. This
client never opens a raw socket to the internet -- it cannot; it only speaks
the sidecar's JSON-lines protocol over ``AF_UNIX``.

Typical use::

    client = EgressClient("/var/run/northstar-egress/egress.sock")
    result = client.request(
        agent_id="main", run_id="run-1",
        host="rekor.sigstore.dev", port=443,
        method="POST", path="/api/v1/log/entries",
        headers={"content-type": "application/json"}, body=b"{}",
        call_id="call-9", arguments={...},
        card=card.as_dict(), approval_receipt=receipt.as_dict(),
    )
    if result.status == "ok":
        ...  # result.body, result.http_status, result.receipt
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import secrets
import socket
import time
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any

#: The socket must live under the sidecar's private runtime directory.
#: "Do not expose the socket over TCP" (same rule as the codex sidecar).
SOCKET_ROOT = PurePosixPath("/var/run/northstar-egress")
SOCKET_NAME = "egress.sock"

MIN_TIMEOUT_MS = 1_000
MAX_TIMEOUT_MS = 120_000
MAX_RESPONSE_BYTES = 5_000_000


class EgressClientError(ValueError):
    """A client-side configuration error. Fails before any socket opens."""


@dataclass(frozen=True)
class EgressResult:
    """One completed sidecar round-trip. Never raises for expected conditions."""

    request_id: str
    status: str  # ok | denied | rejected | error | transport_unavailable | protocol_error
    http_status: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    truncated: bool = False
    deny_code: str = ""
    reason: str = ""
    errors: tuple[str, ...] = ()
    receipt: dict[str, Any] | None = None
    latency_ms: int = 0


def validate_socket_path(value: str | os.PathLike[str]) -> tuple[bool, tuple[str, ...]]:
    text = os.fspath(value)
    path = PurePosixPath(text)
    if not text.startswith(str(SOCKET_ROOT) + "/"):
        return False, ("egress socket must be below the private sidecar runtime directory",)
    if path.name != SOCKET_NAME:
        return False, (f"socket filename must be {SOCKET_NAME}",)
    return True, ()


class EgressClient:
    """One-connection-per-request Unix socket client for the egress sidecar."""

    def __init__(
        self,
        socket_path: str | os.PathLike[str],
        *,
        timeout_ms: int = 30_000,
        connect_timeout_s: float = 5.0,
        max_response_bytes: int = MAX_RESPONSE_BYTES,
    ) -> None:
        text = os.fspath(socket_path)
        ok, errors = validate_socket_path(text)
        if not ok:
            raise EgressClientError("refusing to build an egress client: " + "; ".join(errors))
        if not MIN_TIMEOUT_MS <= int(timeout_ms) <= MAX_TIMEOUT_MS:
            raise EgressClientError(f"timeout_ms must be between {MIN_TIMEOUT_MS} and {MAX_TIMEOUT_MS}")
        self.socket_path = text
        self.timeout_ms = int(timeout_ms)
        self.connect_timeout_s = float(connect_timeout_s)
        self.max_response_bytes = int(max_response_bytes)

    def new_request_id(self) -> str:
        return f"egress-{secrets.token_hex(8)}"

    def request(
        self,
        *,
        agent_id: str,
        run_id: str,
        host: str,
        port: int,
        method: str,
        path: str,
        headers: dict[str, str] | None = None,
        body: bytes = b"",
        timeout_ms: int | None = None,
        call_id: str = "",
        arguments: dict[str, Any] | None = None,
        card: dict[str, Any] | None = None,
        approval_receipt: dict[str, Any] | None = None,
        request_id: str | None = None,
    ) -> EgressResult:
        """Send one egress request through the sidecar. Never raises for an
        expected condition (denial, rejection, transport failure)."""
        rid = request_id or self.new_request_id()
        started = time.monotonic()
        wire: dict[str, Any] = {
            "request_id": rid,
            "agent_id": agent_id,
            "run_id": run_id,
            "host": host,
            "port": port,
            "method": method,
            "path": path,
            "headers": dict(headers or {}),
            "body_b64": base64.b64encode(body or b"").decode("ascii"),
            "timeout_ms": self.timeout_ms if timeout_ms is None else int(timeout_ms),
            "call_id": call_id,
            "arguments": dict(arguments or {}),
        }
        if card is not None:
            wire["card"] = card
        if approval_receipt is not None:
            wire["approval_receipt"] = approval_receipt
        try:
            line = self._round_trip(wire)
        except FileNotFoundError as error:
            return self._failure(rid, "transport_unavailable", f"egress socket is not present: {error}", started)
        except (TimeoutError, socket.timeout) as error:
            return self._failure(rid, "transport_unavailable", f"sidecar did not answer in time: {error}", started)
        except OSError as error:
            return self._failure(rid, "transport_unavailable", f"egress transport failed: {error}", started)
        latency_ms = int((time.monotonic() - started) * 1000)
        try:
            payload = json.loads(line)
        except (TypeError, json.JSONDecodeError) as error:
            return self._failure(rid, "protocol_error", f"sidecar returned non-JSON: {error}", started)
        if not isinstance(payload, dict) or payload.get("request_id") != rid:
            return self._failure(rid, "protocol_error", "sidecar response did not match the request", started)
        status = str(payload.get("status", "protocol_error"))
        body_bytes = b""
        raw_body = payload.get("body_b64", "")
        if isinstance(raw_body, str) and raw_body:
            try:
                body_bytes = base64.b64decode(raw_body, validate=True)
            except (binascii.Error, ValueError):
                return self._failure(rid, "protocol_error", "sidecar returned invalid body_b64", started)
        headers_out = payload.get("headers")
        return EgressResult(
            request_id=rid,
            status=status,
            http_status=payload.get("http_status"),
            headers=dict(headers_out) if isinstance(headers_out, dict) else {},
            body=body_bytes,
            truncated=bool(payload.get("truncated", False)),
            deny_code=str(payload.get("deny_code", "") or ""),
            reason=str(payload.get("reason", "") or payload.get("error", "") or ""),
            errors=tuple(payload.get("errors", ()) or ()),
            receipt=payload.get("receipt") if isinstance(payload.get("receipt"), dict) else None,
            latency_ms=latency_ms,
        )

    def _failure(self, rid: str, status: str, message: str, started: float) -> EgressResult:
        return EgressResult(
            request_id=rid,
            status=status,
            errors=(message,),
            latency_ms=int((time.monotonic() - started) * 1000),
        )

    def _round_trip(self, wire: dict[str, Any]) -> str:
        data = (json.dumps(wire, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.settimeout(self.connect_timeout_s)
            sock.connect(self.socket_path)
            sock.sendall(data)
            # The read deadline covers the sidecar's own timeout plus grace.
            sock.settimeout(self.timeout_ms / 1000.0 + 10.0)
            chunks: list[bytes] = []
            total = 0
            while total <= self.max_response_bytes:
                chunk = sock.recv(min(65536, self.max_response_bytes + 1 - total))
                if not chunk:
                    break
                newline = chunk.find(b"\n")
                if newline >= 0:
                    chunks.append(chunk[:newline])
                    return b"".join(chunks).decode("utf-8", "replace")
                chunks.append(chunk)
                total += len(chunk)
            raise OSError("sidecar response exceeded the byte cap or never terminated")
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def probe(self) -> EgressResult:
        """Health check: a deliberately invalid request; the sidecar must
        answer ``rejected`` (proving it is alive) rather than time out."""
        return self.request(
            agent_id="probe",
            run_id="probe",
            host="",
            port=0,
            method="",
            path="",
            timeout_ms=MIN_TIMEOUT_MS,
        )
