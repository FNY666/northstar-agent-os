"""Zero-dependency Unix-socket client for northstar-codex-sidecar.

One connection, one JSON request line, one JSON response line — the exact
protocol the sidecar's listener serves. All failures are returned as
structured statuses (``transport_unavailable``, ``timeout``,
``protocol_error``), never raised: the runtime turns them into tool results,
and the sidecar's own status taxonomy is preserved end to end.
"""
from __future__ import annotations

import json
import socket
import uuid
from typing import Any

MAX_RESPONSE_BYTES = 8 * 1024 * 1024


class SidecarClient:
    def __init__(self, socket_path: str, timeout: float = 310.0) -> None:
        self.socket_path = str(socket_path)
        self.timeout = timeout

    def execute(self, prompt: str, timeout_ms: int = 300_000) -> dict[str, Any]:
        request_id = uuid.uuid4().hex[:32]
        request = {"request_id": request_id, "prompt": prompt, "timeout_ms": int(timeout_ms)}
        wire = json.dumps(request, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n"
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect(self.socket_path)
                sock.sendall(wire)
                buffer = b""
                while b"\n" not in buffer and len(buffer) < MAX_RESPONSE_BYTES:
                    chunk = sock.recv(65536)
                    if not chunk:
                        break
                    buffer += chunk
        except socket.timeout:
            return {"request_id": request_id, "status": "timeout"}
        except OSError:
            return {"request_id": request_id, "status": "transport_unavailable"}
        if not buffer:
            return {"request_id": request_id, "status": "transport_unavailable"}
        line = buffer.split(b"\n", 1)[0]
        try:
            value = json.loads(line.decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            return {"request_id": request_id, "status": "protocol_error", "error": "invalid JSON response"}
        if not isinstance(value, dict):
            return {"request_id": request_id, "status": "protocol_error", "error": "non-object response"}
        value.setdefault("request_id", request_id)
        return value
