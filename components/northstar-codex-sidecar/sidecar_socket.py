"""Private Unix-socket entry point for the restricted sidecar."""
from __future__ import annotations
import os, socket
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from sidecar import run_one
from transport import MAX_LINE_CHARS, decode_request, encode_response

SOCKET_PATH = "/var/run/northstar-codex/sidecar.sock"
MAX_WORKERS = 8
CONNECTION_READ_TIMEOUT = 10.0

def socket_mode() -> int: return 0o660

def read_json_line(conn: socket.socket) -> str | None:
    chunks: list[bytes] = []; total = 0
    while total <= MAX_LINE_CHARS:
        chunk = conn.recv(min(8192, MAX_LINE_CHARS + 1 - total))
        if not chunk: break
        newline = chunk.find(b"\n")
        if newline >= 0:
            chunks.append(chunk[:newline]); return b"".join(chunks).decode("utf-8", "replace")
        chunks.append(chunk); total += len(chunk)
    return None

def handle_line(line: str) -> str:
    request = decode_request(line)
    if request is None:
        return encode_response({"request_id": None, "status": "rejected", "errors": ["invalid JSON request"]})
    return encode_response(run_one(request))

def handle_connection(conn: socket.socket) -> None:
    try:
        conn.settimeout(CONNECTION_READ_TIMEOUT)
        data = read_json_line(conn)
        if data is None:
            response = encode_response({"request_id": None, "status": "rejected", "errors": ["invalid or oversized request"]})
        else: response = handle_line(data)
        try: conn.sendall(response.encode("utf-8"))
        except OSError: pass
    except (OSError, TimeoutError): pass
    except Exception:
        try:
            conn.sendall(encode_response({"request_id": None, "status": "internal_error", "error": "sidecar request failed"}).encode("utf-8"))
        except OSError: pass
    finally:
        try: conn.close()
        except (AttributeError, OSError): pass

def serve(path: str = SOCKET_PATH) -> None:
    socket_path = Path(path); socket_path.parent.mkdir(parents=True, exist_ok=True)
    try: socket_path.unlink()
    except FileNotFoundError: pass
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(socket_path)); os.chmod(socket_path, socket_mode()); server.listen(MAX_WORKERS)
    pool = ThreadPoolExecutor(max_workers=MAX_WORKERS)
    try:
        while True:
            conn, _ = server.accept()
            pool.submit(handle_connection, conn)
    finally:
        server.close(); pool.shutdown(wait=True)
        try: socket_path.unlink()
        except FileNotFoundError: pass

if __name__ == "__main__": serve()
