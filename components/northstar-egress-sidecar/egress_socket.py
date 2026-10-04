"""Private Unix-socket entry point for the egress sidecar."""
from __future__ import annotations

import os
import socket
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path, PurePosixPath

from egress_sidecar import SOCKET_ROOT, SidecarContext, build_context, run_one
from transport import MAX_LINE_BYTES, decode_request, encode_response

SOCKET_PATH = str(SOCKET_ROOT / "egress.sock")
MAX_WORKERS = 16
CONNECTION_READ_TIMEOUT = 15.0


def socket_mode() -> int:
    return 0o660


def validate_socket_path(value: str) -> tuple[bool, tuple[str, ...]]:
    path = PurePosixPath(value)
    if not value.startswith(str(SOCKET_ROOT) + "/"):
        return False, ("socket must be below the private sidecar runtime directory",)
    if path.name != "egress.sock":
        return False, ("socket filename must be egress.sock",)
    return True, ()


def read_json_line(conn: socket.socket) -> str | None:
    chunks: list[bytes] = []
    total = 0
    while total <= MAX_LINE_BYTES:
        chunk = conn.recv(min(8192, MAX_LINE_BYTES + 1 - total))
        if not chunk:
            break
        newline = chunk.find(b"\n")
        if newline >= 0:
            chunks.append(chunk[:newline])
            return b"".join(chunks).decode("utf-8", "replace")
        chunks.append(chunk)
        total += len(chunk)
    return None


def handle_line(line: str, ctx: SidecarContext) -> str:
    request = decode_request(line)
    if request is None:
        return encode_response({"request_id": None, "status": "rejected", "errors": ["invalid JSON request"]})
    return encode_response(run_one(request, ctx))


def handle_connection(conn: socket.socket, ctx: SidecarContext) -> None:
    try:
        conn.settimeout(CONNECTION_READ_TIMEOUT)
        data = read_json_line(conn)
        if data is None:
            response = encode_response(
                {"request_id": None, "status": "rejected", "errors": ["invalid or oversized request"]}
            )
        else:
            response = handle_line(data, ctx)
        try:
            conn.sendall(response.encode("utf-8"))
        except OSError:
            pass
    except (OSError, TimeoutError):
        pass
    except Exception:
        try:
            conn.sendall(
                encode_response({"request_id": None, "status": "internal_error", "error": "sidecar request failed"}).encode(
                    "utf-8"
                )
            )
        except OSError:
            pass
    finally:
        try:
            conn.close()
        except (AttributeError, OSError):
            pass


def serve(ctx: SidecarContext, path: str = SOCKET_PATH) -> None:
    ok, errors = validate_socket_path(path)
    if not ok:
        # Fail at startup rather than publishing a socket the service contract
        # does not permit. systemd reports this as a start failure.
        raise ValueError("refusing to listen: " + "; ".join(errors))
    socket_path = Path(path)
    socket_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        socket_path.unlink()
    except FileNotFoundError:
        pass
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(socket_path))
    os.chmod(socket_path, socket_mode())
    server.listen(MAX_WORKERS)
    pool = ThreadPoolExecutor(max_workers=MAX_WORKERS)
    try:
        while True:
            conn, _ = server.accept()
            pool.submit(handle_connection, conn, ctx)
    finally:
        server.close()
        pool.shutdown(wait=True)
        try:
            socket_path.unlink()
        except FileNotFoundError:
            pass


def main() -> None:
    policy_dir = os.environ.get("NORTHSTAR_EGRESS_POLICY_DIR", "/etc/northstar-egress")
    seed_hex = os.environ.get("NORTHSTAR_EGRESS_SIGNING_SEED", "").strip()
    enforcer_seed = bytes.fromhex(seed_hex) if seed_hex else None
    if enforcer_seed is not None and len(enforcer_seed) != 32:
        raise ValueError("NORTHSTAR_EGRESS_SIGNING_SEED must be 64 hex chars (32 bytes)")
    ctx = build_context(
        policy_dir=policy_dir,
        enforcer_seed=enforcer_seed,
        key_id=os.environ.get("NORTHSTAR_EGRESS_KEY_ID") or None,
    )
    serve(ctx, os.environ.get("NORTHSTAR_EGRESS_SOCKET", SOCKET_PATH))


if __name__ == "__main__":
    main()
