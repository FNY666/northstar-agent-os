"""Private Unix-socket entry point for the egress sidecar."""
from __future__ import annotations

import os
import json
import re
import socket
import threading
from collections.abc import Mapping
from concurrent.futures import Executor, ThreadPoolExecutor
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
    """Read one UTF-8 JSONL request, counting the delimiter in the wire cap."""
    chunks: list[bytes] = []
    total = 0
    while total < MAX_LINE_BYTES:
        chunk = conn.recv(min(8192, MAX_LINE_BYTES - total))
        if not chunk:
            break
        newline = chunk.find(b"\n")
        if newline >= 0:
            if total + newline + 1 > MAX_LINE_BYTES:
                return None
            chunks.append(chunk[:newline])
            try:
                return b"".join(chunks).decode("utf-8", "strict")
            except UnicodeDecodeError:
                return None
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


def _handle_connection_with_slot(
    conn: socket.socket, ctx: SidecarContext, slots: threading.BoundedSemaphore
) -> None:
    try:
        handle_connection(conn, ctx)
    finally:
        slots.release()


def submit_connection(
    pool: Executor,
    slots: threading.BoundedSemaphore,
    conn: socket.socket,
    ctx: SidecarContext,
) -> bool:
    """Keep accepted sockets and queued work bounded by the worker budget."""
    if not slots.acquire(blocking=False):
        conn.close()
        return False
    try:
        pool.submit(_handle_connection_with_slot, conn, ctx, slots)
    except BaseException:
        slots.release()
        conn.close()
        raise
    return True


def signing_seed_from_environment(environ: Mapping[str, str] | None = None) -> bytes:
    """Load the mandatory production signing key from the sidecar environment."""
    values = os.environ if environ is None else environ
    seed_hex = values.get("NORTHSTAR_EGRESS_SIGNING_SEED", "").strip()
    if not seed_hex:
        raise ValueError("NORTHSTAR_EGRESS_SIGNING_SEED is required for the egress sidecar")
    if not re.fullmatch(r"[0-9a-fA-F]{64}", seed_hex):
        raise ValueError("NORTHSTAR_EGRESS_SIGNING_SEED must be 64 hex chars (32 bytes)")
    try:
        seed = bytes.fromhex(seed_hex)
    except ValueError as exc:
        raise ValueError("NORTHSTAR_EGRESS_SIGNING_SEED must be 64 hex chars (32 bytes)") from exc
    if len(seed) != 32:
        raise ValueError("NORTHSTAR_EGRESS_SIGNING_SEED must be 64 hex chars (32 bytes)")
    return seed


def key_id_from_environment(environ: Mapping[str, str] | None = None) -> str:
    values = os.environ if environ is None else environ
    key_id = values.get("NORTHSTAR_EGRESS_KEY_ID", "").strip()
    if not key_id or len(key_id) > 200 or key_id == "__legacy_default__":
        raise ValueError("NORTHSTAR_EGRESS_KEY_ID must be 1-200 characters and not the reserved legacy ID")
    return key_id


def trusted_public_keys_from_file(path: str | Path | None) -> dict[str, bytes]:
    """Read the operator-managed key-id -> 32-byte Ed25519 public-key map."""
    if path is None or not str(path).strip():
        return {}
    key_path = Path(path)

    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("trusted public key file contains duplicate key IDs")
            result[key] = value
        return result

    try:
        if not key_path.exists():
            return {}
        if key_path.stat().st_size > 65_536:
            raise ValueError("trusted public key file exceeds 64 KiB")
        value = json.loads(key_path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read trusted public keys: {type(exc).__name__}") from exc
    if not isinstance(value, dict) or len(value) > 128:
        raise ValueError("trusted public key file must be an object with at most 128 keys")
    result: dict[str, bytes] = {}
    for key_id, encoded in value.items():
        if (not isinstance(key_id, str) or not key_id or len(key_id) > 200
                or not isinstance(encoded, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", encoded)):
            raise ValueError("trusted public key entries must map key IDs to 64 hex chars")
        result[key_id] = bytes.fromhex(encoded)
    return result


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
    slots = threading.BoundedSemaphore(MAX_WORKERS)
    try:
        while True:
            conn, _ = server.accept()
            submit_connection(pool, slots, conn, ctx)
    finally:
        server.close()
        pool.shutdown(wait=True)
        try:
            socket_path.unlink()
        except FileNotFoundError:
            pass


def main() -> None:
    policy_dir = os.environ.get("NORTHSTAR_EGRESS_POLICY_DIR", "/etc/northstar-egress")
    enforcer_seed = signing_seed_from_environment()
    key_id = key_id_from_environment()
    trusted_keys_path = os.environ.get("NORTHSTAR_EGRESS_TRUSTED_KEYS", "").strip()
    trusted_public_keys = trusted_public_keys_from_file(trusted_keys_path)
    socket_path = os.environ.get("NORTHSTAR_EGRESS_SOCKET", SOCKET_PATH)
    # The receipt feed lives next to the socket by default; override with
    # NORTHSTAR_EGRESS_FEED (e.g. to put it on persistent storage -- the
    # socket dir may be tmpfs).
    feed_path = os.environ.get("NORTHSTAR_EGRESS_FEED", "").strip() or str(
        Path(socket_path).parent / "receipts.jsonl"
    )
    ctx = build_context(
        policy_dir=policy_dir,
        enforcer_seed=enforcer_seed,
        key_id=key_id,
        trusted_public_keys=trusted_public_keys,
        receipt_feed_path=feed_path,
    )
    serve(ctx, socket_path)


if __name__ == "__main__":
    main()
