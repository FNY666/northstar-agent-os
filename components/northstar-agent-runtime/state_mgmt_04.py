"""State 04: zlib compression for checkpoints, Simulated.

Compress checkpoint payloads with zlib before storage; decompress on
read.  Records original size and algorithm in the envelope so the
reader never has to guess.

Fail-closed: corrupt payload, wrong algorithm, or size mismatch raises.
"""

from __future__ import annotations

import ast
import json
import zlib
from typing import Any, Dict

MODULE_VERSION = "state-mgmt-04.v1"
SCHEMA_PIN = "northstar.state-mgmt-04.v1"
ALGORITHM = "zlib"


class CompressionError(Exception):
    pass


def compress(state: Dict[str, Any], *, level: int = 6) -> bytes:
    """Serialize state to JSON and zlib-compress. Returns envelope bytes."""
    if not isinstance(state, dict):
        raise CompressionError("state must be dict")
    if not 0 <= level <= 9:
        raise CompressionError("level must be 0..9")
    raw = json.dumps(state, sort_keys=True, separators=(",", ":")).encode("utf-8")
    payload = zlib.compress(raw, level)
    envelope = {
        "algorithm": ALGORITHM,
        "original_bytes": len(raw),
        "payload": payload.hex(),
    }
    return json.dumps(envelope, sort_keys=True).encode("utf-8")


def decompress(blob: bytes) -> Dict[str, Any]:
    """Decompress envelope bytes back to state dict. Fail-closed."""
    try:
        envelope = json.loads(blob.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as e:
        raise CompressionError(f"bad envelope: {e}")
    if envelope.get("algorithm") != ALGORITHM:
        raise CompressionError(f"unsupported algorithm {envelope.get('algorithm')!r}")
    try:
        payload = bytes.fromhex(envelope["payload"])
    except (KeyError, ValueError) as e:
        raise CompressionError(f"bad payload hex: {e}")
    try:
        raw = zlib.decompress(payload)
    except zlib.error as e:
        raise CompressionError(f"corrupt payload: {e}")
    if len(raw) != envelope.get("original_bytes"):
        raise CompressionError("size mismatch after decompress")
    try:
        state = json.loads(raw.decode("utf-8"))
    except ValueError as e:
        raise CompressionError(f"bad JSON inside payload: {e}")
    if not isinstance(state, dict):
        raise CompressionError("state must be dict")
    return state


def ratio(state: Dict[str, Any]) -> float:
    raw = json.dumps(state, sort_keys=True).encode("utf-8")
    return len(compress(state)) / max(1, len(raw))


def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "json", "pathlib", "typing", "zlib"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    state = {"ledger": [{"seq": i, "msg": "hello world"} for i in range(200)]}
    blob = compress(state)
    assert decompress(blob) == state
    assert ratio(state) < 1.0  # actually compresses
    # Corrupt payload
    env = json.loads(blob.decode())
    env["payload"] = env["payload"][:-4] + "ffff"
    try:
        decompress(json.dumps(env).encode())
        raise AssertionError("should raise")
    except CompressionError:
        pass
    # Wrong algorithm
    env2 = json.loads(blob.decode())
    env2["algorithm"] = "lzma"
    try:
        decompress(json.dumps(env2).encode())
        raise AssertionError("should raise")
    except CompressionError:
        pass
    assert stdlib_only()
    print("state_mgmt_04 OK: compress/decompress, envelope, fail-closed")


if __name__ == "__main__":
    main()
