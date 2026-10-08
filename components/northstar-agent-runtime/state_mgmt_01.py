"""State 01: versioned checkpoint schema, Simulated.

A checkpoint is a versioned, hash-verified snapshot of runtime state.
Format: {format_version, created_at, state, checksum}.

Fail-closed: bad checksum or unknown version raises.
"""

from __future__ import annotations

import ast
import hashlib
import json
from dataclasses import dataclass
from typing import Any, Dict

FORMAT_VERSION = "northstar-checkpoint.v1"
SCHEMA_PIN = "northstar.state-mgmt-01.v1"
MODULE_VERSION = "state-mgmt-01.v1"


class CheckpointError(Exception):
    pass


def checksum(state: Dict[str, Any]) -> str:
    canonical = json.dumps(state, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()


def encode(state: Dict[str, Any], *, created_at: str = "") -> str:
    """Encode a checkpoint to canonical JSON."""
    if not isinstance(state, dict):
        raise CheckpointError("state must be dict")
    doc = {
        "format_version": FORMAT_VERSION,
        "created_at": created_at,
        "state": state,
        "checksum": checksum(state),
    }
    return json.dumps(doc, sort_keys=True, separators=(",", ":"))


def decode(text: str) -> Dict[str, Any]:
    """Decode and verify a checkpoint. Fail-closed."""
    try:
        doc = json.loads(text)
    except (json.JSONDecodeError, ValueError) as e:
        raise CheckpointError(f"invalid JSON: {e}")
    if doc.get("format_version") != FORMAT_VERSION:
        raise CheckpointError("unsupported format_version")
    state = doc.get("state")
    if not isinstance(state, dict):
        raise CheckpointError("state missing or not dict")
    if doc.get("checksum") != checksum(state):
        raise CheckpointError("checksum mismatch (tampered)")
    return state


def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "dataclasses", "hashlib", "json", "pathlib", "typing"}
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
    s = {"seq": 3, "tool": "read", "args": {"p": "/x"}}
    enc = encode(s, created_at="t0")
    assert decode(enc) == s
    # Tamper -> fail-closed
    doc = json.loads(enc)
    doc["state"]["seq"] = 99
    try:
        decode(json.dumps(doc))
        raise AssertionError("should raise")
    except CheckpointError:
        pass
    # Bad version
    doc2 = json.loads(enc)
    doc2["format_version"] = "v9"
    try:
        decode(json.dumps(doc2))
        raise AssertionError("should raise")
    except CheckpointError:
        pass
    assert stdlib_only()
    print("state_mgmt_01 OK: versioned schema, checksum, fail-closed")


if __name__ == "__main__":
    main()
