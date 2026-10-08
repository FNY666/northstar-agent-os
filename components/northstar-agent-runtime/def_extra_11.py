"""Tamper detection for sealed blobs (mock), Simulated.

seal() wraps arbitrary bytes as v1.<b64>.<hmac>; open() verifies the
MAC and version before returning the payload.

What this IS: detect-at-read tamper evidence for stored blobs.

What this IS NOT:
* Not encryption -- the payload is only base64, readable by anyone.
* Wrong version or bad MAC FAILS CLOSED.
"""

from __future__ import annotations

import ast
import base64
import hashlib
import hmac
from typing import Tuple

#: Module version.
DEF_EXTRA_11_VERSION = "def-extra-11.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.def-extra-11.v1"


class TamperError(Exception):
    """Fail-closed."""


_SEAL_VERSION = "v1"


def seal(payload: bytes, key: bytes) -> str:
    """Seal bytes into a tamper-evident token."""
    if not key:
        raise TamperError("key required")
    body = base64.urlsafe_b64encode(payload).decode()
    mac = hmac.new(key, f"{_SEAL_VERSION}.{body}".encode(), hashlib.sha256).hexdigest()
    return f"{_SEAL_VERSION}.{body}.{mac}"


def open_seal(token: str, key: bytes) -> Tuple[bool, bytes, str]:
    """Open a sealed token.  Returns (ok, payload, detail)."""
    if not key:
        return False, b"", "no key"
    parts = token.split(".")
    if len(parts) != 3:
        return False, b"", "malformed token"
    version, body, mac = parts
    if version != _SEAL_VERSION:
        return False, b"", f"unsupported version {version}"
    expected = hmac.new(key, f"{version}.{body}".encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, mac):
        return False, b"", "tamper detected: bad MAC"
    try:
        payload = base64.urlsafe_b64decode(body.encode())
    except Exception:
        return False, b"", "bad payload encoding"
    return True, payload, "intact"


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "base64", "hashlib", "hmac", "pathlib", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    """Self-check."""
    key = b"seal-key"
    token = seal(b"secret-config", key)
    ok, payload, detail = open_seal(token, key)
    assert ok is True and payload == b"secret-config", detail
    # Flip one char of the body -> tamper.
    parts = token.split(".")
    bad_body = ("A" if parts[1][0] != "A" else "B") + parts[1][1:]
    ok, _, detail = open_seal(f"{parts[0]}.{bad_body}.{parts[2]}", key)
    assert ok is False and "tamper" in detail
    # Wrong key fails.
    ok, _, _ = open_seal(token, b"wrong-key")
    assert ok is False
    # Malformed fails closed.
    ok, _, _ = open_seal("not-a-token", key)
    assert ok is False
    assert stdlib_only()
    print("def-extra-11 OK: seal, tamper detection, fail-closed")


if __name__ == "__main__":
    main()
