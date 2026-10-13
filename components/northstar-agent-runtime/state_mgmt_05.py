"""State 05: encryption at rest (Fernet mock), Simulated.

Mock of Fernet semantics using stdlib only (no `cryptography` dep):
- key = 32 random bytes (urlsafe base64)
- seal: AES-less demo -> XOR keystream from HMAC-SHA256 counter +
        HMAC-SHA256 tag over (nonce || ciphertext), all base64.

This is NOT production crypto (XOR stream + HMAC is malleable-adjacent
in naive hands).  It models the API + key lifecycle; swap in real
Fernet/AES-GCM for production.

Fail-closed: bad key, bad tag, or malformed token raises.
"""

from __future__ import annotations

import ast
import base64
import hashlib
import hmac
import json
import os
from typing import Any, Dict

MODULE_VERSION = "state-mgmt-05.v1"
SCHEMA_PIN = "northstar.state-mgmt-05.v1"
NONCE_BYTES = 16
KEY_BYTES = 32


class SealError(Exception):
    pass


def generate_key() -> str:
    """Generate a urlsafe-base64 32-byte key (Fernet-shaped)."""
    return base64.urlsafe_b64encode(os.urandom(KEY_BYTES)).decode("ascii")


def _key_bytes(key: str) -> bytes:
    try:
        raw = base64.urlsafe_b64decode(key.encode("ascii"))
    except Exception as e:
        raise SealError(f"bad key encoding: {e}")
    if len(raw) != KEY_BYTES:
        raise SealError("key must decode to 32 bytes")
    return raw


def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    out = b""
    counter = 0
    while len(out) < length:
        out += hmac.new(key, nonce + counter.to_bytes(8, "big"), hashlib.sha256).digest()
        counter += 1
    return out[:length]


def seal(key: str, state: Dict[str, Any]) -> str:
    """Encrypt state dict -> token string."""
    kb = _key_bytes(key)
    if not isinstance(state, dict):
        raise SealError("state must be dict")
    plaintext = json.dumps(state, sort_keys=True, separators=(",", ":")).encode("utf-8")
    nonce = os.urandom(NONCE_BYTES)
    ct = bytes(a ^ b for a, b in zip(plaintext, _keystream(kb, nonce, len(plaintext))))
    tag = hmac.new(kb, nonce + ct, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(nonce + tag + ct).decode("ascii")


def unseal(key: str, token: str) -> Dict[str, Any]:
    """Decrypt token -> state dict. Fail-closed on any tampering."""
    kb = _key_bytes(key)
    try:
        blob = base64.urlsafe_b64decode(token.encode("ascii"))
    except Exception as e:
        raise SealError(f"bad token encoding: {e}")
    if len(blob) < NONCE_BYTES + 32:
        raise SealError("token too short")
    nonce, tag, ct = blob[:NONCE_BYTES], blob[NONCE_BYTES:NONCE_BYTES + 32], blob[NONCE_BYTES + 32:]
    if not hmac.compare_digest(tag, hmac.new(kb, nonce + ct, hashlib.sha256).digest()):
        raise SealError("tag mismatch (tampered or wrong key)")
    pt = bytes(a ^ b for a, b in zip(ct, _keystream(kb, nonce, len(ct))))
    try:
        state = json.loads(pt.decode("utf-8"))
    except ValueError as e:
        raise SealError(f"bad JSON inside token: {e}")
    if not isinstance(state, dict):
        raise SealError("state must be dict")
    return state


def stdlib_only() -> bool:
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "base64", "hashlib", "hmac", "json", "os", "pathlib", "typing"}
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
    key = generate_key()
    state = {"seq": 7, "secret": "sauce"}
    tok = seal(key, state)
    assert unseal(key, tok) == state
    # Tamper -> fail-closed
    raw = bytearray(base64.urlsafe_b64decode(tok.encode()))
    raw[-1] ^= 1
    bad = base64.urlsafe_b64encode(bytes(raw)).decode()
    try:
        unseal(key, bad)
        raise AssertionError("should raise")
    except SealError:
        pass
    # Wrong key
    try:
        unseal(generate_key(), tok)
        raise AssertionError("should raise")
    except SealError:
        pass
    assert stdlib_only()
    print("state_mgmt_05 OK: seal/unseal, tamper detection, fail-closed")


if __name__ == "__main__":
    main()
