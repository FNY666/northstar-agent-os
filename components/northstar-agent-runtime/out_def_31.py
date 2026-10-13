"""Output watermark verification, Simulated.

Embeds and verifies a keyed integrity watermark on output text so the
runtime can detect tampering, truncation, or substitution of its own
outputs before they leave the gate.

What this IS:
* A keyed sha256 token appended as ``[wm:<16 hex chars>]``; verification
  extracts the token and recomputes it over the text without the token.
* Deterministic, stdlib-only (hashlib), fail-closed on mismatch.

What this IS NOT:
* Not invisible steganography -- the token is visible in the text.
* Not an asymmetric signature -- no non-repudiation; key secrecy is
  enforced by the host, not this module.
* Simulated: no real key management or secure storage.
"""

from __future__ import annotations

import ast
import hashlib
import re

#: Module version.
OUT_DEF_31_VERSION = "out-def-31.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.out-def-31.v1"

_WM_TRAILING_RE = re.compile(r"\[wm:([0-9a-f]{16})\]\s*$")
_WM_ANY_RE = re.compile(r"\[wm:[0-9a-f]{16}\]")


class OutDef31Error(Exception):
    """Fail-closed."""


def _key_bytes(key: str | bytes) -> bytes:
    if isinstance(key, str):
        return key.encode("utf-8")
    return bytes(key)


def _token_for(text: str, key: str | bytes) -> str:
    kb = _key_bytes(key)
    if not kb:
        raise OutDef31Error("empty watermark key")
    return hashlib.sha256(kb + b"|" + text.encode("utf-8")).hexdigest()[:16]


def embed_watermark(text: str, key: str | bytes) -> str:
    """Append a ``[wm:<hex>]`` watermark token to *text*."""
    return f"{text} [wm:{_token_for(text, key)}]"


def has_watermark(text: str) -> bool:
    """Return True if *text* contains a watermark token anywhere."""
    return _WM_ANY_RE.search(text) is not None


def verify_watermark(text_with_token: str, key: str | bytes) -> tuple[bool, str]:
    """Verify the trailing watermark token. Returns (ok, reason).

    ok=False means the token is missing, the text was altered, or the
    key does not match.
    """
    m = _WM_TRAILING_RE.search(text_with_token)
    if not m:
        return False, "no watermark token found"
    body = text_with_token[: m.start()]
    if body.endswith(" "):
        # Strip the single separator space added by embed_watermark.
        body = body[:-1]
    try:
        expected = _token_for(body, key)
    except OutDef31Error as exc:
        return False, str(exc)
    if m.group(1) != expected:
        return False, "watermark mismatch -- text or key altered"
    return True, "watermark ok"


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "hashlib", "re", "pathlib"}
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
    key = "test-key"
    text = "model output here"
    marked = embed_watermark(text, key)
    assert has_watermark(marked) is True

    # Round-trip.
    ok, _ = verify_watermark(marked, key)
    assert ok is True

    # Tampered body.
    ok, reason = verify_watermark(marked.replace("output", "OUTPUT"), key)
    assert ok is False
    assert "mismatch" in reason

    # Wrong key.
    ok, _ = verify_watermark(marked, "other-key")
    assert ok is False

    # Token moved away from the end (appended text after it).
    ok, reason = verify_watermark(marked + " extra", key)
    assert ok is False
    assert "no watermark token" in reason

    # No token at all.
    ok, _ = verify_watermark("plain text", key)
    assert ok is False
    assert has_watermark("plain text") is False

    # Empty key fails closed.
    try:
        embed_watermark(text, "")
    except OutDef31Error:
        pass
    else:
        raise AssertionError("empty key should fail closed")

    assert stdlib_only()
    print("out-def-31 OK: embed, verify, tamper detection, stdlib")


if __name__ == "__main__":
    main()
