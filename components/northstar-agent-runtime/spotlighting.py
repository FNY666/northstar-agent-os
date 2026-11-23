"""Spotlighting: tool-result boundary marking (Microsoft Research), Simulated.

Delimits untrusted tool output so the model can distinguish data from
instructions.  Three techniques:
- delimiting: wrap in random unguessable delimiters
- datamarking: interleave nonce tokens in whitespace
- encoding: base64 for high-risk tools

Microsoft result: indirect injection ASR 50% -> <2%, ~0 utility loss.

What this IS: the tool-result -> context boundary defense.  ~30 LOC,
no extra LLM round-trip.

What this IS NOT:
* Not a content filter -- it marks provenance, doesn't judge content.
* The model must be instructed to respect the markings (prompt-level).
* Nonce must be unpredictable per-call; reuse weakens the defense.
"""

from __future__ import annotations

import ast
import base64
import secrets
from typing import Any

#: Module version.
SPOTLIGHTING_VERSION = "spotlighting.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.spotlighting.v1"


class SpotlightingError(Exception):
    """Fail-closed: bad inputs raise."""


def generate_nonce(nbytes: int = 8) -> str:
    """Generate an unguessable nonce for this call."""
    if nbytes < 8:
        raise SpotlightingError("nbytes must be >= 8")
    return secrets.token_hex(nbytes)


def delimit(data: str, nonce: str) -> str:
    """Wrap data in unguessable delimiters.

    Format: <untrusted_data nonce={nonce}> ... </untrusted_data>
    """
    if not isinstance(data, str):
        raise SpotlightingError("data must be str")
    if not nonce:
        raise SpotlightingError("nonce required")
    return f"<untrusted_data nonce={nonce}>\n{data}\n</untrusted_data>"


def datamark(data: str, nonce: str) -> str:
    """Interleave nonce tokens in whitespace (datamarking).

    Inserts the nonce token at whitespace boundaries, making it
    structurally difficult to splice instructions into the data
    without breaking the marking pattern.
    """
    if not isinstance(data, str):
        raise SpotlightingError("data must be str")
    if not nonce:
        raise SpotlightingError("nonce required")
    # Split on whitespace, rejoin with nonce markers.
    parts = data.split()
    if not parts:
        return data
    marked = f"[{nonce}]".join(parts)
    # Wrap as well for defense in depth.
    return delimit(marked, nonce)


def encode_b64(data: str, nonce: str) -> str:
    """Base64-encode high-risk tool output.

    For tools like web fetch and email where the content is fully
    untrusted.  The model must decode explicitly, creating a
    conscious boundary crossing.
    """
    if not isinstance(data, str):
        raise SpotlightingError("data must be str")
    if not nonce:
        raise SpotlightingError("nonce required")
    encoded = base64.b64encode(data.encode("utf-8")).decode("ascii")
    return (
        f"<untrusted_data nonce={nonce} encoding=base64>\n"
        f"{encoded}\n"
        f"</untrusted_data>"
    )


def spotlight(
    data: str,
    *,
    level: str = "delimit",
    nonce: str | None = None,
) -> tuple[str, str]:
    """Apply spotlighting at the requested level.

    Levels: "delimit" (default), "datamark", "base64".
    Returns (marked_data, nonce).  Nonce is generated if not provided.

    The nonce should be logged to the sealed ledger for audit.
    """
    if level not in ("delimit", "datamark", "base64"):
        raise SpotlightingError(f"unknown level {level!r}")
    if nonce is None:
        nonce = generate_nonce()
    if level == "delimit":
        return delimit(data, nonce), nonce
    elif level == "datamark":
        return datamark(data, nonce), nonce
    else:
        return encode_b64(data, nonce), nonce


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "base64", "pathlib", "secrets", "typing"}
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
    nonce = generate_nonce()
    assert len(nonce) == 16  # 8 bytes hex

    # Delimit.
    marked, n2 = spotlight("hello world", level="delimit")
    assert "<untrusted_data" in marked
    assert f"nonce={n2}" in marked
    assert "hello world" in marked

    # Datamark.
    marked, _ = spotlight("hello world", level="datamark")
    assert "[{}]".format(marked.split("[")[1].split("]")[0]) in marked

    # Base64.
    marked, _ = spotlight("secret", level="base64")
    assert "encoding=base64" in marked
    assert "secret" not in marked  # encoded, not plaintext

    # Fail-closed.
    try:
        spotlight("x", level="bogus")
        raise AssertionError("should raise")
    except SpotlightingError:
        pass
    try:
        delimit("x", "")
        raise AssertionError("should raise")
    except SpotlightingError:
        pass

    assert stdlib_only()
    print("spotlighting OK: delimit, datamark, base64, fail-closed, stdlib")


if __name__ == "__main__":
    main()
