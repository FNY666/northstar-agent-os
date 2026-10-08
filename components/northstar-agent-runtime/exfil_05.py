"""Steganography detection (mock) (stego-mock), Simulated.

Mock detector for appended-data steganography: finds bytes hidden after JPEG EOI or PNG IEND markers.

What this IS: a mock appended-data stego detector (format markers only).

What this IS NOT:
* MOCK: does not do LSB/statistical steganalysis.
* Only checks trailing data after end markers.
"""

from __future__ import annotations

import ast
from typing import Any, Dict, List


#: Module version.
EXFIL_05_VERSION = "exfil-05.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.exfil-05.v1"


class Exfil05Error(Exception):
    """Fail-closed."""


_JPEG_EOI = b"\xff\xd9"
_PNG_IEND = b"\x49\x45\x4E\x44\xAE\x42\x60\x82"


def detect_stego_appended(data: bytes, fmt: str) -> tuple:
    """Detect data appended after image end markers. Returns (suspicious, reason)."""
    if not isinstance(data, (bytes, bytearray)):
        raise Exfil05Error("data must be bytes")
    data = bytes(data)
    if fmt == "jpeg":
        pos = data.rfind(_JPEG_EOI)
        if pos != -1:
            trailing = len(data) - (pos + 2)
            if trailing > 0:
                return True, "%d bytes after JPEG EOI" % trailing
    elif fmt == "png":
        pos = data.rfind(_PNG_IEND)
        if pos != -1:
            trailing = len(data) - (pos + 8)
            if trailing > 0:
                return True, "%d bytes after PNG IEND" % trailing
    else:
        raise Exfil05Error("unsupported fmt: %s" % fmt)
    return False, "ok"

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "typing"}
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
    ok, _ = detect_stego_appended(b"\xff\xd8\xff\xd9", "jpeg")
    assert ok is False
    ok, _ = detect_stego_appended(b"\xff\xd8\xff\xd9" + b"SECRET" * 10, "jpeg")
    assert ok is True
    assert stdlib_only()
    print("exfil-05 OK: mock stego, fail-closed")


if __name__ == "__main__":
    main()
