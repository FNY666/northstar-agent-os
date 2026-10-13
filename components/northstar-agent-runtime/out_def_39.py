"""EXIF data stripping defense (D-OUT-039), Simulated.

Detects/cleans:
- JPEG APPn segments (0xFFE0-0xFFEF) whose payload starts with b'Exif\\x00\\x00'
  -- EXIF blocks routinely smuggle GPS coordinates, device serials, and
  timestamps out with shared images.
- strip_exif(): walks the segment structure and drops EXIF APPn segments,
  returning (cleaned_bytes, removed_count).
- Fail-closed: truncated or malformed input returns (original, 0) without raising.

What this IS:
* A gate-layer byte-walker that strips EXIF APPn segments from JPEG-like data.

What this IS NOT:
* Not a real image parser -- no pixel decode, no TIFF/IFD tag parsing.
* Not a format validator -- non-JPEG input passes through untouched.
"""

from __future__ import annotations

import ast
from typing import Tuple

#: Module version.
OUT_DEF_39_VERSION = "out-def-39.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.out-def-39.v1"

#: EXIF APPn payload signature.
EXIF_SIG = b"Exif\x00\x00"

_SOI = b"\xff\xd8"


def strip_exif(data: bytes) -> Tuple[bytes, int]:
    """Return (cleaned, removed_count).

    Walks JPEG-like segments: SOI (0xFFD8), then 0xFF marker bytes with
    2-byte big-endian lengths for APPn (0xE0-0xEF) and friends. Any APPn
    segment whose payload starts with b'Exif\\x00\\x00' is dropped.
    Truncated/malformed input is fail-closed: (original, 0), never raises.
    """
    original = bytes(data or b"")
    if len(original) < 2 or original[:2] != _SOI:
        return original, 0  # not JPEG-like: nothing to strip
    out = bytearray(original[:2])
    pos = 2
    removed = 0
    n = len(original)
    while pos < n:
        if original[pos] != 0xFF:
            return original, 0  # fail-closed: malformed
        # Skip fill bytes; the next non-0xFF byte is the marker.
        j = pos
        while j < n and original[j] == 0xFF:
            j += 1
        if j >= n:
            return original, 0  # fail-closed: truncated
        marker = original[j]
        header = original[pos : j + 1]  # fill bytes + marker
        pos = j + 1
        if marker == 0xD9:  # EOI
            out += header
            break
        if marker == 0xDA:  # SOS: remainder is scan data, copy verbatim
            out += original[pos - len(header) :]
            break
        if marker == 0x01 or 0xD0 <= marker <= 0xD7:
            # TEM / RSTn: no length field.
            out += header
            continue
        # Length-prefixed segment (length includes its own 2 bytes).
        if pos + 2 > n:
            return original, 0  # fail-closed: truncated
        length = int.from_bytes(original[pos : pos + 2], "big")
        if length < 2 or pos + length > n:
            return original, 0  # fail-closed: malformed/truncated
        payload = original[pos + 2 : pos + length]
        if 0xE0 <= marker <= 0xEF and payload.startswith(EXIF_SIG):
            removed += 1  # drop EXIF APPn
        else:
            out += header + original[pos : pos + length]
        pos += length
    return bytes(out), removed


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


def _segment(marker: int, payload: bytes) -> bytes:
    length = len(payload) + 2
    return bytes([0xFF, marker]) + length.to_bytes(2, "big") + payload


def main() -> None:
    """Self-check."""
    exif_app1 = _segment(0xE1, EXIF_SIG + b"II*\x00fake-ifd")
    jfif_app0 = _segment(0xE0, b"JFIF\x00" + b"\x01\x02")
    fake_jpeg = (
        _SOI
        + exif_app1
        + jfif_app0
        + bytes([0xFF, 0xDA])  # SOS
        + b"\x00\x3f\x00"  # scan data
        + bytes([0xFF, 0xD9])  # EOI
    )
    cleaned, removed = strip_exif(fake_jpeg)
    assert removed == 1
    assert EXIF_SIG not in cleaned
    assert b"JFIF" in cleaned  # non-EXIF APPn preserved
    assert cleaned[:2] == _SOI and cleaned.endswith(b"\xff\xd9")

    # No EXIF present: untouched, zero removed.
    plain = _SOI + jfif_app0 + bytes([0xFF, 0xD9])
    cleaned, removed = strip_exif(plain)
    assert removed == 0 and cleaned == plain

    # Truncated segment: fail-closed, original returned, no raise.
    truncated = _SOI + bytes([0xFF, 0xE1, 0x00])  # length field cut off
    cleaned, removed = strip_exif(truncated)
    assert removed == 0 and cleaned == truncated

    # Bad length: fail-closed.
    bad_len = _SOI + bytes([0xFF, 0xE1, 0x00, 0x01]) + b"\xff\xd9"
    cleaned, removed = strip_exif(bad_len)
    assert removed == 0 and cleaned == bad_len

    # Non-JPEG input passes through untouched.
    cleaned, removed = strip_exif(b"hello world")
    assert removed == 0 and cleaned == b"hello world"

    # Empty input: fail-closed without raising.
    cleaned, removed = strip_exif(b"")
    assert removed == 0 and cleaned == b""

    assert stdlib_only()
    print("out-def-39 OK: exif strip, fail-closed, stdlib")


if __name__ == "__main__":
    main()
