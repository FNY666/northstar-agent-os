"""Image metadata scrubber: PNG text chunks and JPEG COM segments, Simulated.

Cleans:
- PNG: tEXt / iTXt / zTXt / eXIf ancillary chunks
- JPEG: COM (comment) segments

What this IS:
* Gate-layer scrubbing of image-identifying metadata chunks/segments.

What this IS NOT:
* Not an image decoder -- chunk/segment walk only, pixels untouched.
* Not EXIF-in-APP1 parsing -- only the listed chunk/segment types are dropped.
"""

from __future__ import annotations

import ast

#: Module version.
OUT_DEF_42_VERSION = "out-def-42.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.out-def-42.v1"


class OutDef42Error(Exception):
    """Fail-closed."""


_PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
_JPEG_MAGIC = b"\xFF\xD8"

#: PNG ancillary chunk types dropped.
_PNG_DROP = {b"tEXt", b"iTXt", b"zTXt", b"eXIf"}

_JPEG_COM = 0xFE
_JPEG_SOS = 0xDA
_JPEG_EOI = 0xD9
#: JPEG markers with no length field: SOI, EOI, TEM, RST0-RST7.
_JPEG_STANDALONE = {0xD8, 0xD9, 0x01} | set(range(0xD0, 0xD8))


def _clean_png(data: bytes) -> tuple[bytes, int]:
    """Walk PNG chunks (len + type + payload + CRC), dropping metadata chunks."""
    if len(data) < 8:
        return data, 0
    out = bytearray(data[:8])
    removed = 0
    pos = 8
    n = len(data)
    while pos + 8 <= n:
        length = int.from_bytes(data[pos : pos + 4], "big")
        ctype = data[pos + 4 : pos + 8]
        if length > n - pos - 12:
            return data, 0  # malformed: chunk overruns buffer
        total = 12 + length
        if ctype in _PNG_DROP:
            removed += 1
        else:
            out += data[pos : pos + total]
        pos += total
        if ctype == b"IEND":
            out += data[pos:]
            pos = n
            break
    out += data[pos:]
    return bytes(out), removed


def _clean_jpeg(data: bytes) -> tuple[bytes, int]:
    """Walk JPEG segments, dropping COM segments. Scan data passes through."""
    out = bytearray(data[:2])
    removed = 0
    pos = 2
    n = len(data)
    while pos < n:
        if data[pos] != 0xFF:
            return data, 0  # malformed: expected marker
        m = pos + 1
        while m < n and data[m] == 0xFF:
            m += 1
        if m >= n:
            return data, 0  # malformed: truncated marker
        marker = data[m]
        seg_start = pos
        if marker in _JPEG_STANDALONE:
            out += data[seg_start : m + 1]
            pos = m + 1
            if marker == _JPEG_EOI:
                out += data[pos:]
                pos = n
            continue
        if m + 3 > n:
            return data, 0  # malformed: truncated length
        seg_len = int.from_bytes(data[m + 1 : m + 3], "big")
        if seg_len < 2 or m + 1 + seg_len > n:
            return data, 0  # malformed: bad length
        seg_end = m + 1 + seg_len
        if marker == _JPEG_SOS:
            out += data[seg_start:seg_end]
            out += data[seg_end:]  # compressed scan data passes through verbatim
            pos = n
            continue
        if marker == _JPEG_COM:
            removed += 1
        else:
            out += data[seg_start:seg_end]
        pos = seg_end
    return bytes(out), removed


def clean_image_metadata(data: bytes) -> tuple[bytes, int]:
    """Remove image metadata chunks/segments. Returns (cleaned, removed_count).

    Unknown formats and malformed input return (original_bytes, 0) fail-closed.
    """
    try:
        if data[:8] == _PNG_MAGIC:
            return _clean_png(data)
        if data[:2] == _JPEG_MAGIC:
            return _clean_jpeg(data)
        return data, 0
    except Exception:
        return data, 0


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def _chunk(ctype: bytes, payload: bytes) -> bytes:
    return len(payload).to_bytes(4, "big") + ctype + payload + b"\x00" * 4


def _seg(marker: int, payload: bytes) -> bytes:
    return b"\xFF" + bytes([marker]) + (2 + len(payload)).to_bytes(2, "big") + payload


def main() -> None:
    """Self-check."""
    # PNG with metadata chunks.
    png = (
        b"\x89PNG\r\n\x1a\n"
        + _chunk(b"IHDR", b"\x00" * 13)
        + _chunk(b"tEXt", b"Title\x00hello")
        + _chunk(b"IEND", b"")
    )
    cleaned, removed = clean_image_metadata(png)
    assert removed == 1
    assert b"tEXt" not in cleaned
    assert b"IEND" in cleaned

    # JPEG with COM segment.
    jpeg = b"\xFF\xD8" + _seg(0xE0, b"JFIF\x00") + _seg(0xFE, b"note") + b"\xFF\xD9"
    cleaned, removed = clean_image_metadata(jpeg)
    assert removed == 1
    assert b"note" not in cleaned
    assert cleaned.endswith(b"\xFF\xD9")

    # Unknown format unchanged.
    out, removed = clean_image_metadata(b"hello")
    assert out == b"hello" and removed == 0

    # Malformed: no raise, original returned.
    bad = b"\x89PNG\r\n\x1a\n" + (1000).to_bytes(4, "big") + b"tEXt" + b"short"
    out, removed = clean_image_metadata(bad)
    assert out == bad and removed == 0
    out, removed = clean_image_metadata(b"\xFF\xD8\x00")
    assert out == b"\xFF\xD8\x00" and removed == 0

    assert stdlib_only()
    print("out-def-42 OK: image metadata, malformed-safe, stdlib")


if __name__ == "__main__":
    main()
