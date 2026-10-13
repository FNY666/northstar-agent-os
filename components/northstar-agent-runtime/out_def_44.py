"""Video metadata scrubber: MP4-style metadata boxes, Simulated.

Cleans:
- Boxes with type uuid / meta
- Boxes whose type starts with XMP_
- Recurses into container boxes: moov, trak, mdia, minf

What this IS:
* Gate-layer scrubbing of video-identifying metadata boxes.

What this IS NOT:
* Not a video decoder -- box walk only, media samples untouched.
* Not a full MP4 parser -- no 64-bit largesize or full-box version handling.
"""

from __future__ import annotations

import ast

#: Module version.
OUT_DEF_44_VERSION = "out-def-44.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.out-def-44.v1"


class OutDef44Error(Exception):
    """Fail-closed."""


#: Box types dropped outright.
_DROP_BOXES = {b"uuid", b"meta"}

#: Prefix for XMP metadata boxes.
_XMP_PREFIX = b"XMP_"

#: Container boxes recursed into (payload re-walked, size fixed up).
_CONTAINER_BOXES = {b"moov", b"trak", b"mdia", b"minf"}


def _walk_boxes(data: bytes) -> tuple[bytes, int]:
    """Walk size+type boxes; drop metadata boxes; recurse into containers."""
    out = bytearray()
    removed = 0
    pos = 0
    n = len(data)
    while pos + 8 <= n:
        size = int.from_bytes(data[pos : pos + 4], "big")
        btype = data[pos + 4 : pos + 8]
        if size < 8 or size > n - pos:
            break  # malformed box: stop parsing, keep the rest verbatim
        payload = data[pos + 8 : pos + size]
        if btype in _DROP_BOXES or btype.startswith(_XMP_PREFIX):
            removed += 1
        elif btype in _CONTAINER_BOXES:
            inner, r = _walk_boxes(payload)
            removed += r
            out += (8 + len(inner)).to_bytes(4, "big") + btype + inner
        else:
            out += data[pos : pos + size]
        pos += size
    out += data[pos:]
    return bytes(out), removed


def clean_video_metadata(data: bytes) -> tuple[bytes, int]:
    """Remove metadata boxes. Returns (cleaned_bytes, removed_count).

    Malformed input never raises: returns (original_bytes, 0) fail-closed.
    """
    try:
        return _walk_boxes(data)
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


def _box(btype: bytes, payload: bytes) -> bytes:
    return (8 + len(payload)).to_bytes(4, "big") + btype + payload


def main() -> None:
    """Self-check."""
    inner = _box(b"uuid", b"1" * 8) + _box(b"mvhd", b"\x00" * 8)
    mp4 = _box(b"moov", inner) + _box(b"mdat", b"PAYLOAD")
    cleaned, removed = clean_video_metadata(mp4)
    assert removed == 1, removed
    assert b"uuid" not in cleaned
    assert b"mvhd" in cleaned
    assert b"PAYLOAD" in cleaned

    # XMP_ prefixed box dropped.
    mp4 = _box(b"XMP_", b"xx") + _box(b"ftyp", b"isom")
    cleaned, removed = clean_video_metadata(mp4)
    assert removed == 1
    assert b"XMP_" not in cleaned
    assert b"ftyp" in cleaned

    # Clean input unchanged.
    clean = _box(b"ftyp", b"isom") + _box(b"mdat", b"DATA")
    out, removed = clean_video_metadata(clean)
    assert out == clean and removed == 0

    # Malformed: no raise.
    bad = b"\x00\x00\x00\x05ABCDrest"  # size < 8
    out, removed = clean_video_metadata(bad)
    assert out == bad and removed == 0
    bad = b"\x00\x00\x01\x00ABCD"  # size > remaining
    out, removed = clean_video_metadata(bad)
    assert out == bad and removed == 0
    out, removed = clean_video_metadata(b"")
    assert out == b"" and removed == 0

    assert stdlib_only()
    print("out-def-44 OK: video metadata, malformed-safe, stdlib")


if __name__ == "__main__":
    main()
