"""Audio metadata scrubber: ID3v2 headers and ID3v1 trailers, Simulated.

Cleans:
- ID3v2 tag header (10-byte header + syncsafe-sized body) at stream start
- ID3v1 128-byte trailer (b'TAG' + 125 bytes) at stream end

What this IS:
* Gate-layer scrubbing of audio-identifying tag metadata.

What this IS NOT:
* Not an audio decoder -- tag regions only, audio frames untouched.
* Not a full ID3 parser -- no frame-level or APIC handling.
"""

from __future__ import annotations

import ast

#: Module version.
OUT_DEF_43_VERSION = "out-def-43.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.out-def-43.v1"


class OutDef43Error(Exception):
    """Fail-closed."""


_ID3V2_MAGIC = b"ID3"
_ID3V2_HEADER_LEN = 10
_ID3V1_MAGIC = b"TAG"
_ID3V1_LEN = 128


def clean_audio_metadata(data: bytes) -> tuple[bytes, int]:
    """Strip ID3v2 header and/or ID3v1 trailer. Returns (cleaned, removed_count).

    removed_count is 0-2. Short or malformed input returns (original, 0)
    fail-closed and never raises.
    """
    try:
        out = data
        removed = 0
        # ID3v2: 10-byte header, body size is 4 syncsafe bytes (7 bits each).
        if len(out) >= _ID3V2_HEADER_LEN and out[:3] == _ID3V2_MAGIC:
            size_bytes = out[6:10]
            if all(b < 0x80 for b in size_bytes):
                body = (
                    (size_bytes[0] << 21)
                    | (size_bytes[1] << 14)
                    | (size_bytes[2] << 7)
                    | size_bytes[3]
                )
                total = _ID3V2_HEADER_LEN + body
                if total <= len(out):
                    out = out[total:]
                    removed += 1
        # ID3v1: last 128 bytes start with b'TAG'.
        if len(out) >= _ID3V1_LEN and out[-_ID3V1_LEN : -_ID3V1_LEN + 3] == _ID3V1_MAGIC:
            out = out[:-_ID3V1_LEN]
            removed += 1
        return out, removed
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


def main() -> None:
    """Self-check."""
    v2 = b"ID3\x04\x00\x00" + bytes([0, 0, 0, 10]) + b"X" * 10
    v1 = b"TAG" + b"Y" * 125
    data = v2 + b"AUDIOBYTES" + v1
    cleaned, removed = clean_audio_metadata(data)
    assert removed == 2, removed
    assert cleaned == b"AUDIOBYTES"

    # v2 only.
    cleaned, removed = clean_audio_metadata(v2 + b"DATA")
    assert removed == 1 and cleaned == b"DATA"

    # v1 only.
    cleaned, removed = clean_audio_metadata(b"DATA" + v1)
    assert removed == 1 and cleaned == b"DATA"

    # Clean input unchanged.
    out, removed = clean_audio_metadata(b"RIFF....WAVE")
    assert out == b"RIFF....WAVE" and removed == 0

    # Malformed: no raise.
    for bad in (
        b"",
        b"ID3",
        b"ID3\x04\x00",
        b"ID3\x04\x00\x00\xff\x00\x00\x00rest",  # invalid syncsafe byte
        b"ID3\x04\x00\x00" + bytes([0, 0, 7, 0]),  # body longer than buffer
    ):
        out, removed = clean_audio_metadata(bad)
        assert out == bad and removed == 0, bad

    assert stdlib_only()
    print("out-def-43 OK: audio metadata, malformed-safe, stdlib")


if __name__ == "__main__":
    main()
