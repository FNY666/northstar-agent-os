"""Archive metadata scrubber: ZIP EOCD comments and extra fields, Simulated.

Cleans:
- End-of-central-directory comment (zeroed, length field set to 0)
- Local file header extra fields (zeroed in place, length field set to 0)

What this IS:
* Gate-layer scrubbing of archive-identifying metadata regions.

What this IS NOT:
* Not an archive parser -- signature-based scan, no central-directory walk.
* Not filename scrubbing -- entry names are preserved.
"""

from __future__ import annotations

import ast

#: Module version.
OUT_DEF_45_VERSION = "out-def-45.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.out-def-45.v1"


class OutDef45Error(Exception):
    """Fail-closed."""


_EOCD_SIG = b"PK\x05\x06"
_EOCD_LEN = 22
_LOCAL_SIG = b"PK\x03\x04"
_LOCAL_FIXED_LEN = 30
_MAX_COMMENT = 65535


def clean_archive_metadata(data: bytes) -> tuple[bytes, int]:
    """Zero ZIP EOCD comment and local-header extra fields.

    Returns (cleaned_bytes, fields_zeroed_count). Never raises: malformed
    input returns (original_bytes, 0) fail-closed.
    """
    try:
        out = bytearray(data)
        n = len(out)
        zeroed = 0

        # End-of-central-directory: 22-byte record, comment length in last 2 bytes.
        eocd_at = out.rfind(_EOCD_SIG, max(0, n - (_EOCD_LEN + _MAX_COMMENT)))
        if eocd_at != -1 and eocd_at + _EOCD_LEN <= n:
            comment_len = int.from_bytes(
                out[eocd_at + 20 : eocd_at + 22], "little"
            )
            comment_end = eocd_at + _EOCD_LEN + comment_len
            if 0 < comment_len and comment_end <= n:
                for i in range(eocd_at + _EOCD_LEN, comment_end):
                    out[i] = 0
                out[eocd_at + 20 : eocd_at + 22] = b"\x00\x00"
                zeroed += 1

        # Local file headers: 30-byte fixed part, then filename, then extra field.
        pos = 0
        while True:
            idx = out.find(_LOCAL_SIG, pos)
            if idx == -1 or idx + _LOCAL_FIXED_LEN > n:
                break
            fn_len = int.from_bytes(out[idx + 26 : idx + 28], "little")
            extra_len = int.from_bytes(out[idx + 28 : idx + 30], "little")
            extra_start = idx + _LOCAL_FIXED_LEN + fn_len
            extra_end = extra_start + extra_len
            if extra_len > 0 and extra_end <= n:
                for i in range(extra_start, extra_end):
                    out[i] = 0
                out[idx + 28 : idx + 30] = b"\x00\x00"
                zeroed += 1
            pos = idx + 4
        return bytes(out), zeroed
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


def _local_header(filename: bytes, extra: bytes) -> bytes:
    fixed = _LOCAL_SIG + b"\x00" * 22
    fixed += len(filename).to_bytes(2, "little") + len(extra).to_bytes(2, "little")
    return fixed + filename + extra


def main() -> None:
    """Self-check."""
    local = _local_header(b"name", b"ABCDEF") + b"filedata"
    eocd = _EOCD_SIG + b"\x00" * 16 + (5).to_bytes(2, "little") + b"hello"
    data = local + eocd
    cleaned, zeroed = clean_archive_metadata(data)
    assert zeroed == 2, zeroed
    assert len(cleaned) == len(data)
    assert b"ABCDEF" not in cleaned
    assert b"hello" not in cleaned
    assert b"name" in cleaned
    assert b"filedata" in cleaned

    # Clean input unchanged.
    out, zeroed = clean_archive_metadata(b"not a zip")
    assert out == b"not a zip" and zeroed == 0

    # Malformed: no raise.
    for bad in (b"", _EOCD_SIG, _LOCAL_SIG, _EOCD_SIG + b"\x00" * 10):
        out, zeroed = clean_archive_metadata(bad)
        assert isinstance(out, bytes) and isinstance(zeroed, int)

    assert stdlib_only()
    print("out-def-45 OK: archive metadata, malformed-safe, stdlib")


if __name__ == "__main__":
    main()
