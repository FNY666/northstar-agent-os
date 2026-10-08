"""Checksum helpers: CRC32, Adler-32. What this IS: fast integrity checks. What this IS NOT: not cryptographic (see util_01)."""

from __future__ import annotations

import ast
import zlib

#: Module version.
UTIL_31_VERSION = "util-31.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.util-31.v1"


def crc32_hex(data: bytes) -> str:
    return f"{zlib.crc32(data) & 0xFFFFFFFF:08x}"


def adler32_hex(data: bytes) -> str:
    return f"{zlib.adler32(data) & 0xFFFFFFFF:08x}"


def verify_crc32(data: bytes, expected_hex: str) -> bool:
    return crc32_hex(data) == expected_hex.lower()


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = ['__future__', 'ast', 'pathlib', 'zlib']
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
    assert crc32_hex(b"123456789") == "cbf43926"
    assert adler32_hex(b"123456789") == "091e01de"
    assert verify_crc32(b"abc", crc32_hex(b"abc")) is True
    assert verify_crc32(b"abc", "00000000") is False
    print("checksum helpers OK")


if __name__ == "__main__":
    main()
