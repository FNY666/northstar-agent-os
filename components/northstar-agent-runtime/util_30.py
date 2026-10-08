"""Compression helpers: zlib and gzip round-trips, ratio. What this IS: payload shrinking. What this IS NOT: not encryption."""

from __future__ import annotations

import ast
import gzip
import zlib

#: Module version.
UTIL_30_VERSION = "util-30.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.util-30.v1"


class CompressionError(Exception):
    """Compression helper failure."""


def zlib_compress(data: bytes, level=6) -> bytes:
    return zlib.compress(data, level)


def zlib_decompress(data: bytes) -> bytes:
    try:
        return zlib.decompress(data)
    except zlib.error as e:
        raise CompressionError(f"bad zlib data: {e}") from e


def gzip_bytes(data: bytes) -> bytes:
    return gzip.compress(data)


def gunzip_bytes(data: bytes) -> bytes:
    try:
        return gzip.decompress(data)
    except (OSError, EOFError) as e:
        raise CompressionError(f"bad gzip data: {e}") from e


def compression_ratio(original: bytes, compressed: bytes) -> float:
    if not original:
        return 0.0
    return len(compressed) / len(original)


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = ['__future__', 'ast', 'gzip', 'pathlib', 'zlib']
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
    data = b"hello world " * 100
    assert zlib_decompress(zlib_compress(data)) == data
    assert gunzip_bytes(gzip_bytes(data)) == data
    assert compression_ratio(data, zlib_compress(data)) < 1.0
    try:
        zlib_decompress(b"junk")
        raise AssertionError("should raise")
    except CompressionError:
        pass
    print("compression helpers OK")


if __name__ == "__main__":
    main()
