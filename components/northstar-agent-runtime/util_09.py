"""File helpers: size-capped read, atomic write, line read. What this IS: safe small-file IO. What this IS NOT: not a VFS."""

from __future__ import annotations

import ast
import os
import tempfile
from pathlib import Path

#: Module version.
UTIL_09_VERSION = "util-09.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.util-09.v1"


class FileError(Exception):
    """File helper failure."""


def safe_read(path, max_bytes=10 * 1024 * 1024, encoding="utf-8") -> str:
    p = Path(path)
    try:
        if p.stat().st_size > max_bytes:
            raise FileError(f"file too large: {p}")
        return p.read_text(encoding=encoding)
    except OSError as e:
        raise FileError(f"cannot read {p}: {e}") from e


def atomic_write(path, data: str, encoding="utf-8"):
    """Write via temp file + os.replace (crash-safe)."""
    p = Path(path)
    ensure_parent(p)
    fd, tmp = tempfile.mkstemp(dir=str(p.parent), prefix=".tmp-")
    try:
        with os.fdopen(fd, "w", encoding=encoding) as f:
            f.write(data)
        os.replace(tmp, p)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def read_lines(path, encoding="utf-8"):
    return safe_read(path, encoding=encoding).splitlines()


def ensure_parent(path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = ['__future__', 'ast', 'os', 'pathlib', 'tempfile']
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
    import tempfile
    d = tempfile.mkdtemp()
    p = f"{d}/sub/f.txt"
    atomic_write(p, "hello\nworld\n")
    assert read_lines(p) == ["hello", "world"]
    assert safe_read(p) == "hello\nworld\n"
    try:
        safe_read(p, max_bytes=2)
        raise AssertionError("should raise")
    except FileError:
        pass
    print("file helpers OK")


if __name__ == "__main__":
    main()
