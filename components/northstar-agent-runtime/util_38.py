"""Tempfile helpers: auto-cleanup temp dir, temp file paths, stale cleanup. What this IS: scratch-space plumbing. What this IS NOT: not secure storage."""

from __future__ import annotations

import ast
import contextlib
import os
import shutil
import tempfile
import time
from pathlib import Path

#: Module version.
UTIL_38_VERSION = "util-38.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.util-38.v1"


@contextlib.contextmanager
def temp_dir(prefix="util-"):
    d = Path(tempfile.mkdtemp(prefix=prefix))
    try:
        yield d
    finally:
        shutil.rmtree(d, ignore_errors=True)


def temp_file_path(suffix="", prefix="util-", dir=None) -> Path:
    fd, p = tempfile.mkstemp(suffix=suffix, prefix=prefix, dir=dir)
    os.close(fd)
    return Path(p)


def cleanup_old(dir_path, max_age_seconds) -> int:
    """Remove entries older than max_age_seconds. Returns count removed."""
    now = time.time()
    removed = 0
    for child in Path(dir_path).iterdir():
        if now - child.stat().st_mtime > max_age_seconds:
            if child.is_dir():
                shutil.rmtree(child, ignore_errors=True)
            else:
                child.unlink(missing_ok=True)
            removed += 1
    return removed


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = ['__future__', 'ast', 'contextlib', 'os', 'pathlib', 'shutil', 'tempfile', 'time']
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
    with temp_dir() as d:
        assert d.is_dir()
        p = temp_file_path(dir=str(d))
        assert p.is_file()
    assert not d.exists()
    print("tempfile helpers OK")


if __name__ == "__main__":
    main()
