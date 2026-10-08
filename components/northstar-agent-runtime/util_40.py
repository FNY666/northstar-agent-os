"""ID helpers: thread-safe counter, short base36 IDs, prefixed IDs. What this IS: cheap local unique IDs. What this IS NOT: not globally unique (see util_32)."""

from __future__ import annotations

import ast
import itertools
import threading
import time

#: Module version.
UTIL_40_VERSION = "util-40.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.util-40.v1"


_counter = itertools.count(1)
_lock = threading.Lock()
_ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyz"


class IdError(Exception):
    """ID helper failure."""


def reset_counter():
    global _counter
    with _lock:
        _counter = itertools.count(1)


def unique_int() -> int:
    with _lock:
        return next(_counter)


def short_id(n=8) -> str:
    """Base36 ID from the counter, padded/trimmed to n chars."""
    if n <= 0:
        raise IdError("n must be positive")
    num = unique_int()
    chars = []
    while num > 0:
        num, rem = divmod(num, 36)
        chars.append(_ALPHABET[rem])
    s = "".join(reversed(chars)) or "0"
    return s.rjust(n, "0")[-n:]


def prefixed_id(prefix: str) -> str:
    return f"{prefix}-{short_id(6)}-{int(time.time())}"


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = ['__future__', 'ast', 'itertools', 'pathlib', 'threading', 'time']
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
    reset_counter()
    assert unique_int() == 1
    assert unique_int() == 2
    sid = short_id(8)
    assert len(sid) == 8
    pid = prefixed_id("run")
    assert pid.startswith("run-")
    print("id helpers OK")


if __name__ == "__main__":
    main()
