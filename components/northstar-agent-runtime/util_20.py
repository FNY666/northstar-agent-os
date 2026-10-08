"""Test helpers: mock clock, stdout capture, assert-raises, temp cwd. What this IS: small testing utilities. What this IS NOT: not a test framework."""

from __future__ import annotations

import ast
import contextlib
import io
import os
import sys
from pathlib import Path

#: Module version.
UTIL_20_VERSION = "util-20.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.util-20.v1"


class MockClock:
    """Controllable clock for tests."""

    def __init__(self, start=0.0):
        self._t = float(start)

    def now(self) -> float:
        return self._t

    def advance(self, seconds: float):
        self._t += seconds

    def sleep(self, seconds: float):
        self.advance(seconds)


@contextlib.contextmanager
def capture_stdout():
    buf = io.StringIO()
    old = sys.stdout
    sys.stdout = buf
    try:
        yield buf
    finally:
        sys.stdout = old


def assert_raises_msg(exc_type, fn, substr):
    """Assert fn() raises exc_type with substr in the message."""
    try:
        fn()
    except exc_type as e:
        assert substr in str(e), f"{substr!r} not in {e}"
        return e
    raise AssertionError(f"{exc_type.__name__} not raised")


@contextlib.contextmanager
def temp_cwd(path):
    old = os.getcwd()
    os.chdir(path)
    try:
        yield Path(path)
    finally:
        os.chdir(old)


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = ['__future__', 'ast', 'contextlib', 'io', 'os', 'pathlib', 'sys']
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
    c = MockClock(start=10.0)
    c.sleep(5)
    assert c.now() == 15.0
    with capture_stdout() as buf:
        print("hi")
    assert buf.getvalue() == "hi\n"
    e = assert_raises_msg(ValueError, lambda: int("x"), "invalid literal")
    assert isinstance(e, ValueError)
    print("test helpers OK")


if __name__ == "__main__":
    main()
