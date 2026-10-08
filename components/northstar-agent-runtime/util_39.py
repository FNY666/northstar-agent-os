"""Inspect helpers: signatures, callable names, generator check. What this IS: reflection one-liners. What this IS NOT: not a debugger."""

from __future__ import annotations

import ast
import inspect

#: Module version.
UTIL_39_VERSION = "util-39.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.util-39.v1"


class InspectError(Exception):
    """Inspect helper failure."""


def signature_str(fn) -> str:
    try:
        return str(inspect.signature(fn))
    except (TypeError, ValueError) as e:
        raise InspectError(f"no signature: {e}") from e


def callable_name(fn) -> str:
    return getattr(fn, "__name__", type(fn).__name__)


def is_generator_fn(fn) -> bool:
    return inspect.isgeneratorfunction(fn)


def source_file(obj):
    try:
        return inspect.getsourcefile(obj)
    except TypeError:
        return None


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = ['__future__', 'ast', 'inspect', 'pathlib']
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
    def f(a, b=2):
        return a
    assert signature_str(f) == "(a, b=2)"
    assert callable_name(f) == "f"
    def g():
        yield 1
    assert is_generator_fn(g) is True
    assert is_generator_fn(f) is False
    assert source_file(f).endswith(".py")
    print("inspect helpers OK")


if __name__ == "__main__":
    main()
