"""Enum helpers: from value, names, values, to dict. What this IS: enum introspection. What this IS NOT: not codegen."""

from __future__ import annotations

import ast
import enum


#: Module version.
UTIL_26_VERSION = "util-26.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.util-26.v1"


class EnumError(Exception):
    """Enum helper failure."""


def from_value(cls, value, default=None):
    try:
        return cls(value)
    except ValueError:
        if default is not None:
            return default
        raise EnumError(f"{value!r} not in {cls.__name__}")


def names(cls):
    return [e.name for e in cls]


def values(cls):
    return [e.value for e in cls]


def to_dict(cls):
    return {e.name: e.value for e in cls}


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = ['__future__', 'ast', 'enum', 'pathlib']
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
    class C(enum.Enum):
        RED = 1
        BLUE = 2
    assert from_value(C, 1) is C.RED
    assert names(C) == ["RED", "BLUE"]
    assert values(C) == [1, 2]
    assert to_dict(C) == {"RED": 1, "BLUE": 2}
    try:
        from_value(C, 99)
        raise AssertionError("should raise")
    except EnumError:
        pass
    print("enum helpers OK")


if __name__ == "__main__":
    main()
