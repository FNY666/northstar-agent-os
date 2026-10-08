"""Dataclass helpers: safe asdict, replace-update, field names. What this IS: dataclass plumbing. What this IS NOT: not a serializer."""

from __future__ import annotations

import ast
import dataclasses

#: Module version.
UTIL_27_VERSION = "util-27.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.util-27.v1"


class DataclassError(Exception):
    """Dataclass helper failure."""


def to_dict_safe(obj) -> dict:
    if not dataclasses.is_dataclass(obj):
        raise DataclassError("not a dataclass")
    return dataclasses.asdict(obj)


def update(obj, **changes):
    if not dataclasses.is_dataclass(obj):
        raise DataclassError("not a dataclass")
    return dataclasses.replace(obj, **changes)


def field_names(obj) -> list:
    if not dataclasses.is_dataclass(obj):
        raise DataclassError("not a dataclass")
    return [f.name for f in dataclasses.fields(obj)]


def is_dataclass_instance(obj) -> bool:
    return dataclasses.is_dataclass(obj) and not isinstance(obj, type)


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = ['__future__', 'ast', 'dataclasses', 'pathlib']
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
    import dataclasses
    @dataclasses.dataclass
    class P:
        x: int
        y: str = "a"
    p = P(1)
    assert to_dict_safe(p) == {"x": 1, "y": "a"}
    q = update(p, y="b")
    assert q.y == "b" and p.y == "a"
    assert field_names(p) == ["x", "y"]
    assert is_dataclass_instance(p) is True
    assert is_dataclass_instance(P) is False
    print("dataclass helpers OK")


if __name__ == "__main__":
    main()
