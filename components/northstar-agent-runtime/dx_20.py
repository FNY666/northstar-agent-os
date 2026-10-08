"""DX-20: Type checkers (mock), Simulated.

Declared types per symbol; `check(symbol, value)` validates the runtime
value against the declared type via isinstance. Unknown symbols and
unknown type names raise. `bool` is not accepted as `int`.

What this IS: declared-type assertion against runtime values.
What this IS NOT: not a static type checker.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import Any, Dict, List

#: Module version.
DX20_TYPECHECK_VERSION = "dx-typecheck.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.dx-typecheck.v1"

#: Declared type names.
KNOWN_TYPES = frozenset({"int", "str", "bool", "float", "list", "dict", "none"})

_TYPEMAP = {
    "int": int, "str": str, "bool": bool, "float": float,
    "list": list, "dict": dict, "none": type(None),
}


class TypeCheckError(Exception):
    """Fail-closed."""


@dataclass(frozen=True)
class CheckResult:
    symbol: str
    ok: bool
    expected: str
    actual: str


class TypeRegistry:
    """Symbol -> declared type registry."""

    def __init__(self) -> None:
        self._decls: Dict[str, str] = {}

    def declare(self, symbol: str, type_name: str) -> None:
        if not symbol or not symbol.strip():
            raise TypeCheckError("symbol required")
        if type_name not in KNOWN_TYPES:
            raise TypeCheckError(f"unknown type '{type_name}'")
        self._decls[symbol] = type_name

    def check(self, symbol: str, value: Any) -> CheckResult:
        if symbol not in self._decls:
            raise TypeCheckError(f"no declared type for '{symbol}'")
        expected = self._decls[symbol]
        target = _TYPEMAP[expected]
        # bool is a subclass of int; keep them distinct.
        if expected == "int" and isinstance(value, bool):
            ok = False
        else:
            ok = isinstance(value, target)
        return CheckResult(
            symbol=symbol,
            ok=ok,
            expected=expected,
            actual=type(value).__name__,
        )

    @property
    def symbols(self) -> List[str]:
        return sorted(self._decls)


def stdlib_only() -> bool:
    import pathlib

    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "dataclasses", "pathlib", "typing"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name.split(".")[0] not in allowed:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in allowed:
                return False
    return True


def main() -> None:
    reg = TypeRegistry()
    reg.declare("count", "int")
    reg.declare("name", "str")
    r = reg.check("count", 3)
    assert r.ok is True and r.expected == "int"
    assert reg.check("count", "x").ok is False
    assert reg.check("count", True).ok is False  # bool is not int
    assert reg.check("name", "n").ok is True
    try:
        reg.check("missing", 1)
        raise AssertionError("should raise")
    except TypeCheckError:
        pass
    try:
        reg.declare("x", "datetime")
        raise AssertionError("should raise")
    except TypeCheckError:
        pass
    assert reg.symbols == ["count", "name"]
    assert stdlib_only()
    print("dx_20 OK: declare, isinstance check, bool/int split, validation")


if __name__ == "__main__":
    main()
