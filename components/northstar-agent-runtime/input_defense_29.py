"""Type coercion guards (input defense), Simulated

What this IS: Strict, explicit type coercions for untrusted input. Rejects ambiguous values (bool-as-int, NaN/Infinity, empty strings) instead of silently coercing.

What this IS NOT:
* Not a general parser -- narrow helpers with loud failures.
* Callers must handle InputDefenseError; no silent defaults.
"""

from __future__ import annotations

import math

#: Module version.
MODULE_VERSION = "input-defense-29.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.input-defense-29.v1"

ALLOWED_IMPORTS = frozenset({'pathlib', '__future__', 'math', 'ast', 'typing'})


class InputDefenseError(Exception):
    """Fail-closed: malformed input or policy violation raises."""


def to_int(value):
    """Strict int coercion. Rejects bool, float, NaN, malformed strings."""
    if isinstance(value, bool):
        raise InputDefenseError("bool is not a valid int")
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not value.is_integer():
            raise InputDefenseError("non-integer float")
        return int(value)
    if isinstance(value, str):
        s = value.strip()
        if not s or not (s.lstrip("+-").isdigit()):
            raise InputDefenseError("not an integer string: %r" % (value,))
        return int(s)
    raise InputDefenseError("cannot coerce %r to int" % type(value).__name__)


def to_float(value):
    """Strict float coercion. Rejects NaN and Infinity."""
    if isinstance(value, bool):
        raise InputDefenseError("bool is not a valid float")
    if isinstance(value, (int, float)):
        f = float(value)
    elif isinstance(value, str):
        try:
            f = float(value.strip())
        except ValueError:
            raise InputDefenseError("not a float string: %r" % (value,))
    else:
        raise InputDefenseError("cannot coerce %r to float" % type(value).__name__)
    if __import__("math").isnan(f) or __import__("math").isinf(f):
        raise InputDefenseError("NaN/Infinity not allowed")
    return f


def to_nonempty_str(value):
    """Require a non-empty string (after strip)."""
    if not isinstance(value, str):
        raise InputDefenseError("expected str, got %s" % type(value).__name__)
    s = value.strip()
    if not s:
        raise InputDefenseError("empty string not allowed")
    return s


def to_bool(value):
    """Strict bool coercion from a small explicit set."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        s = value.strip().lower()
        if s in ("true", "1", "yes", "y"):
            return True
        if s in ("false", "0", "no", "n"):
            return False
    raise InputDefenseError("cannot coerce %r to bool" % (value,))



def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import ast
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] not in ALLOWED_IMPORTS:
                    return False
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] not in ALLOWED_IMPORTS:
                return False
    return True


def main() -> None:
    """Self-check."""
    assert to_int("42") == 42
    assert to_int(7) == 7
    assert to_int(3.0) == 3
    for bad in (True, 3.5, "abc", "", None):
        try:
            to_int(bad)
            raise AssertionError("should raise for %r" % (bad,))
        except InputDefenseError:
            pass
    assert to_float("1.5") == 1.5
    for bad in ("nan", "inf", "-Infinity"):
        try:
            to_float(bad)
            raise AssertionError("should raise for %r" % (bad,))
        except InputDefenseError:
            pass
    assert to_nonempty_str(" x ") == "x"
    try:
        to_nonempty_str("   ")
        raise AssertionError("should raise")
    except InputDefenseError:
        pass
    assert to_bool("yes") is True and to_bool("0") is False
    try:
        to_bool("maybe")
        raise AssertionError("should raise")
    except InputDefenseError:
        pass
    assert stdlib_only()
    print("input-defense-29.v1 OK")


if __name__ == "__main__":
    main()
