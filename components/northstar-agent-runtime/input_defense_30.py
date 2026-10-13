"""Numeric range checks (input defense), Simulated

What this IS: Enforces inclusive numeric bounds on untrusted numbers. Rejects out-of-range values instead of clamping silently.

What this IS NOT:
* No silent clamping -- rejection forces the caller to handle it.
* Bounds are per-call policy, not global constants.
"""

from __future__ import annotations



#: Module version.
MODULE_VERSION = "input-defense-30.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.input-defense-30.v1"

ALLOWED_IMPORTS = frozenset({'pathlib', '__future__', 'typing', 'ast'})


class InputDefenseError(Exception):
    """Fail-closed: malformed input or policy violation raises."""


def check_range(value, minimum=None, maximum=None, name="value"):
    """Validate value within [minimum, maximum]. Raises on violation."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise InputDefenseError("%s must be a number" % name)
    if minimum is not None and value < minimum:
        raise InputDefenseError(
            "%s %r below minimum %r" % (name, value, minimum))
    if maximum is not None and value > maximum:
        raise InputDefenseError(
            "%s %r above maximum %r" % (name, value, maximum))
    return value


def check_int_range(value, minimum=None, maximum=None, name="value"):
    """Validate integer within bounds (rejects non-integer floats)."""
    if isinstance(value, bool):
        raise InputDefenseError("%s must be an integer" % name)
    if isinstance(value, float):
        if not value.is_integer():
            raise InputDefenseError("%s must be an integer" % name)
        value = int(value)
    if not isinstance(value, int):
        raise InputDefenseError("%s must be an integer" % name)
    return check_range(value, minimum, maximum, name)


def in_range(value, minimum=None, maximum=None):
    """Non-raising predicate version. Returns True if in bounds."""
    try:
        check_range(value, minimum, maximum)
        return True
    except InputDefenseError:
        return False



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
    assert check_range(5, 0, 10) == 5
    assert check_range(0, 0, 10) == 0  # inclusive
    assert check_range(10, 0, 10) == 10
    for bad, mn, mx in ((11, 0, 10), (-1, 0, 10), (True, 0, 10), ("5", 0, 10)):
        try:
            check_range(bad, mn, mx)
            raise AssertionError("should raise for %r" % (bad,))
        except InputDefenseError:
            pass
    assert check_int_range(3.0, 0, 5) == 3
    try:
        check_int_range(3.5, 0, 5)
        raise AssertionError("should raise")
    except InputDefenseError:
        pass
    assert in_range(5, 0, 10) is True
    assert in_range(99, 0, 10) is False
    assert stdlib_only()
    print("input-defense-30.v1 OK")


if __name__ == "__main__":
    main()
