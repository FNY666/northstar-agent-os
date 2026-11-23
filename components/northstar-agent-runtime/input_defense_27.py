"""Strict allowlist validation (input defense), Simulated

What this IS: Validates inputs against an explicit allowlist of values or patterns. Anything not listed is rejected (default deny).

What this IS NOT:
* Allowlists must be maintained; stale lists break legit use.
* For open-ended text this is the wrong tool -- use blocklists/heuristics.
"""

from __future__ import annotations

import re

#: Module version.
MODULE_VERSION = "input-defense-27.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.input-defense-27.v1"

ALLOWED_IMPORTS = frozenset({'pathlib', '__future__', 'ast', 're', 'typing'})


class InputDefenseError(Exception):
    """Fail-closed: malformed input or policy violation raises."""


class Allowlist:
    """Strict allowlist for values and regex patterns."""

    def __init__(self, values=None, patterns=None):
        self.values = frozenset(values or ())
        self.patterns = [__import__("re").compile(p) for p in (patterns or ())]
        if not self.values and not self.patterns:
            raise InputDefenseError("allowlist must not be empty")

    def check(self, value):
        """Returns True if value is explicitly allowed."""
        if not isinstance(value, str):
            return False
        if value in self.values:
            return True
        return any(p.fullmatch(value) for p in self.patterns)

    def require(self, value):
        """Raise InputDefenseError unless value is allowed."""
        if not self.check(value):
            raise InputDefenseError("value not on allowlist: %r" % (value,))
        return True



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
    a = Allowlist(values={"read", "list"}, patterns=[r"get_\w+"])
    assert a.check("read") is True
    assert a.check("get_user") is True
    assert a.check("delete") is False
    assert a.check(123) is False
    a.require("list")
    try:
        a.require("drop")
        raise AssertionError("should raise")
    except InputDefenseError:
        pass
    try:
        Allowlist()
        raise AssertionError("should raise")
    except InputDefenseError:
        pass
    assert stdlib_only()
    print("input-defense-27.v1 OK")


if __name__ == "__main__":
    main()
