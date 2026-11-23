"""Whitespace normalization (input defense), Simulated

What this IS: Collapses runs of whitespace to single spaces and trims ends, so padding tricks cannot evade length or keyword checks.

What this IS NOT:
* Not Unicode whitespace folding beyond str.split semantics.
* Does not alter non-whitespace characters.
"""

from __future__ import annotations

import re

#: Module version.
MODULE_VERSION = "input-defense-18.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.input-defense-18.v1"

ALLOWED_IMPORTS = frozenset({'pathlib', '__future__', 'ast', 're', 'typing'})


class InputDefenseError(Exception):
    """Fail-closed: malformed input or policy violation raises."""


_WS_RE = re.compile(r"\s+")


def normalize_whitespace(text):
    """Collapse whitespace runs to single spaces and trim. Returns clean str."""
    if not isinstance(text, str):
        raise InputDefenseError("text must be str")
    return _WS_RE.sub(" ", text).strip()


def whitespace_anomaly(text, max_run=50):
    """True if any whitespace run exceeds max_run (padding trick)."""
    if not isinstance(text, str):
        raise InputDefenseError("text must be str")
    return any(len(m.group(0)) > max_run for m in _WS_RE.finditer(text))



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
    assert normalize_whitespace("  a   b\t\nc  ") == "a b c"
    assert normalize_whitespace("") == ""
    assert whitespace_anomaly("a" + " " * 60 + "b") is True
    assert whitespace_anomaly("a b") is False
    try:
        normalize_whitespace(None)
        raise AssertionError("should raise")
    except InputDefenseError:
        pass
    assert stdlib_only()
    print("input-defense-18.v1 OK")


if __name__ == "__main__":
    main()
