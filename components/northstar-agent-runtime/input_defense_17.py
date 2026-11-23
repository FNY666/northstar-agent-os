"""Zero-width character removal (input defense), Simulated

What this IS: Removes zero-width characters (U+200B, U+200C, U+200D, U+FEFF) used to smuggle payloads past keyword filters.

What this IS NOT:
* Not a full homoglyph solution -- zero-width chars only.
* U+200D is also a legit ZWJ in emoji; removal is a policy choice for untrusted input.
"""

from __future__ import annotations

import re

#: Module version.
MODULE_VERSION = "input-defense-17.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.input-defense-17.v1"

ALLOWED_IMPORTS = frozenset({'pathlib', '__future__', 'ast', 're', 'typing'})


class InputDefenseError(Exception):
    """Fail-closed: malformed input or policy violation raises."""


ZERO_WIDTH = "\u200b\u200c\u200d\ufeff"
_ZW_RE = re.compile("[" + re.escape(ZERO_WIDTH) + "]")


def strip_zero_width(text):
    """Remove zero-width characters. Returns (clean, removed_count)."""
    if not isinstance(text, str):
        raise InputDefenseError("text must be str")
    removed = len(_ZW_RE.findall(text))
    return _ZW_RE.sub("", text), removed


def contains_zero_width(text):
    """True if any zero-width char is present."""
    if not isinstance(text, str):
        raise InputDefenseError("text must be str")
    return _ZW_RE.search(text) is not None



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
    clean, n = strip_zero_width("e\u200bvil\ufeff")
    assert clean == "evil"
    assert n == 2
    assert contains_zero_width("\u200d") is True
    assert contains_zero_width("ok") is False
    try:
        strip_zero_width(b"x")
        raise AssertionError("should raise")
    except InputDefenseError:
        pass
    assert stdlib_only()
    print("input-defense-17.v1 OK")


if __name__ == "__main__":
    main()
