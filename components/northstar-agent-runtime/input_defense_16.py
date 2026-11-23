"""Bidirectional control removal (input defense), Simulated

What this IS: Strips Unicode bidirectional control characters that attackers use to visually reorder text (e.g. hide file extensions, flip command arguments).

What this IS NOT:
* Not a full Unicode confusables solution -- only bidi controls.
* Does not normalize other invisible characters (see 17).
"""

from __future__ import annotations

import re

#: Module version.
MODULE_VERSION = "input-defense-16.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.input-defense-16.v1"

ALLOWED_IMPORTS = frozenset({'pathlib', '__future__', 'ast', 're', 'typing'})


class InputDefenseError(Exception):
    """Fail-closed: malformed input or policy violation raises."""


BIDI_CONTROLS = "".join(
    [chr(c) for c in range(0x202A, 0x202F)]  # U+202A-U+202E
    + [chr(c) for c in range(0x2066, 0x206A)]  # U+2066-U+2069
)
_BIDI_RE = re.compile("[" + re.escape(BIDI_CONTROLS) + "]")


def strip_bidi_controls(text):
    """Remove bidirectional control characters. Returns (clean, removed_count)."""
    if not isinstance(text, str):
        raise InputDefenseError("text must be str")
    removed = len(_BIDI_RE.findall(text))
    return _BIDI_RE.sub("", text), removed


def contains_bidi_controls(text):
    """True if any bidi control is present."""
    if not isinstance(text, str):
        raise InputDefenseError("text must be str")
    return _BIDI_RE.search(text) is not None



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
    clean, n = strip_bidi_controls("a\u202efile\u202c.txt")
    assert clean == "afile.txt"
    assert n == 2
    assert contains_bidi_controls("\u2066x\u2069") is True
    assert contains_bidi_controls("plain") is False
    try:
        strip_bidi_controls(None)
        raise AssertionError("should raise")
    except InputDefenseError:
        pass
    assert stdlib_only()
    print("input-defense-16.v1 OK")


if __name__ == "__main__":
    main()
