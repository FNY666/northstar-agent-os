"""Rotation check: single substring test.

b is a rotation of a iff len equal and b in a+a.

What this IS: a real O(n) check.
What this IS NOT: finding the rotation offset; trivially derived.
"""

from __future__ import annotations

import ast

#: Module version.
STR_16_VERSION = "str-rotation.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.str-rotation-check.v1"


class StrError(Exception):
    """Fail-closed."""


def is_rotation(a: str, b: str) -> bool:
    """True iff b is a rotation of a."""
    return len(a) == len(b) and b in (a + a)


def rotation_offset(a: str, b: str) -> int:
    """Left-rotation offset of a that yields b, or -1."""
    if len(a) != len(b):
        return -1
    idx = (a + a).find(b)
    return idx if idx < len(a) else -1


def test_rot_true():
    assert is_rotation("waterbottle", "erbottlewat") is True


def test_rot_false():
    assert is_rotation("abc", "acb") is False


def test_rot_offset():
    assert rotation_offset("abcde", "cdeab") == 2
    assert rotation_offset("abc", "acb") == -1


def test_rot_empty():
    assert is_rotation("", "") is True


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib"}
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
    test_rot_true()
    test_rot_false()
    test_rot_offset()
    test_rot_empty()
    assert stdlib_only()
    print("str-16 OK: rotation")


if __name__ == "__main__":
    main()
