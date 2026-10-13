"""Control Char Stripping: strip C0 controls and DEL from text, Simulated.

Invisible control characters are a classic injection vector: null bytes
truncate C strings, bell/backspace alter terminal output, and DEL can slip
past naive filters. This module strips every char with ord(c) < 0x20
(except an allow-listed keep set) plus DEL (0x7F), and reports how many
characters were removed.

What this IS: a fail-closed sanitizer for invisible control characters.

What this IS NOT:
* A full unicode-normalization pass (confusables are a different defense).
* A parser or validator of any structured format.
"""

from __future__ import annotations

import ast
from typing import Tuple

#: Module version.
INPUT_DEFENSE_06_VERSION = "input-defense-06.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.input-defense-06.v1"


class InputDefense06Error(Exception):
    """Fail-closed."""


def strip_controls(
    text: str, keep: Tuple[str, ...] = ("\n", "\t")
) -> Tuple[str, int]:
    """Remove control chars (ord(c) < 0x20 except keep set) and DEL 0x7F.

    Returns (cleaned, removed_count). Non-str input raises InputDefense06Error.
    """
    if not isinstance(text, str):
        raise InputDefense06Error(f"expected str, got {type(text).__name__}")
    keep_set = set(keep)
    out = []
    removed = 0
    for ch in text:
        o = ord(ch)
        if o == 0x7F or (o < 0x20 and ch not in keep_set):
            removed += 1
        else:
            out.append(ch)
    return "".join(out), removed


def has_controls(text: str) -> bool:
    """True if text contains any strippable control char (default keep set)."""
    if not isinstance(text, str):
        raise InputDefense06Error(f"expected str, got {type(text).__name__}")
    keep_set = {"\n", "\t"}
    for ch in text:
        o = ord(ch)
        if o == 0x7F or (o < 0x20 and ch not in keep_set):
            return True
    return False


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing"}
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
    cleaned, removed = strip_controls("a\x00b\x07c\x7fd\n\te")
    assert cleaned == "abcd\n\te", repr(cleaned)
    assert removed == 3, removed
    cleaned2, removed2 = strip_controls("keep\rme", keep=("\n", "\t", "\r"))
    assert cleaned2 == "keep\rme" and removed2 == 0
    assert not has_controls("clean\n\ttext")
    assert has_controls("bad\x00text")
    assert has_controls("bad\x7ftext")
    for bad in (123, None, b"bytes"):
        try:
            strip_controls(bad)  # type: ignore[arg-type]
        except InputDefense06Error:
            pass
        else:
            raise AssertionError("non-str must raise")
    try:
        has_controls(42)  # type: ignore[arg-type]
    except InputDefense06Error:
        pass
    else:
        raise AssertionError("non-str must raise")
    assert stdlib_only()
    print("input-defense-06 OK")


if __name__ == "__main__":
    main()
