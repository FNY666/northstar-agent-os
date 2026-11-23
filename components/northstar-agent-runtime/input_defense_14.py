"""Invisible Character Removal: strips zero-width and hidden chars, Simulated.

Removes characters that are invisible to a human reader but visible to
a machine: zero-width space/non-joiner/joiner, the byte-order-mark
code point, word joiner, Mongolian vowel separator, soft hyphen, and
the invisible mathematical operators U+2061-U+2064. Attackers use these
to split keywords (evading filters), to hide payloads in copy-pasted
text, and to smuggle instructions past token-based checks.

What this IS: A sanitizer that strips invisible characters and counts them.

What this IS NOT:
* A confusable or script detector (see modules 12/13): it only handles zero-width/hidden chars.
* A rich-text cleaner: it leaves visible formatting (bold/italic markup) alone.
"""

from __future__ import annotations

import ast
from typing import FrozenSet, Tuple

#: Module version.
INPUT_DEFENSE_14_VERSION = "input-defense-14.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.input-defense-14.v1"


class InputDefense14Error(Exception):
    """Fail-closed."""


#: Invisible / zero-width characters that are stripped by :func:`remove`.
INVISIBLE: FrozenSet[str] = frozenset({
    "​",  # U+200B ZERO WIDTH SPACE
    "‌",  # U+200C ZERO WIDTH NON-JOINER
    "‍",  # U+200D ZERO WIDTH JOINER
    "﻿",  # U+FEFF ZERO WIDTH NO-BREAK SPACE (BOM)
    "⁠",  # U+2060 WORD JOINER
    "᠎",  # U+180E MONGOLIAN VOWEL SEPARATOR
    "­",  # U+00AD SOFT HYPHEN
    "⁡",  # U+2061 FUNCTION APPLICATION
    "⁢",  # U+2062 INVISIBLE TIMES
    "⁣",  # U+2063 INVISIBLE SEPARATOR
    "⁤",  # U+2064 INVISIBLE PLUS
})


def remove(text: str) -> Tuple[str, int]:
    """Return ``(cleaned, removed)`` with invisible chars stripped.

    ``cleaned`` is the input minus every character in :data:`INVISIBLE`;
    ``removed`` is the count of stripped characters. Fail-closed:
    non-str input raises :class:`InputDefense14Error`.
    """
    if not isinstance(text, str):
        raise InputDefense14Error(
            "remove requires str, got %s" % type(text).__name__
        )
    cleaned = "".join(ch for ch in text if ch not in INVISIBLE)
    return (cleaned, len(text) - len(cleaned))


def has_invisible(text: str) -> bool:
    """Return True when any invisible character is present.

    Fail-closed: non-str input raises :class:`InputDefense14Error`.
    """
    if not isinstance(text, str):
        raise InputDefense14Error(
            "has_invisible requires str, got %s" % type(text).__name__
        )
    return any(ch in INVISIBLE for ch in text)


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing"}  # only modules you actually import
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
    # Zero-width space hidden inside a word.
    cleaned, removed = remove("a​b")
    assert cleaned == "ab" and removed == 1, (cleaned, removed)
    # Multiple distinct invisible chars in one pass.
    cleaned, removed = remove("a‍­b")
    assert cleaned == "ab" and removed == 2, (cleaned, removed)
    # Keyword split by invisible chars rejoins exactly.
    keyword = "pas​s⁢wo⁣rd"
    cleaned, removed = remove(keyword)
    assert cleaned == "password" and removed == 3, (cleaned, removed)
    # has_invisible agrees with remove.
    assert has_invisible("a​b") is True
    assert has_invisible("a‍b") is True
    assert has_invisible("﻿bom") is True
    assert has_invisible("clean") is False
    assert has_invisible("") is False
    assert remove("clean") == ("clean", 0)
    # Fail-closed on non-str.
    for bad in (None, 123, b"clean", ["clean"]):
        try:
            remove(bad)  # type: ignore[arg-type]
        except InputDefense14Error:
            pass
        else:
            raise AssertionError("remove(%r) did not raise" % (bad,))
        try:
            has_invisible(bad)  # type: ignore[arg-type]
        except InputDefense14Error:
            pass
        else:
            raise AssertionError("has_invisible(%r) did not raise" % (bad,))
    assert stdlib_only()
    print("input-defense-14 OK")


if __name__ == "__main__":
    main()
