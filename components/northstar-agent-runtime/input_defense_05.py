"""Unicode sanitization (NFKC): width/case obfuscation cleanup, Simulated.

NFKC normalization folds fullwidth forms (ＡＢＣ -> ABC), compatibility
ligatures, and other visually confusable variants into their canonical
forms. detect_obfuscation() flags any input whose NFKC form differs from the
input, which is a strong signal of deliberate obfuscation attempts.

What this IS: an NFKC normalization + obfuscation detector.

What this IS NOT:
* A homoglyph resolver for look-alike letters across scripts (Cyrillic а).
* A guarantee that normalized text is safe, only that it is canonical.
"""

from __future__ import annotations

import ast
import pathlib
import unicodedata
from typing import Tuple

#: Module version.
INPUT_DEFENSE_05_VERSION = "input-defense-05.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.input-defense-05.v1"


class InputDefense05Error(Exception):
    """Fail-closed."""


def sanitize(text: str) -> Tuple[str, bool]:
    """NFKC-normalize text; return (cleaned, changed)."""
    if not isinstance(text, str):
        raise InputDefense05Error(
            f"sanitize() requires str, got {type(text).__name__}"
        )
    cleaned = unicodedata.normalize("NFKC", text)
    return cleaned, cleaned != text


def detect_obfuscation(text: str) -> bool:
    """True iff NFKC normalization changes the text (possible obfuscation)."""
    if not isinstance(text, str):
        raise InputDefense05Error(
            f"detect_obfuscation() requires str, got {type(text).__name__}"
        )
    return unicodedata.normalize("NFKC", text) != text


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    tree = ast.parse(pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__)
    allowed = {"__future__", "ast", "pathlib", "typing", "unicodedata"}
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
    cleaned, changed = sanitize("hello")
    assert cleaned == "hello" and not changed
    cleaned, changed = sanitize("ＡＢＣ")  # fullwidth
    assert cleaned == "ABC" and changed
    cleaned, changed = sanitize("ﬁ")  # fi ligature
    assert cleaned == "fi" and changed
    cleaned, changed = sanitize("１２３")
    assert cleaned == "123" and changed
    assert detect_obfuscation("ＡＢＣ") is True
    assert detect_obfuscation("ABC") is False
    assert detect_obfuscation("") is False
    try:
        sanitize(b"bytes")
    except InputDefense05Error:
        pass
    else:
        raise AssertionError("non-str sanitize must raise")
    try:
        detect_obfuscation(None)
    except InputDefense05Error:
        pass
    else:
        raise AssertionError("non-str detect_obfuscation must raise")
    assert stdlib_only()
    print("input-defense-05 OK")


if __name__ == "__main__":
    main()
