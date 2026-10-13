"""Punctuation normalization (input defense), Simulated

What this IS: Maps full-width and lookalike punctuation to ASCII equivalents before matching, closing a common filter-evasion channel.

What this IS NOT:
* Mapping table is a fixed subset, not exhaustive Unicode.
* For matching pipelines only; keep original for display/audit.
"""

from __future__ import annotations

import string


#: Module version.
MODULE_VERSION = "input-defense-20.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.input-defense-20.v1"

ALLOWED_IMPORTS = frozenset({"__future__", "ast", "pathlib", "string", "typing"})


class InputDefenseError(Exception):
    """Fail-closed: malformed input or policy violation raises."""


PUNCT_MAP = {
    "\uff01": "!", "\uff1f": "?", "\uff0c": ",",
    "\u3002": ".", "\uff1a": ":", "\uff1b": ";",
    "\u2018": "'", "\u2019": "'", "\u201c": '"', "\u201d": '"',
    "\u3001": ",", "\uff08": "(", "\uff09": ")",
    "\u2026": "...", "\u2013": "-", "\u2014": "-",
}


def normalize_punctuation(text):
    """Map lookalike punctuation to ASCII. Returns clean str."""
    if not isinstance(text, str):
        raise InputDefenseError("text must be str")
    return "".join(PUNCT_MAP.get(ch, ch) for ch in text)


def strip_punctuation(text):
    """Remove ASCII punctuation. Returns clean str."""
    if not isinstance(text, str):
        raise InputDefenseError("text must be str")
    return text.translate(str.maketrans("", "", string.punctuation))



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
    assert normalize_punctuation("\uff01\uff1f") == "!?"
    assert normalize_punctuation("a\u2019s") == "a's"
    assert strip_punctuation("a,b.c!") == "abc"
    try:
        normalize_punctuation(None)
        raise AssertionError("should raise")
    except InputDefenseError:
        pass
    assert stdlib_only()
    print("input-defense-20.v1 OK")


if __name__ == "__main__":
    main()
