"""Punctuation-insensitive word LCS

What this IS: word LCS after regex tokenization and lowercasing (punctuation ignored).

What this IS NOT:
* plain word LCS -- see lcs_24.
* character LCS -- see lcs_01.
"""

from __future__ import annotations

import ast
import re
#: Module version.
LCS_47_VERSION = "lcs-47.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.lcs-47.v1"


_WORD = re.compile(r"[A-Za-z0-9]+")


def _lcs_seq_len(x, y) -> int:
    prev = [0] * (len(y) + 1)
    for w in x:
        cur = [0] * (len(y) + 1)
        for j in range(1, len(y) + 1):
            if w == y[j - 1]:
                cur[j] = prev[j - 1] + 1
            else:
                cur[j] = prev[j] if prev[j] >= cur[j - 1] else cur[j - 1]
        prev = cur
    return prev[len(y)]


def lcs_words_clean(a: str, b: str) -> int:
    # Tokenize words, drop punctuation, fold case, then LCS.
    return _lcs_seq_len(_WORD.findall(a.lower()), _WORD.findall(b.lower()))

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "typing", "re"}
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
    assert lcs_words_clean("Hello, world!", "hello world") == 2
    assert lcs_words_clean("a,b,c", "a b c") == 3
    assert lcs_words_clean("", "x") == 0
    assert lcs_words_clean("The cat.", "the dog") == 1
    assert lcs_words_clean("a a a", "a a") == 2
    assert stdlib_only()
    print("47-ok OK")


if __name__ == "__main__":
    main()
