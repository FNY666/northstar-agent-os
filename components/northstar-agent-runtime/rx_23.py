"""Word-boundary finder

What this IS: a case-insensitive whole-word finder.

What this IS NOT: a stemming search engine.
"""

from __future__ import annotations

import ast
import re
from typing import Dict, List, Optional, Tuple

#: Module version.
RX_23_VERSION = "rx-23.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rx-23.v1"

WORD_FIND_PLACEHOLDER = re.compile(r'\b')
def find_word(text: str, word: str, ignore_case: bool = True) -> list:
    if not isinstance(text, str) or not isinstance(word, str):
        raise TypeError("text and word must be str")
    flags = re.IGNORECASE if ignore_case else 0
    return re.findall(r"\b" + re.escape(word) + r"\b", text, flags)


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "re", "typing"}
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
    assert find_word("the cat sat", "cat") == ["cat"]
    assert find_word("The Cat", "cat") == ["Cat"]
    assert find_word("concatenate", "cat") == []
    assert find_word("cat cat", "cat") == ["cat", "cat"]
    assert find_word("Cat", "cat", ignore_case=False) == []
    assert stdlib_only()
    print("23-word_find OK")


if __name__ == "__main__":
    main()
