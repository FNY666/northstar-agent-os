"""Emoji-range detector

What this IS: a detector for common emoji unicode ranges.

What this IS NOT: a grapheme-cluster splitter.
"""

from __future__ import annotations

import ast
import re
from typing import Dict, List, Optional, Tuple

#: Module version.
RX_50_VERSION = "rx-50.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rx-50.v1"

EMOJI_RE = re.compile(r'[\\U0001F300-\\U0001FAFF\\u2600-\\u27BF\\u2B00-\\u2BFF]')
def has_emoji(text: str) -> bool:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return EMOJI_RE.search(text) is not None

def find_emojis(text: str) -> list:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return EMOJI_RE.findall(text)


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
    assert has_emoji("hello \U0001F600")
    assert has_emoji("\u2600 sunny")
    assert not has_emoji("plain text")
    assert find_emojis("a\U0001F600b") == ["\U0001F600"]
    assert find_emojis("") == []
    assert stdlib_only()
    print("50-emoji OK")


if __name__ == "__main__":
    main()
