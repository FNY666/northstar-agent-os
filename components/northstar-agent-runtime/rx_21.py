"""Hashtag extractor

What this IS: an extractor for #hashtag tokens.

What this IS NOT: a social-media entity linker.
"""

from __future__ import annotations

import ast
import re
from typing import Dict, List, Optional, Tuple

#: Module version.
RX_21_VERSION = "rx-21.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rx-21.v1"

HASHTAG_RE = re.compile(r'(?<![A-Za-z0-9_])#([A-Za-z0-9_]{1,64})')
def find_hashtags(text: str) -> list:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return HASHTAG_RE.findall(text)


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
    assert find_hashtags("hello #world") == ["world"]
    assert find_hashtags("#a #b2_c") == ["a", "b2_c"]
    assert find_hashtags("no tags") == []
    assert find_hashtags("email a#b.com") == []
    assert find_hashtags("#2026") == ["2026"]
    assert stdlib_only()
    print("21-hashtag OK")


if __name__ == "__main__":
    main()
