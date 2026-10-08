"""snake_case identifier matcher

What this IS: a matcher for lower_snake_case identifiers.

What this IS NOT: a camelCase matcher -- see rx-14.
"""

from __future__ import annotations

import ast
import re
from typing import Dict, List, Optional, Tuple

#: Module version.
RX_15_VERSION = "rx-15.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rx-15.v1"

SNAKE_RE = re.compile(r'[a-z][a-z0-9]*(?:_[a-z0-9]+)+')
def is_snake(text: str) -> bool:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return SNAKE_RE.fullmatch(text) is not None

def find_snakes(text: str) -> list:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return SNAKE_RE.findall(text)


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
    assert is_snake("snake_case")
    assert is_snake("my_var_2")
    assert not is_snake("Snake_Case")
    assert not is_snake("camelCase")
    assert find_snakes("use my_var and other_thing") == ["my_var", "other_thing"]
    assert stdlib_only()
    print("15-snake OK")


if __name__ == "__main__":
    main()
