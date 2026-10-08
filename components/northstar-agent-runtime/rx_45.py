"""JSON string literal matcher

What this IS: a matcher for double-quoted JSON strings with escapes.

What this IS NOT: a JSON parser -- use the json module.
"""

from __future__ import annotations

import ast
import re
from typing import Dict, List, Optional, Tuple

#: Module version.
RX_45_VERSION = "rx-45.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rx-45.v1"

JSON_STR_RE = re.compile(r'\"(?:[^\"\\\\]|\\\\.)*\"')
def is_json_string(text: str) -> bool:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return JSON_STR_RE.fullmatch(text) is not None

def find_json_strings(text: str) -> list:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return JSON_STR_RE.findall(text)


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
    assert is_json_string('"hi"')
    assert is_json_string('"a\\nb"')
    assert not is_json_string("'hi'")
    assert not is_json_string('"unclosed')
    assert find_json_strings('{"k": "v"}') == ['"k"', '"v"']
    assert stdlib_only()
    print("45-json_str OK")


if __name__ == "__main__":
    main()
