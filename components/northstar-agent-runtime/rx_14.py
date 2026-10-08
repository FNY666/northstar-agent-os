"""camelCase identifier matcher

What this IS: a matcher for lowerCamelCase identifiers.

What this IS NOT: a snake_case matcher -- see rx-15.
"""

from __future__ import annotations

import ast
import re
from typing import Dict, List, Optional, Tuple

#: Module version.
RX_14_VERSION = "rx-14.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rx-14.v1"

CAMEL_RE = re.compile(r'[a-z]+(?:[A-Z][a-z0-9]*)+')
def is_camel(text: str) -> bool:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return CAMEL_RE.fullmatch(text) is not None

def find_camels(text: str) -> list:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return CAMEL_RE.findall(text)


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
    assert is_camel("camelCase")
    assert is_camel("myVar2Name")
    assert not is_camel("CamelCase")
    assert not is_camel("snake_case")
    assert find_camels("use myVar and otherThing") == ["myVar", "otherThing"]
    assert stdlib_only()
    print("14-camel OK")


if __name__ == "__main__":
    main()
