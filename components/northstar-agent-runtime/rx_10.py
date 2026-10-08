"""UUID matcher

What this IS: a UUID (any version) hexadecimal matcher.

What this IS NOT: a version/variant validator -- it checks shape, not the version nibble.
"""

from __future__ import annotations

import ast
import re
from typing import Dict, List, Optional, Tuple

#: Module version.
RX_10_VERSION = "rx-10.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rx-10.v1"

UUID_RE = re.compile(r'[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}')
def is_uuid(text: str) -> bool:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return UUID_RE.fullmatch(text) is not None

def find_uuids(text: str) -> list:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return UUID_RE.findall(text)


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
    assert is_uuid("f74542ed-d5df-4d95-96f9-3022fb26eab5")
    assert is_uuid("00000000-0000-0000-0000-000000000000")
    assert not is_uuid("f74542ed-d5df-4d95-96f9")
    assert not is_uuid("xyz")
    assert find_uuids("id f74542ed-d5df-4d95-96f9-3022fb26eab5 end") == ["f74542ed-d5df-4d95-96f9-3022fb26eab5"]
    assert stdlib_only()
    print("10-uuid4 OK")


if __name__ == "__main__":
    main()
