"""INI section header matcher

What this IS: a matcher for [section] headers.

What this IS NOT: an INI parser.
"""

from __future__ import annotations

import ast
import re
from typing import Dict, List, Optional, Tuple

#: Module version.
RX_44_VERSION = "rx-44.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rx-44.v1"

INI_SECTION_RE = re.compile(r'^\\[([^\\[\\]]+)\\]\\s*$')
def parse_ini_section(line: str):
    if not isinstance(line, str):
        raise TypeError("line must be str")
    m = INI_SECTION_RE.match(line.strip())
    return m.group(1) if m else None


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
    assert parse_ini_section("[server]") == "server"
    assert parse_ini_section("  [a.b]  ") == "a.b"
    assert parse_ini_section("[bad") is None
    assert parse_ini_section("key=val") is None
    assert parse_ini_section("[]") is None
    assert stdlib_only()
    print("44-ini_section OK")


if __name__ == "__main__":
    main()
