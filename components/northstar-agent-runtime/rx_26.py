"""ANSI escape stripper

What this IS: a stripper for ANSI SGR escape sequences.

What this IS NOT: a terminal emulator.
"""

from __future__ import annotations

import ast
import re
from typing import Dict, List, Optional, Tuple

#: Module version.
RX_26_VERSION = "rx-26.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rx-26.v1"

ANSI_RE = re.compile(r'\\x1b\\[[0-9;]*m')
def strip_ansi(text: str) -> str:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return ANSI_RE.sub("", text)

def has_ansi(text: str) -> bool:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return ANSI_RE.search(text) is not None


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
    assert strip_ansi("\x1b[31mred\x1b[0m") == "red"
    assert strip_ansi("plain") == "plain"
    assert has_ansi("\x1b[1;32mok\x1b[0m")
    assert not has_ansi("plain")
    assert strip_ansi("\x1b[0m\x1b[0m") == ""
    assert stdlib_only()
    print("26-ansi_strip OK")


if __name__ == "__main__":
    main()
