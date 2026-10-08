"""Duration string parser

What this IS: a parser for 1h30m15s style duration strings.

What this IS NOT: a natural-language time parser.
"""

from __future__ import annotations

import ast
import re
from typing import Dict, List, Optional, Tuple

#: Module version.
RX_32_VERSION = "rx-32.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rx-32.v1"

DUR_RE = re.compile(r'^(?:(\\d+)h)?(?:(\\d+)m)?(?:(\\d+)s)?$')
def parse_duration(text: str):
    if not isinstance(text, str):
        raise TypeError("text must be str")
    m = DUR_RE.match(text)
    if not m or not any(m.groups()):
        return None
    h, mi, s = (int(g) if g else 0 for g in m.groups())
    return h * 3600 + mi * 60 + s


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
    assert parse_duration("1h30m") == 5400
    assert parse_duration("45s") == 45
    assert parse_duration("2h") == 7200
    assert parse_duration("") is None
    assert parse_duration("abc") is None
    assert stdlib_only()
    print("32-duration OK")


if __name__ == "__main__":
    main()
