"""HH:MM:SS time matcher

What this IS: a 24-hour clock time matcher.

What this IS NOT: a timezone-aware datetime parser.
"""

from __future__ import annotations

import ast
import re
from typing import Dict, List, Optional, Tuple

#: Module version.
RX_07_VERSION = "rx-07.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rx-07.v1"

TIME_RE = re.compile(r'(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]')
def is_time(text: str) -> bool:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return TIME_RE.fullmatch(text) is not None

def find_times(text: str) -> list:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return TIME_RE.findall(text)


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
    assert is_time("07:31:44")
    assert is_time("23:59:59")
    assert not is_time("24:00:00")
    assert not is_time("7:31")
    assert find_times("at 07:31:44 and 12:00:00") == ["07:31:44", "12:00:00"]
    assert stdlib_only()
    print("07-time_hms OK")


if __name__ == "__main__":
    main()
