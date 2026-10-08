"""Cron expression matcher

What this IS: a 5-field cron shape matcher (minute hour dom month dow).

What this IS NOT: a cron scheduler -- semantics are not evaluated.
"""

from __future__ import annotations

import ast
import re
from typing import Dict, List, Optional, Tuple

#: Module version.
RX_39_VERSION = "rx-39.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rx-39.v1"

CRON_RE = re.compile(r'(?:[\\*\\d,/-]+\\s+){4}[\\*\\d,/-]+')
def is_cron(text: str) -> bool:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return CRON_RE.fullmatch(text.strip()) is not None


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
    assert is_cron("*/5 * * * *")
    assert is_cron("0 9 * * 1")
    assert not is_cron("* * * *")
    assert not is_cron("every minute")
    assert is_cron(" 0 0 1 1 * ")
    assert stdlib_only()
    print("39-cron OK")


if __name__ == "__main__":
    main()
