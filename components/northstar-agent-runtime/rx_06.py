"""ISO-8601 date matcher

What this IS: a YYYY-MM-DD calendar date matcher (format-level only).

What this IS NOT: a calendar validator -- 2026-02-30 passes the format check.
"""

from __future__ import annotations

import ast
import re
from typing import Dict, List, Optional, Tuple

#: Module version.
RX_06_VERSION = "rx-06.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rx-06.v1"

ISO_DATE_RE = re.compile(r'\\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])')
def is_iso_date(text: str) -> bool:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return ISO_DATE_RE.fullmatch(text) is not None

def find_dates(text: str) -> list:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    return ISO_DATE_RE.findall(text)


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
    assert is_iso_date("2026-10-09")
    assert is_iso_date("1999-01-31")
    assert not is_iso_date("2026-13-01")
    assert not is_iso_date("09/10/2026")
    assert find_dates("from 2026-10-01 to 2026-10-09") == ["2026-10-01", "2026-10-09"]
    assert stdlib_only()
    print("06-iso_date OK")


if __name__ == "__main__":
    main()
