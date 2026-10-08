"""Key=value pair matcher

What this IS: a matcher for KEY=value assignment lines.

What this IS NOT: a shell parser -- quoting is not handled.
"""

from __future__ import annotations

import ast
import re
from typing import Dict, List, Optional, Tuple

#: Module version.
RX_43_VERSION = "rx-43.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rx-43.v1"

KV_RE = re.compile(r'^([A-Za-z_][A-Za-z0-9_]*)=(.*)$')
def parse_kv(line: str):
    if not isinstance(line, str):
        raise TypeError("line must be str")
    m = KV_RE.match(line)
    if not m:
        return None
    return (m.group(1), m.group(2))


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
    assert parse_kv("KEY=value") == ("KEY", "value")
    assert parse_kv("A=b=c") == ("A", "b=c")
    assert parse_kv("EMPTY=") == ("EMPTY", "")
    assert parse_kv("1BAD=x") is None
    assert parse_kv("no equals") is None
    assert stdlib_only()
    print("43-kv_pair OK")


if __name__ == "__main__":
    main()
