"""Common Log Format parser

What this IS: a parser for Apache/Nginx common-log-format lines.

What this IS NOT: a combined-log-format parser (no referrer/agent fields).
"""

from __future__ import annotations

import ast
import re
from typing import Dict, List, Optional, Tuple

#: Module version.
RX_31_VERSION = "rx-31.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.rx-31.v1"

CLF_RE = re.compile(r'^(\\S+) \\S+ \\S+ \\[([^\\]]+)\\] \"(\\S+)(?: (\\S+)(?: \\S+)?)?\" (\\d{3}) (\\S+)')
def parse_clf(line: str):
    if not isinstance(line, str):
        raise TypeError("line must be str")
    m = CLF_RE.match(line)
    if not m:
        return None
    host, ts, method, path, status, size = m.groups()
    return {"host": host, "ts": ts, "method": method, "path": path,
            "status": int(status), "size": None if size == "-" else int(size)}


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
    rec = parse_clf('127.0.0.1 - - [09/Oct/2026:07:31:44 +0800] "GET /index.html HTTP/1.1" 200 1234')
    assert rec["host"] == "127.0.0.1"
    assert rec["status"] == 200
    assert rec["method"] == "GET"
    assert parse_clf("garbage") is None
    assert parse_clf('h - - [t] "GET /" 404 -')["size"] is None
    assert stdlib_only()
    print("31-clf OK")


if __name__ == "__main__":
    main()
