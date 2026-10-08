"""URL parameter smuggling detection (url-param-smuggle), Simulated.

Detects URL parameter smuggling: duplicate parameters, double-encoded values, and sensitive data in query strings.

What this IS: a URL query-string smuggling detector.

What this IS NOT:
* Parses the URL string only; no requests made.
* Encoded values are decoded once before scanning.
"""

from __future__ import annotations

import ast
from typing import Any, Dict, List
import re
import urllib.parse

#: Module version.
EXFIL_19_VERSION = "exfil-19.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.exfil-19.v1"


class Exfil19Error(Exception):
    """Fail-closed."""


def detect_url_param_smuggling(url: str) -> tuple:
    """Detect URL param smuggling. Returns (suspicious, reason)."""
    if not isinstance(url, str) or not url:
        raise Exfil19Error("url must be non-empty str")
    parsed = urllib.parse.urlparse(url)
    raw_query = parsed.query
    params = urllib.parse.parse_qsl(raw_query, keep_blank_values=True)
    names = [k for k, _ in params]
    if len(names) != len(set(names)):
        return True, "duplicate query parameters"
    if "%25" in raw_query:
        return True, "double-encoded value in query"
    for k, v in params:
        decoded = urllib.parse.unquote(v)
        for pat, label in [(r"\b\d{3}-\d{2}-\d{4}\b", "SSN"), (r"sk-[A-Za-z0-9]{16,}", "API key")]:
            if re.search(pat, decoded):
                return True, "sensitive in param %s: %s" % (k, label)
    return False, "ok"

def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "typing", "re", "urllib"}
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
    ok, _ = detect_url_param_smuggling("https://x.com/?q=hello&page=2")
    assert ok is False
    ok, _ = detect_url_param_smuggling("https://x.com/?a=1&a=2")
    assert ok is True
    ok, _ = detect_url_param_smuggling("https://x.com/?id=123-45-6789")
    assert ok is True
    assert stdlib_only()
    print("exfil-19 OK: url param smuggling, fail-closed")


if __name__ == "__main__":
    main()
