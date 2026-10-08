"""URL parser/validator (stdlib urllib.parse).

What this IS: parser/validator for URL.
Mock/simulation for agent-runtime gates -- not a full implementation.

What this IS NOT:
* Not a complete URL implementation.
* Host enforces real protocol behavior; this validates structure.
"""

from __future__ import annotations

import urllib.parse

#: Module version.
PROTO_09_VERSION = "proto-09-url.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.proto-09-url.v1"


class Proto09Error(Exception):
    """Fail-closed."""


def parse_url(url: str) -> dict:
    """Parse a URL into components. Raises Proto09Error."""
    try:
        p = urllib.parse.urlparse(url)
    except ValueError as exc:
        raise Proto09Error("bad URL: %s" % exc)
    try:
        port = p.port
    except ValueError as exc:
        raise Proto09Error("bad port: %s" % exc)
    return {
        "scheme": p.scheme,
        "host": p.hostname or "",
        "port": port,
        "path": p.path,
        "query": dict(urllib.parse.parse_qsl(p.query)),
        "fragment": p.fragment,
    }


def validate_url(url: str, require_https: bool = False) -> tuple:
    """Validate a URL. Returns (ok, reason)."""
    try:
        parts = parse_url(url)
    except Proto09Error as exc:
        return False, str(exc)
    if not parts["scheme"] or not parts["host"]:
        return False, "URL needs scheme and host"
    if require_https and parts["scheme"] != "https":
        return False, "https required"
    return True, "valid URL"


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import ast
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "typing", "urllib"}
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
    u = parse_url("https://ex.com:8443/p?a=1&b=2#frag")
    assert u["scheme"] == "https" and u["host"] == "ex.com" and u["port"] == 8443
    assert u["query"] == {"a": "1", "b": "2"} and u["fragment"] == "frag"
    ok, _ = validate_url("http://ex.com/", require_https=True)
    assert ok is False

    assert stdlib_only()
    print("proto-09 (url): OK")


if __name__ == "__main__":
    main()
