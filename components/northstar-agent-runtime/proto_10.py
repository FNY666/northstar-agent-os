"""Generic URI parser per RFC 3986 (scheme/authority/path/query/fragment).

What this IS: parser/validator for URI.
Mock/simulation for agent-runtime gates -- not a full implementation.

What this IS NOT:
* Not a complete URI implementation.
* Host enforces real protocol behavior; this validates structure.
"""

from __future__ import annotations

import re
import urllib.parse

#: Module version.
PROTO_10_VERSION = "proto-10-uri.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.proto-10-uri.v1"


class Proto10Error(Exception):
    """Fail-closed."""


_SCHEME_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*):")


def parse_uri(text: str) -> dict:
    """Parse a generic URI. Raises Proto10Error on empty input."""
    if not isinstance(text, str) or not text:
        raise Proto10Error("empty URI")
    m = _SCHEME_RE.match(text)
    scheme = m.group(1) if m else ""
    p = urllib.parse.urlparse(text)
    return {
        "scheme": scheme,
        "authority": p.netloc,
        "path": p.path,
        "query": p.query,
        "fragment": p.fragment,
        "absolute": bool(scheme),
    }


def is_absolute_uri(text: str) -> bool:
    """True if the URI has a scheme."""
    return parse_uri(text)["absolute"]


def validate_uri(text: str) -> tuple:
    """Validate a URI. Returns (ok, reason)."""
    try:
        parse_uri(text)
    except Proto10Error as exc:
        return False, str(exc)
    if " " in text:
        return False, "URI must not contain spaces"
    return True, "valid URI"


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import ast
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "re", "typing", "urllib"}
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
    u = parse_uri("mailto:user@ex.com")
    assert u["scheme"] == "mailto" and u["absolute"] is True
    assert is_absolute_uri("/relative/path") is False
    ok, _ = validate_uri("http://ex.com/a b")
    assert ok is False

    assert stdlib_only()
    print("proto-10 (uri): OK")


if __name__ == "__main__":
    main()
