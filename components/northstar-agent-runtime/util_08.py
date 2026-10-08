"""JSON helpers: safe parse, canonical dumps, pretty print. What this IS: JSON with sane defaults and clear errors. What this IS NOT: not a streaming parser."""

from __future__ import annotations

import ast
import json

#: Module version.
UTIL_08_VERSION = "util-08.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.util-08.v1"


class JsonError(Exception):
    """JSON helper failure."""


def safe_parse(s, default=None):
    """Parse JSON; return default on any failure."""
    try:
        return json.loads(s)
    except (json.JSONDecodeError, TypeError):
        return default


def canonical(obj) -> str:
    """Canonical JSON: sorted keys, compact separators."""
    try:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    except (TypeError, ValueError) as e:
        raise JsonError(f"not serializable: {e}") from e


def pretty(obj) -> str:
    try:
        return json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True)
    except (TypeError, ValueError) as e:
        raise JsonError(f"not serializable: {e}") from e


def parse_file(path, default=None):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return default


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = ['__future__', 'ast', 'json', 'pathlib']
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
    assert safe_parse('{"a": 1}') == {"a": 1}
    assert safe_parse("nope", default={}) == {}
    assert canonical({"b": 1, "a": 2}) == '{"a":2,"b":1}'
    assert "\n" in pretty({"a": 1})
    print("json helpers OK")


if __name__ == "__main__":
    main()
