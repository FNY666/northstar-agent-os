"""JSON parser/validator (stdlib json).

What this IS: parser/validator for JSON.
Mock/simulation for agent-runtime gates -- not a full implementation.

What this IS NOT:
* Not a complete JSON implementation.
* Host enforces real protocol behavior; this validates structure.
"""

from __future__ import annotations

import json

#: Module version.
PROTO_01_VERSION = "proto-01-json.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.proto-01-json.v1"


class Proto01Error(Exception):
    """Fail-closed."""


def parse_json(text: str) -> object:
    """Parse JSON text. Raises Proto01Error on invalid input."""
    if not isinstance(text, str):
        raise Proto01Error("input must be str")
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise Proto01Error("invalid JSON: %s" % exc) from exc


def validate_json(text: str, required_keys=None) -> tuple:
    """Validate JSON text; optionally require top-level keys."""
    try:
        obj = parse_json(text)
    except Proto01Error as exc:
        return False, str(exc)
    if required_keys is not None:
        if not isinstance(obj, dict):
            return False, "top level is not an object"
        missing = [k for k in required_keys if k not in obj]
        if missing:
            return False, "missing keys: " + ",".join(missing)
    return True, "valid JSON"


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import ast
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "json", "pathlib", "typing"}
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
    obj = parse_json('{"a": 1, "b": [1, 2]}')
    assert obj == {"a": 1, "b": [1, 2]}
    ok, _ = validate_json('{"a": 1}', ["a", "z"])
    assert ok is False
    ok, _ = validate_json("[1, 2]", None)
    assert ok is True
    try:
        parse_json("{oops")
    except Proto01Error:
        pass
    else:
        raise AssertionError("expected Proto01Error")

    assert stdlib_only()
    print("proto-01 (json): OK")


if __name__ == "__main__":
    main()
