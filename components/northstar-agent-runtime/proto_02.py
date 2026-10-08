"""Mock YAML subset parser: nested mappings and '- ' lists.

What this IS: parser/validator for YAML (mock).
Mock/simulation for agent-runtime gates -- not a full implementation.

What this IS NOT:
* Not a complete YAML (mock) implementation.
* Host enforces real protocol behavior; this validates structure.
"""

from __future__ import annotations



#: Module version.
PROTO_02_VERSION = "proto-02-yaml.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.proto-02-yaml.v1"


class Proto02Error(Exception):
    """Fail-closed."""


def _scalar(token: str):
    t = token.strip()
    low = t.lower()
    if low in ("~", "null", "none"):
        return None
    if low == "true":
        return True
    if low == "false":
        return False
    if len(t) >= 2 and t[0] == t[-1] and t[0] in ("'", '"'):
        return t[1:-1]
    try:
        return int(t)
    except ValueError:
        pass
    try:
        return float(t)
    except ValueError:
        pass
    return t


def parse_yaml(text: str) -> dict:
    """Parse a small YAML subset. Raises Proto02Error on invalid input."""
    lines = []
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        lines.append((indent, stripped))
    pos = 0

    def parse_block(indent: int):
        nonlocal pos
        if pos < len(lines) and lines[pos][1].startswith("- "):
            items = []
            while (pos < len(lines) and lines[pos][0] == indent
                   and lines[pos][1].startswith("- ")):
                items.append(_scalar(lines[pos][1][2:]))
                pos += 1
            return items
        mapping = {}
        while pos < len(lines) and lines[pos][0] == indent:
            stripped = lines[pos][1]
            if stripped.startswith("- "):
                break
            if ":" not in stripped:
                raise Proto02Error("bad line: " + stripped)
            key, _, val = stripped.partition(":")
            key = key.strip()
            val = val.strip()
            pos += 1
            if val:
                mapping[key] = _scalar(val)
            elif pos < len(lines) and lines[pos][0] > indent:
                mapping[key] = parse_block(lines[pos][0])
            else:
                mapping[key] = {}
        return mapping

    if not lines:
        return {}
    result = parse_block(lines[0][0])
    if pos != len(lines):
        raise Proto02Error("trailing content after top-level block")
    if not isinstance(result, dict):
        raise Proto02Error("top level must be a mapping")
    return result


def validate_yaml(text: str) -> tuple:
    """Validate mock YAML. Returns (ok, reason)."""
    try:
        parse_yaml(text)
    except Proto02Error as exc:
        return False, str(exc)
    return True, "valid mock YAML"


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import ast
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = {"__future__", "ast", "pathlib", "typing"}
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
    doc = parse_yaml("a: 1\nb:\n  c: true\n  d:\n    - 1\n    - 2\ne: hello\n")
    assert doc == {"a": 1, "b": {"c": True, "d": [1, 2]}, "e": "hello"}
    assert parse_yaml("") == {}
    ok, _ = validate_yaml("a: 1\n  orphan: x\n")
    assert ok is False

    assert stdlib_only()
    print("proto-02 (yaml): OK")


if __name__ == "__main__":
    main()
