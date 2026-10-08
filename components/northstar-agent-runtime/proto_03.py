"""Mock TOML subset parser: [sections] and key = value.

What this IS: parser/validator for TOML (mock).
Mock/simulation for agent-runtime gates -- not a full implementation.

What this IS NOT:
* Not a complete TOML (mock) implementation.
* Host enforces real protocol behavior; this validates structure.
"""

from __future__ import annotations



#: Module version.
PROTO_03_VERSION = "proto-03-toml.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.proto-03-toml.v1"


class Proto03Error(Exception):
    """Fail-closed."""


def _toml_value(token: str, lineno: int):
    t = token.strip()
    if len(t) >= 2 and t[0] == t[-1] and t[0] in ("'", '"'):
        return t[1:-1]
    low = t.lower()
    if low == "true":
        return True
    if low == "false":
        return False
    if t.startswith("[") and t.endswith("]"):
        inner = t[1:-1].strip()
        if not inner:
            return []
        return [_toml_value(p, lineno) for p in inner.split(",")]
    try:
        return int(t)
    except ValueError:
        pass
    try:
        return float(t)
    except ValueError:
        pass
    raise Proto03Error("line %d: bad value %r" % (lineno, token))


def parse_toml(text: str) -> dict:
    """Parse a small TOML subset. Raises Proto03Error on invalid input."""
    root = {}
    section = root
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            name = line[1:-1].strip()
            if not name:
                raise Proto03Error("line %d: empty section" % lineno)
            section = root.setdefault(name, {})
            continue
        if "=" not in line:
            raise Proto03Error("line %d: expected key = value" % lineno)
        key, _, val = line.partition("=")
        key = key.strip()
        if not key:
            raise Proto03Error("line %d: empty key" % lineno)
        section[key] = _toml_value(val, lineno)
    return root


def validate_toml(text: str) -> tuple:
    """Validate mock TOML. Returns (ok, reason)."""
    try:
        parse_toml(text)
    except Proto03Error as exc:
        return False, str(exc)
    return True, "valid mock TOML"


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
    doc = parse_toml('title = "x"\n[db]\nport = 5432\ntls = true\ntags = ["a", "b"]\n')
    assert doc == {"title": "x", "db": {"port": 5432, "tls": True, "tags": ["a", "b"]}}
    ok, _ = validate_toml("no equals here\n")
    assert ok is False

    assert stdlib_only()
    print("proto-03 (toml): OK")


if __name__ == "__main__":
    main()
