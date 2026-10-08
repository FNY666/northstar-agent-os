"""ENV/dotenv parser: KEY=VALUE, export prefix, quotes, comments.

What this IS: parser/validator for ENV/dotenv.
Mock/simulation for agent-runtime gates -- not a full implementation.

What this IS NOT:
* Not a complete ENV/dotenv implementation.
* Host enforces real protocol behavior; this validates structure.
"""

from __future__ import annotations

import re

#: Module version.
PROTO_07_VERSION = "proto-07-env.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.proto-07-env.v1"


class Proto07Error(Exception):
    """Fail-closed."""


_KEY_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def parse_env(text: str) -> dict:
    """Parse dotenv text. Raises Proto07Error on bad lines."""
    result = {}
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].strip()
        if "=" not in line:
            raise Proto07Error("line %d: expected KEY=VALUE" % lineno)
        key, _, val = line.partition("=")
        key = key.strip()
        if not _KEY_RE.fullmatch(key):
            raise Proto07Error("line %d: bad key %r" % (lineno, key))
        val = val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
            val = val[1:-1]
        result[key] = val
    return result


def validate_env(text: str, required=None) -> tuple:
    """Validate ENV text; optionally require keys. Returns (ok, reason)."""
    try:
        data = parse_env(text)
    except Proto07Error as exc:
        return False, str(exc)
    if required:
        missing = [k for k in required if k not in data]
        if missing:
            return False, "missing: " + ",".join(missing)
    return True, "valid ENV"


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import ast
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
    data = parse_env('A=1\nexport B="x y"\n# c\nC=\'z\'\n')
    assert data == {"A": "1", "B": "x y", "C": "z"}
    ok, _ = validate_env("1BAD=x\n")
    assert ok is False

    assert stdlib_only()
    print("proto-07 (env): OK")


if __name__ == "__main__":
    main()
