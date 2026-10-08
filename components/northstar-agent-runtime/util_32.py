"""UUID helpers: v4, v5, parse, validate. What this IS: identifier generation. What this IS NOT: not sortable IDs (see util_40)."""

from __future__ import annotations

import ast
import uuid

#: Module version.
UTIL_32_VERSION = "util-32.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.util-32.v1"


class UuidError(Exception):
    """UUID helper failure."""


def uuid4_str() -> str:
    return str(uuid.uuid4())


def uuid5_str(namespace: uuid.UUID, name: str) -> str:
    return str(uuid.uuid5(namespace, name))


def parse_uuid(s: str) -> uuid.UUID:
    try:
        return uuid.UUID(s or "")
    except (ValueError, AttributeError, TypeError) as e:
        raise UuidError(f"bad uuid: {s!r}") from e


def is_uuid(s: str) -> bool:
    try:
        parse_uuid(s)
        return True
    except UuidError:
        return False


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = ['__future__', 'ast', 'pathlib', 'uuid']
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
    import uuid as _u
    assert _u.UUID(uuid4_str()).version == 4
    a = uuid5_str(_u.NAMESPACE_DNS, "example.com")
    assert uuid5_str(_u.NAMESPACE_DNS, "example.com") == a
    assert _u.UUID(a).version == 5
    assert parse_uuid(a) == _u.UUID(a)
    assert is_uuid("nope") is False
    print("uuid helpers OK")


if __name__ == "__main__":
    main()
