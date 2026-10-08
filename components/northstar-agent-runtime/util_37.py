"""Env helpers: typed getenv with defaults, required vars. What this IS: 12-factor config reads. What this IS NOT: not a dotenv loader."""

from __future__ import annotations

import ast
import os

#: Module version.
UTIL_37_VERSION = "util-37.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.util-37.v1"


class EnvError(Exception):
    """Env helper failure."""


def getenv_str(key: str, default="") -> str:
    return os.environ.get(key, default)


def getenv_int(key: str, default=0) -> int:
    raw = os.environ.get(key)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError as e:
        raise EnvError(f"bad int for {key}: {raw!r}") from e


def getenv_bool(key: str, default=False) -> bool:
    raw = os.environ.get(key)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def getenv_float(key: str, default=0.0) -> float:
    raw = os.environ.get(key)
    if raw is None or raw == "":
        return default
    try:
        return float(raw)
    except ValueError as e:
        raise EnvError(f"bad float for {key}: {raw!r}") from e


def require_env(key: str) -> str:
    val = os.environ.get(key)
    if not val:
        raise EnvError(f"missing required env var: {key}")
    return val


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = ['__future__', 'ast', 'os', 'pathlib']
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
    import os
    os.environ["U37_X"] = "42"
    assert getenv_int("U37_X") == 42
    assert getenv_int("U37_MISSING", default=7) == 7
    os.environ["U37_B"] = "yes"
    assert getenv_bool("U37_B") is True
    assert getenv_str("U37_MISSING", default="d") == "d"
    assert require_env("U37_X") == "42"
    del os.environ["U37_X"], os.environ["U37_B"]
    print("env helpers OK")


if __name__ == "__main__":
    main()
