"""Config helpers: env prefix scan, JSON file load, merge, typed get. What this IS: layered config assembly. What this IS NOT: not a schema validator."""

from __future__ import annotations

import ast
import json
import os
from pathlib import Path

#: Module version.
UTIL_19_VERSION = "util-19.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.util-19.v1"


class ConfigError(Exception):
    """Config helper failure."""


def from_env(prefix="") -> dict:
    out = {}
    for k, v in os.environ.items():
        if k.startswith(prefix):
            out[k[len(prefix):].lower()] = v
    return out


def from_json_file(path) -> dict:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise ConfigError(f"bad config file {path}: {e}") from e


def merge_configs(*configs) -> dict:
    """Later configs win."""
    out = {}
    for c in configs:
        out.update(c)
    return out


def get_typed(config: dict, key: str, type_fn, default=None):
    if key not in config:
        return default
    try:
        return type_fn(config[key])
    except (ValueError, TypeError) as e:
        raise ConfigError(f"bad value for {key!r}: {e}") from e


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = ['__future__', 'ast', 'json', 'os', 'pathlib']
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
    assert merge_configs({"a": 1}, {"a": 2, "b": 3}) == {"a": 2, "b": 3}
    assert get_typed({"n": "5"}, "n", int) == 5
    assert get_typed({}, "missing", int, default=9) == 9
    try:
        get_typed({"n": "xx"}, "n", int)
        raise AssertionError("should raise")
    except ConfigError:
        pass
    print("config helpers OK")


if __name__ == "__main__":
    main()
