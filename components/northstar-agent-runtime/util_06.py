"""Dict helpers: deep merge, flatten/unflatten, path get/set. What this IS: config-shaped dict surgery. What this IS NOT: not a schema validator."""

from __future__ import annotations

import ast


#: Module version.
UTIL_06_VERSION = "util-06.v1"

#: Schema pin.
SCHEMA_PIN = "northstar.util-06.v1"


class DictError(Exception):
    """Dict helper failure."""


def deep_merge(a: dict, b: dict) -> dict:
    """Recursive merge; b wins. Returns a new dict."""
    out = dict(a)
    for k, v in b.items():
        if k in out and isinstance(out[k], dict) and isinstance(v, dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def flatten(d: dict, sep=".", prefix="") -> dict:
    out = {}
    for k, v in d.items():
        key = f"{prefix}{sep}{k}" if prefix else str(k)
        if isinstance(v, dict):
            out.update(flatten(v, sep, key))
        else:
            out[key] = v
    return out


def unflatten(flat: dict, sep=".") -> dict:
    out = {}
    for key, v in flat.items():
        node = out
        parts = str(key).split(sep)
        for p in parts[:-1]:
            node = node.setdefault(p, {})
        node[parts[-1]] = v
    return out


def get_path(d: dict, path: str, default=None, sep="."):
    node = d
    for p in path.split(sep):
        if not isinstance(node, dict) or p not in node:
            return default
        node = node[p]
    return node


def set_path(d: dict, path: str, value, sep=".") -> dict:
    node = d
    parts = path.split(sep)
    for p in parts[:-1]:
        child = node.get(p)
        if not isinstance(child, dict):
            child = {}
            node[p] = child
        node = child
    node[parts[-1]] = value
    return d


def stdlib_only() -> bool:
    """AST check: stdlib only."""
    import pathlib

    tree = ast.parse(
        pathlib.Path(__file__).read_text(encoding="utf-8"), filename=__file__
    )
    allowed = ['__future__', 'ast', 'pathlib']
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
    assert deep_merge({"a": {"x": 1}}, {"a": {"y": 2}}) == {"a": {"x": 1, "y": 2}}
    assert flatten({"a": {"b": 1}}) == {"a.b": 1}
    assert unflatten({"a.b": 1}) == {"a": {"b": 1}}
    assert get_path({"a": {"b": 1}}, "a.b") == 1
    assert get_path({}, "x.y", default=5) == 5
    d = {}
    set_path(d, "a.b", 2)
    assert d == {"a": {"b": 2}}
    print("dict helpers OK")


if __name__ == "__main__":
    main()
