"""AE-module: deep_get -- Nested dict lookup by key path with default."""
from __future__ import annotations
VERSION = "ae_29.v1"
def deep_get(d: dict, keys: list, default=None):
    cur = d
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur

def main() -> None:
    assert deep_get({"a": {"b": 1}}, ["a", "b"]) == 1
    assert deep_get({"a": {}}, ["a", "x"], "d") == "d"
    assert deep_get({}, ["a"]) is None
    print("ae_29 deep_get OK")
if __name__ == "__main__": main()
