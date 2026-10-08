"""X-module: deep_merge -- Deep-merge two dicts (b wins)."""
from __future__ import annotations
VERSION = "x_13.v1"
def deep_merge(a: dict, b: dict) -> dict:
    out = dict(a)
    for k, v in b.items():
        if k in out and isinstance(out[k], dict) and isinstance(v, dict):
            out[k] = deep_merge(out[k], v)
        else: out[k] = v
    return out

def main() -> None:
    assert deep_merge({"a": {"x": 1}}, {"a": {"y": 2}}) == {"a": {"x": 1, "y": 2}}
    assert deep_merge({"a": 1}, {"a": 2}) == {"a": 2}
    print("x_13 deep_merge OK")
if __name__ == "__main__": main()
