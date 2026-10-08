"""X-module: get_path -- Get nested dict value by dotted path."""
from __future__ import annotations
VERSION = "x_14.v1"
def get_path(d: dict, path: str, default=None):
    cur = d
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur: return default
        cur = cur[part]
    return cur

def main() -> None:
    d = {"a": {"b": 7}}
    assert get_path(d, "a.b") == 7
    assert get_path(d, "a.c") is None
    print("x_14 get_path OK")
if __name__ == "__main__": main()
