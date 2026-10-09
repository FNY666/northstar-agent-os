"""AF-module: deep_get -- Fetch a nested dict value by key path; default if missing."""
from __future__ import annotations
VERSION = "af_23"
def deep_get(d: dict, path: tuple, default=None):
    cur = d
    for k in path:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur

def main() -> None:
    assert deep_get({'a': {'b': 1}}, ('a', 'b')) == 1
    assert deep_get({'a': {}}, ('a', 'x'), 'd') == 'd'
    assert deep_get({}, ('a',), 7) == 7
    print("af_23 deep_get OK")
if __name__ == "__main__": main()
