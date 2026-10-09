"""AF-module: deep_set -- Set a nested dict value by key path, creating dicts as needed."""
from __future__ import annotations
VERSION = "af_24"
def deep_set(d: dict, path: tuple, value) -> dict:
    cur = d
    for k in path[:-1]:
        cur = cur.setdefault(k, {})
    cur[path[-1]] = value
    return d

def main() -> None:
    assert deep_set({}, ('a', 'b'), 1) == {'a': {'b': 1}}
    d = {'a': {'b': 2}}
    assert deep_set(d, ('a', 'b'), 9) == {'a': {'b': 9}}
    assert deep_set({}, ('x',), 0) == {'x': 0}
    print("af_24 deep_set OK")
if __name__ == "__main__": main()
