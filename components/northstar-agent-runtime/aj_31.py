"""AJ-31: Dict merge."""
from __future__ import annotations
VERSION = "aj_31.v1"


def deep_merge(a, b):
    r = dict(a)
    for k, v in b.items():
        r[k] = deep_merge(r[k], v) if isinstance(r.get(k), dict) and isinstance(v, dict) else v
    return r

def main() -> None:
    assert deep_merge({'a':{'x':1}},{'a':{'y':2}}) == {'a':{'x':1,'y':2}}
    assert deep_merge({}, {'a':1}) == {'a':1}
    print(f"aj_31 OK")
if __name__ == "__main__": main()
