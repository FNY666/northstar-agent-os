"""AF-module: unflatten_dict -- Dotted-key flat dict back to nested dict."""
from __future__ import annotations
VERSION = "af_26"
def unflatten_dict(d: dict) -> dict:
    out: dict = {}
    for dotted, v in d.items():
        cur = out
        parts = str(dotted).split('.')
        for p in parts[:-1]:
            cur = cur.setdefault(p, {})
        cur[parts[-1]] = v
    return out

def main() -> None:
    assert unflatten_dict({'a.b': 1, 'c': 2}) == {'a': {'b': 1}, 'c': 2}
    assert unflatten_dict({}) == {}
    assert unflatten_dict({'x': 0}) == {'x': 0}
    print("af_26 unflatten_dict OK")
if __name__ == "__main__": main()
