"""AF-module: merge_dicts -- Merge dicts; later mappings win on key conflicts."""
from __future__ import annotations
VERSION = "af_02"
def merge_dicts(*ds: dict) -> dict:
    out: dict = {}
    for d in ds:
        out.update(d)
    return out

def main() -> None:
    assert merge_dicts({'a': 1}, {'b': 2}) == {'a': 1, 'b': 2}
    assert merge_dicts({'a': 1}, {'a': 9}) == {'a': 9}
    assert merge_dicts() == {}
    print("af_02 merge_dicts OK")
if __name__ == "__main__": main()
