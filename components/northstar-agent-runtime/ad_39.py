"""AD-module: merge_dicts -- Merge two dicts, right wins on conflict."""
from __future__ import annotations
VERSION = "ad_39.v1"
def merge_dicts(a: dict, b: dict) -> dict:
    c = dict(a)
    c.update(b)
    return c

def main() -> None:
    assert merge_dicts({"a":1},{"b":2}) == {"a":1,"b":2}
    assert merge_dicts({"a":1},{"a":2}) == {"a":2}
    assert merge_dicts({},{}) == {}
    print("ad_39 merge_dicts OK")
if __name__ == "__main__": main()
