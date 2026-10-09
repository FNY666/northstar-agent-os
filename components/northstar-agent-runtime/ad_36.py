"""AD-module: dict_get -- Safe dict lookup with default."""
from __future__ import annotations
VERSION = "ad_36.v1"
def dict_get(d: dict, k, default=None):
    return d[k] if k in d else default

def main() -> None:
    assert dict_get({"a":1}, "a") == 1
    assert dict_get({}, "b") is None
    assert dict_get({}, "b", 9) == 9
    print("ad_36 dict_get OK")
if __name__ == "__main__": main()
