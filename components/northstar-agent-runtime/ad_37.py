"""AD-module: dict_keys_sorted -- Sorted list of dict keys."""
from __future__ import annotations
VERSION = "ad_37.v1"
def dict_keys_sorted(d: dict) -> list:
    return sorted(d.keys())

def main() -> None:
    assert dict_keys_sorted({"b":1,"a":2}) == ["a","b"]
    assert dict_keys_sorted({}) == []
    assert dict_keys_sorted({"x":0}) == ["x"]
    print("ad_37 dict_keys_sorted OK")
if __name__ == "__main__": main()
