"""AD-module: invert_dict -- Swap keys and values of a dict."""
from __future__ import annotations
VERSION = "ad_38.v1"
def invert_dict(d: dict) -> dict:
    return {v: k for k, v in d.items()}

def main() -> None:
    assert invert_dict({"a":1}) == {1:"a"}
    assert invert_dict({}) == {}
    assert invert_dict({"x":0,"y":1}) == {0:"x",1:"y"}
    print("ad_38 invert_dict OK")
if __name__ == "__main__": main()
