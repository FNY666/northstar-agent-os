"""AE-module: invert_dict -- Swap keys and values of a dict."""
from __future__ import annotations
VERSION = "ae_28.v1"
def invert_dict(d: dict) -> dict:
    return {v: k for k, v in d.items()}

def main() -> None:
    assert invert_dict({"a": 1, "b": 2}) == {1: "a", 2: "b"}
    assert invert_dict({}) == {}
    assert invert_dict({"z": 0}) == {0: "z"}
    print("ae_28 invert_dict OK")
if __name__ == "__main__": main()
