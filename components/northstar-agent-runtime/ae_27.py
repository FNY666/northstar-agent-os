"""AE-module: merge_dicts -- Two dicts merged, b wins on conflict."""
from __future__ import annotations
VERSION = "ae_27.v1"
def merge_dicts(a: dict, b: dict) -> dict:
    return {**a, **b}

def main() -> None:
    assert merge_dicts({"x": 1}, {"y": 2}) == {"x": 1, "y": 2}
    assert merge_dicts({"x": 1}, {"x": 9}) == {"x": 9}
    assert merge_dicts({}, {}) == {}
    print("ae_27 merge_dicts OK")
if __name__ == "__main__": main()
