"""AD-module: abs_val -- Absolute value without calling abs()."""
from __future__ import annotations
VERSION = "ad_04.v1"
def abs_val(x: float) -> float:
    return x if x >= 0 else -x

def main() -> None:
    assert abs_val(-3) == 3
    assert abs_val(4) == 4
    assert abs_val(0) == 0
    print("ad_04 abs_val OK")
if __name__ == "__main__": main()
