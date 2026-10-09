"""AD-module: is_zero -- Check if a number is zero."""
from __future__ import annotations
VERSION = "ad_07.v1"
def is_zero(x: float) -> bool:
    return x == 0

def main() -> None:
    assert is_zero(0) is True
    assert is_zero(0.0) is True
    assert is_zero(1) is False
    print("ad_07 is_zero OK")
if __name__ == "__main__": main()
