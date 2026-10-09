"""AD-module: is_positive -- Check if a number is strictly positive."""
from __future__ import annotations
VERSION = "ad_05.v1"
def is_positive(x: float) -> bool:
    return x > 0

def main() -> None:
    assert is_positive(1) is True
    assert is_positive(-1) is False
    assert is_positive(0) is False
    print("ad_05 is_positive OK")
if __name__ == "__main__": main()
