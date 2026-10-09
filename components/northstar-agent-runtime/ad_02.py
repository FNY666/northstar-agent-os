"""AD-module: is_odd -- Check if an integer is odd."""
from __future__ import annotations
VERSION = "ad_02.v1"
def is_odd(n: int) -> bool:
    return n % 2 == 1

def main() -> None:
    assert is_odd(3) is True
    assert is_odd(8) is False
    assert is_odd(-5) is True
    print("ad_02 is_odd OK")
if __name__ == "__main__": main()
