"""AD-module: is_negative -- Check if a number is strictly negative."""
from __future__ import annotations
VERSION = "ad_06.v1"
def is_negative(x: float) -> bool:
    return x < 0

def main() -> None:
    assert is_negative(-1) is True
    assert is_negative(1) is False
    assert is_negative(0) is False
    print("ad_06 is_negative OK")
if __name__ == "__main__": main()
