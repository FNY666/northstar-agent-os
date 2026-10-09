"""AD-module: halve -- Halve a number."""
from __future__ import annotations
VERSION = "ad_09.v1"
def halve(x: float) -> float:
    return x / 2

def main() -> None:
    assert halve(4) == 2.0
    assert halve(5) == 2.5
    assert halve(0) == 0.0
    print("ad_09 halve OK")
if __name__ == "__main__": main()
