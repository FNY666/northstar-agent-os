"""AD-module: cube -- Cube a number."""
from __future__ import annotations
VERSION = "ad_11.v1"
def cube(x: float) -> float:
    return x * x * x

def main() -> None:
    assert cube(2) == 8
    assert cube(-3) == -27
    assert cube(0) == 0
    print("ad_11 cube OK")
if __name__ == "__main__": main()
