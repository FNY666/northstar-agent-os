"""AD-module: factorial_n -- Factorial of a non-negative integer."""
from __future__ import annotations
VERSION = "ad_48.v1"
def factorial_n(n: int) -> int:
    r = 1
    for i in range(2, n + 1): r *= i
    return r

def main() -> None:
    assert factorial_n(0) == 1
    assert factorial_n(5) == 120
    assert factorial_n(1) == 1
    print("ad_48 factorial_n OK")
if __name__ == "__main__": main()
