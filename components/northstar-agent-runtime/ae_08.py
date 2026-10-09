"""AE-module: factorial -- n! for non-negative n."""
from __future__ import annotations
VERSION = "ae_08.v1"
def factorial(n: int) -> int:
    if n < 0:
        raise ValueError('negative')
    r = 1
    for i in range(2, n + 1):
        r *= i
    return r

def main() -> None:
    assert factorial(0) == 1
    assert factorial(5) == 120
    assert factorial(1) == 1
    print("ae_08 factorial OK")
if __name__ == "__main__": main()
