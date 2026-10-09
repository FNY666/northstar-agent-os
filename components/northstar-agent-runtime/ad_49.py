"""AD-module: fib_n -- Nth Fibonacci number (0-indexed)."""
from __future__ import annotations
VERSION = "ad_49.v1"
def fib_n(n: int) -> int:
    a, b = 0, 1
    for _ in range(n): a, b = b, a + b
    return a

def main() -> None:
    assert fib_n(0) == 0
    assert fib_n(7) == 13
    assert fib_n(10) == 55
    print("ad_49 fib_n OK")
if __name__ == "__main__": main()
