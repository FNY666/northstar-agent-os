"""at_13: fib -- Nth Fibonacci number."""
from __future__ import annotations
VERSION = "at_13.v1"
def fib(n):
    a, b = 0, 1
    for _ in range(n): a, b = b, a + b
    return a

def main() -> None:
    assert fib(6) == 8
    assert fib(0) == 0
    print("at_13 fib OK")
if __name__ == "__main__": main()
