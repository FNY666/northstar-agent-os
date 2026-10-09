"""AJ-19: Fibonacci."""
from __future__ import annotations
VERSION = "aj_19.v1"


import functools
@functools.lru_cache(maxsize=None)
def fib(n):
    return n if n < 2 else fib(n-1) + fib(n-2)

def main() -> None:
    assert fib(10) == 55
    assert fib(0) == 0
    print(f"aj_19 OK")
if __name__ == "__main__": main()
