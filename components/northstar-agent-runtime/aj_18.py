"""AJ-18: Factorial memo."""
from __future__ import annotations
VERSION = "aj_18.v1"


import functools
@functools.lru_cache(maxsize=None)
def fact(n):
    return 1 if n <= 1 else n * fact(n-1)

def main() -> None:
    assert fact(5) == 120
    assert fact(0) == 1
    print(f"aj_18 OK")
if __name__ == "__main__": main()
