"""at_43: isqrt -- Integer square root."""
from __future__ import annotations
VERSION = "at_43.v1"
def isqrt(n):
    return int(n ** 0.5)

def main() -> None:
    assert isqrt(16) == 4
    assert isqrt(15) == 3
    print("at_43 isqrt OK")
if __name__ == "__main__": main()
