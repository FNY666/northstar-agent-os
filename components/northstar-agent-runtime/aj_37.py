"""AJ-37: Token bucket params."""
from __future__ import annotations
VERSION = "aj_37.v1"


def bucket_allow(tokens, capacity, rate, elapsed):
    return min(capacity, tokens + rate * elapsed)

def main() -> None:
    assert bucket_allow(1, 10, 2, 3) == 7
    assert bucket_allow(9, 10, 5, 10) == 10
    print(f"aj_37 OK")
if __name__ == "__main__": main()
