"""AJ-36: Retry timer backoff."""
from __future__ import annotations
VERSION = "aj_36.v1"


def backoff(attempt, base=0.5, cap=60.0):
    return min(cap, base * (2 ** attempt))

def main() -> None:
    assert backoff(0) == 0.5 and backoff(3) == 4.0
    assert backoff(100) == 60.0
    print(f"aj_36 OK")
if __name__ == "__main__": main()
