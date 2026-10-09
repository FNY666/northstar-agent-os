"""AJ-38: Clamp."""
from __future__ import annotations
VERSION = "aj_38.v1"


def clamp(x, lo, hi):
    return max(lo, min(hi, x))

def main() -> None:
    assert clamp(5, 1, 10) == 5 and clamp(-1, 1, 10) == 1
    assert clamp(99, 1, 10) == 10
    print(f"aj_38 OK")
if __name__ == "__main__": main()
