"""at_34: mode -- Most common item."""
from __future__ import annotations
VERSION = "at_34.v1"
def mode(xs):
    return max(set(xs), key=xs.count) if xs else None

def main() -> None:
    assert mode([1, 2, 2]) == 2
    assert mode([]) is None
    print("at_34 mode OK")
if __name__ == "__main__": main()
