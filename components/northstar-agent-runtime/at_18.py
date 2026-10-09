"""at_18: lower -- Lowercase a string."""
from __future__ import annotations
VERSION = "at_18.v1"
def lower(s):
    return s.lower()

def main() -> None:
    assert lower('AB') == 'ab'
    assert lower('X') == 'x'
    print("at_18 lower OK")
if __name__ == "__main__": main()
