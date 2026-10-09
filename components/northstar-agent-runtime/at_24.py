"""at_24: words -- Split s into words."""
from __future__ import annotations
VERSION = "at_24.v1"
def words(s):
    return s.split()

def main() -> None:
    assert words('a b') == ['a', 'b']
    assert words('') == []
    print("at_24 words OK")
if __name__ == "__main__": main()
