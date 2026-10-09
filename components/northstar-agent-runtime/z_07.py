"""z_07: word_count."""
from __future__ import annotations
VERSION = "z_07.v1"
def word_count(s):
    return len(s.split())

def main() -> None:
    assert word_count('a b  c') == 3
    assert word_count('') == 0
    print('z_07 word_count OK')

if __name__ == "__main__": main()
