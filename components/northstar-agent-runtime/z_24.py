"""z_24: reverse_words."""
from __future__ import annotations
VERSION = "z_24.v1"
def reverse_words(s):
    return ' '.join(s.split()[::-1])

def main() -> None:
    assert reverse_words('a b c')=='c b a'
    assert reverse_words('x')=='x'
    print('z_24 reverse_words OK')

if __name__ == "__main__": main()
