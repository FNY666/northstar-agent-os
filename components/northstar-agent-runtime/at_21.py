"""at_21: title -- Title-case words."""
from __future__ import annotations
VERSION = "at_21.v1"
def title(s):
    return ' '.join(w[:1].upper() + w[1:] for w in s.split(' '))

def main() -> None:
    assert title('a b') == 'A B'
    assert title('x') == 'X'
    print("at_21 title OK")
if __name__ == "__main__": main()
