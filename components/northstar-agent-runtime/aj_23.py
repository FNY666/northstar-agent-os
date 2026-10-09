"""AJ-23: Caesar cipher."""
from __future__ import annotations
VERSION = "aj_23.v1"


def caesar(s, k):
    out = []
    for c in s:
        if c.isalpha():
            b = ord('A') if c.isupper() else ord('a')
            out.append(chr((ord(c)-b+k) % 26 + b))
        else: out.append(c)
    return ''.join(out)

def main() -> None:
    assert caesar('abc',1) == 'bcd'
    assert caesar(caesar('Hi!',3),-3) == 'Hi!'
    print(f"aj_23 OK")
if __name__ == "__main__": main()
