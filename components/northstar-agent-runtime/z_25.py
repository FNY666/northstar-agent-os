"""z_25: caesar."""
from __future__ import annotations
VERSION = "z_25.v1"
def caesar(s,shift):
    out=[]
    for c in s:
        if c.isalpha():
            b='A' if c.isupper() else 'a'
            out.append(chr((ord(c)-ord(b)+shift)%26+ord(b)))
        else: out.append(c)
    return ''.join(out)

def main() -> None:
    assert caesar('abc',1)=='bcd'
    assert caesar('Zz',1)=='Aa'
    print('z_25 caesar OK')

if __name__ == "__main__": main()
