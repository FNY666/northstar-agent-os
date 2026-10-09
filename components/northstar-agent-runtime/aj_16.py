"""AJ-16: Prime sieve."""
from __future__ import annotations
VERSION = "aj_16.v1"


def sieve(n):
    s = [True]*(n+1); s[0]=s[1]=False
    for i in range(2, int(n**0.5)+1):
        if s[i]: s[i*i::i] = [False]*len(s[i*i::i])
    return [i for i, p in enumerate(s) if p]

def main() -> None:
    assert sieve(10) == [2,3,5,7]
    assert sieve(2) == [2]
    print(f"aj_16 OK")
if __name__ == "__main__": main()
