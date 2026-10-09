"""z_16: median."""
from __future__ import annotations
VERSION = "z_16.v1"
def median(xs):
    s=sorted(xs); n=len(s); mid=n//2
    return s[mid] if n%2 else (s[mid-1]+s[mid])/2

def main() -> None:
    assert median([3,1,2])==2
    assert median([1,2,3,4])==2.5
    print('z_16 median OK')

if __name__ == "__main__": main()
