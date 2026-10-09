"""z_47: bsearch."""
from __future__ import annotations
VERSION = "z_47.v1"
def bsearch(xs,v):
    lo,hi=0,len(xs)-1
    while lo<=hi:
        m=(lo+hi)//2
        if xs[m]==v: return m
        lo,hi=(m+1,hi) if xs[m]<v else (lo,m-1)
    return -1

def main() -> None:
    assert bsearch([1,3,5,7],5)==2
    assert bsearch([1,3,5],4)==-1
    print('z_47 bsearch OK')

if __name__ == "__main__": main()
