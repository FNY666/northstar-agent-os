"""z_20: percentile."""
from __future__ import annotations
VERSION = "z_20.v1"
def percentile(xs,p):
    s=sorted(xs); k=min(len(s)-1,int(p/100*len(s)))
    return s[k]

def main() -> None:
    assert percentile([1,2,3,4,5],50)==3
    assert percentile([1,2,3],100)==3
    print('z_20 percentile OK')

if __name__ == "__main__": main()
