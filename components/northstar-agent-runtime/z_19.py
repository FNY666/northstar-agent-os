"""z_19: variance."""
from __future__ import annotations
VERSION = "z_19.v1"
def variance(xs):
    m=sum(xs)/len(xs)
    return sum((x-m)**2 for x in xs)/len(xs)

def main() -> None:
    assert abs(variance([1,2,3,4]))==1.25
    assert variance([7,7])==0
    print('z_19 variance OK')

if __name__ == "__main__": main()
