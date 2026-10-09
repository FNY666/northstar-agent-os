"""z_41: dot."""
from __future__ import annotations
VERSION = "z_41.v1"
def dot(a,b):
    return sum(x*y for x,y in zip(a,b))

def main() -> None:
    assert dot([1,2],[3,4])==11
    assert dot([0],[5])==0
    print('z_41 dot OK')

if __name__ == "__main__": main()
