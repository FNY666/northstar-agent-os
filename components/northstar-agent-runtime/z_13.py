"""z_13: factorial."""
from __future__ import annotations
VERSION = "z_13.v1"
def factorial(n):
    r=1
    for i in range(2,n+1): r*=i
    return r

def main() -> None:
    assert factorial(5)==120
    assert factorial(0)==1
    print('z_13 factorial OK')

if __name__ == "__main__": main()
