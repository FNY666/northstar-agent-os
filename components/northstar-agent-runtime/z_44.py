"""z_44: linspace."""
from __future__ import annotations
VERSION = "z_44.v1"
def linspace(a,b,n):
    return [a+(b-a)*i/(n-1) for i in range(n)] if n>1 else [a]

def main() -> None:
    assert linspace(0,1,3)==[0.0,0.5,1.0]
    assert linspace(5,5,1)==[5]
    print('z_44 linspace OK')

if __name__ == "__main__": main()
