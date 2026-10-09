"""z_04: uniq_keep."""
from __future__ import annotations
VERSION = "z_04.v1"
def uniq_keep(xs):
    seen=set(); out=[]
    for x in xs:
        if x not in seen:
            seen.add(x); out.append(x)
    return out

def main() -> None:
    assert uniq_keep([1,2,1,3,2]) == [1,2,3]
    assert uniq_keep([]) == []
    print('z_04 uniq_keep OK')

if __name__ == "__main__": main()
