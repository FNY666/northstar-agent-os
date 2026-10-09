"""z_45: running_total."""
from __future__ import annotations
VERSION = "z_45.v1"
def running_total(xs):
    t=0; out=[]
    for x in xs:
        t+=x; out.append(t)
    return out

def main() -> None:
    assert running_total([1,2,3])==[1,3,6]
    assert running_total([])==[]
    print('z_45 running_total OK')

if __name__ == "__main__": main()
