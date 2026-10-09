"""z_33: set_path."""
from __future__ import annotations
VERSION = "z_33.v1"
def set_path(d,path,val):
    cur=d
    *parts,last=path.split('.')
    for p in parts:
        cur=cur.setdefault(p,{})
    cur[last]=val; return d

def main() -> None:
    assert set_path({},'a.b',3)=={'a':{'b':3}}
    assert set_path({'a':{}},'a.b',9)=={'a':{'b':9}}
    print('z_33 set_path OK')

if __name__ == "__main__": main()
