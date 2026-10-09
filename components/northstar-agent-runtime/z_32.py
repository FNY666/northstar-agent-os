"""z_32: get_path."""
from __future__ import annotations
VERSION = "z_32.v1"
def get_path(d,path,default=None):
    cur=d
    for p in path.split('.'):
        cur=cur.get(p) if isinstance(cur,dict) else None
        if cur is None: return default
    return cur

def main() -> None:
    assert get_path({'a':{'b':5}},'a.b')==5
    assert get_path({'a':1},'a.x','d')=='d'
    print('z_32 get_path OK')

if __name__ == "__main__": main()
