"""z_48: insert_sorted."""
from __future__ import annotations
VERSION = "z_48.v1"
def insert_sorted(xs,v):
    import bisect
    bisect.insort(xs,v); return xs

def main() -> None:
    assert insert_sorted([1,3,5],4)==[1,3,4,5]
    assert insert_sorted([],2)==[2]
    print('z_48 insert_sorted OK')

if __name__ == "__main__": main()
