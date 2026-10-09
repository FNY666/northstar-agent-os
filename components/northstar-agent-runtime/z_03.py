"""z_03: flatten_one."""
from __future__ import annotations
VERSION = "z_03.v1"
def flatten_one(xs):
    return [y for x in xs for y in x]

def main() -> None:
    assert flatten_one([[1,2],[3]]) == [1,2,3]
    assert flatten_one([[],[9]]) == [9]
    print('z_03 flatten_one OK')

if __name__ == "__main__": main()
