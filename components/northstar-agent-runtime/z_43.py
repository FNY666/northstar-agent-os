"""z_43: transpose."""
from __future__ import annotations
VERSION = "z_43.v1"
def transpose(M):
    return [list(r) for r in zip(*M)]

def main() -> None:
    assert transpose([[1,2],[3,4]])==[[1,3],[2,4]]
    assert transpose([[1,2,3]])==[[1],[2],[3]]
    print('z_43 transpose OK')

if __name__ == "__main__": main()
