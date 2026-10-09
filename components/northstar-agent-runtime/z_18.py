"""z_18: mean."""
from __future__ import annotations
VERSION = "z_18.v1"
def mean(xs):
    return sum(xs)/len(xs)

def main() -> None:
    assert mean([1,2,3])==2.0
    assert mean([5,5])==5.0
    print('z_18 mean OK')

if __name__ == "__main__": main()
