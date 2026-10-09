"""z_46: diff_seq."""
from __future__ import annotations
VERSION = "z_46.v1"
def diff_seq(xs):
    return [b-a for a,b in zip(xs,xs[1:])]

def main() -> None:
    assert diff_seq([1,3,6,10])==[2,3,4]
    assert diff_seq([5])==[]
    print('z_46 diff_seq OK')

if __name__ == "__main__": main()
