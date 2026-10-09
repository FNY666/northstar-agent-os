"""AF-module: interleave -- Round-robin merge of lists; longer lists tail off."""
from __future__ import annotations
VERSION = "af_28"
def interleave(*xss: list) -> list:
    out: list = []
    for i in range(max((len(xs) for xs in xss), default=0)):
        for xs in xss:
            if i < len(xs):
                out.append(xs[i])
    return out

def main() -> None:
    assert interleave([1, 3], [2, 4, 5]) == [1, 2, 3, 4, 5]
    assert interleave() == []
    assert interleave([1], [2]) == [1, 2]
    print("af_28 interleave OK")
if __name__ == "__main__": main()
