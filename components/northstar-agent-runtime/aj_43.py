"""AJ-43: Softmax."""
from __future__ import annotations
VERSION = "aj_43.v1"


import math
def softmax(xs):
    m = max(xs); ex = [math.exp(x-m) for x in xs]; s = sum(ex)
    return [e/s for e in ex]

def main() -> None:
    assert abs(sum(softmax([1,2,3]))-1.0) < 1e-9
    assert softmax([5])[0] == 1.0
    print(f"aj_43 OK")
if __name__ == "__main__": main()
