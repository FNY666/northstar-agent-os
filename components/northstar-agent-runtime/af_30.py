"""AF-module: batched -- Yield successive n-sized batches from an iterable."""
from __future__ import annotations
VERSION = "af_30"
def batched(xs, n: int):
    if n <= 0:
        raise ValueError('n must be positive')
    it = iter(xs)
    while True:
        b = [x for _, x in zip(range(n), it)]
        if not b:
            return
        yield b

def main() -> None:
    assert list(batched([1, 2, 3, 4, 5], 2)) == [[1, 2], [3, 4], [5]]
    assert list(batched([], 3)) == []
    assert list(batched('abcd', 4)) == [['a', 'b', 'c', 'd']]
    print("af_30 batched OK")
if __name__ == "__main__": main()
