"""Yield overlapping pairs from a sequence."""
def pairwise(seq):
    it = iter(seq)
    try:
        prev = next(it)
    except StopIteration:
        return
    for cur in it:
        yield prev, cur
        prev = cur
if __name__ == "__main__":
    assert list(pairwise([1, 2, 3])) == [(1, 2), (2, 3)]
    assert list(pairwise([1])) == []
    assert list(pairwise([])) == []
    print("ok")
