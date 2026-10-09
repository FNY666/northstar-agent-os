"""Rotate list left by k. stdlib only."""

def rotate(xs, k):
    if not xs: return xs
    k %= len(xs)
    return xs[k:] + xs[:k]

def test():
    assert rotate([1,2,3], 1) == [2,3,1]
    assert rotate([1,2,3], 0) == [1,2,3]
    assert rotate([], 3) == []

if __name__ == '__main__':
    test(); print('ok')
