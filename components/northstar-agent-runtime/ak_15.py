"""ak_15: Rotate a list by k."""

def rotate(xs, k):
    if not xs: return xs
    k %= len(xs)
    return xs[-k:] + xs[:-k] if k else list(xs)

if __name__ == '__main__':
    assert rotate([1, 2, 3], 1) == [3, 1, 2]
    assert rotate([1, 2], 0) == [1, 2]
    print('ok')
