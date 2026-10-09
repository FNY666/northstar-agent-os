"""Check sorted ascending. stdlib only."""

def is_sorted(xs):
    return all(a <= b for a, b in zip(xs, xs[1:]))

def test():
    assert is_sorted([1,2,3])
    assert not is_sorted([3,1,2])
    assert is_sorted([])

if __name__ == '__main__':
    test(); print('ok')
