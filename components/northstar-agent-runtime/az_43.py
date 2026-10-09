"""Check a subset of b. stdlib only."""

def is_subset(a, b):
    return set(a) <= set(b)

def test():
    assert is_subset([1,2],[1,2,3])
    assert not is_subset([1,9],[1,2,3])
    assert is_subset([], [1])

if __name__ == '__main__':
    test(); print('ok')
