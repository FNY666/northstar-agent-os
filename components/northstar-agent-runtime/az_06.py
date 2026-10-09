"""Take first n items. stdlib only."""

def take(xs, n):
    return xs[:n]

def test():
    assert take([1,2,3], 2) == [1,2]
    assert take([], 5) == []
    assert take([1], 10) == [1]

if __name__ == '__main__':
    test(); print('ok')
