"""Drop first n items. stdlib only."""

def drop(xs, n):
    return xs[n:]

def test():
    assert drop([1,2,3], 2) == [3]
    assert drop([], 5) == []
    assert drop([1], 10) == []

if __name__ == '__main__':
    test(); print('ok')
