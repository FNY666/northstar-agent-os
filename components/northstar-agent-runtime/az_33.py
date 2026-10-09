"""List difference a-b. stdlib only."""

def difference(a, b):
    sb = set(b)
    return [x for x in a if x not in sb]

def test():
    assert difference([1,2,3],[2]) == [1,3]
    assert difference([1],[2]) == [1]
    assert difference([], [1]) == []

if __name__ == '__main__':
    test(); print('ok')
