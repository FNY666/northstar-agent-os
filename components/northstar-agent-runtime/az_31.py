"""List intersection. stdlib only."""

def intersect(a, b):
    sb = set(b)
    return [x for x in a if x in sb]

def test():
    assert intersect([1,2,3],[2,3,4]) == [2,3]
    assert intersect([], [1]) == []
    assert intersect([1],[1]) == [1]

if __name__ == '__main__':
    test(); print('ok')
