"""Group list by key fn. stdlib only."""

def group_by(xs, key):
    d = {}
    for x in xs:
        d.setdefault(key(x), []).append(x)
    return d

def test():
    assert group_by([1,2,3,4], lambda x: x % 2) == {1:[1,3], 0:[2,4]}
    assert group_by([], lambda x: x) == {}

if __name__ == '__main__':
    test(); print('ok')
