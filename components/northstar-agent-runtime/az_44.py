"""Zip with fillvalue. stdlib only."""

def zip_long(a, b, fill=None):
    n = max(len(a), len(b))
    return [(a[i] if i < len(a) else fill, b[i] if i < len(b) else fill) for i in range(n)]

def test():
    assert zip_long([1,2],[3],0) == [(1,3),(2,0)]
    assert zip_long([],[]) == []
    assert zip_long([1],[2]) == [(1,2)]

if __name__ == '__main__':
    test(); print('ok')
