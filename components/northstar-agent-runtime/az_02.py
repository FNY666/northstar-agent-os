"""Chunk list into n-sized pieces. stdlib only."""

def chunk(xs, n):
    return [xs[i:i+n] for i in range(0, len(xs), n)]

def test():
    assert chunk([1,2,3,4,5], 2) == [[1,2],[3,4],[5]]
    assert chunk([], 3) == []
    assert chunk([1], 5) == [[1]]

if __name__ == '__main__':
    test(); print('ok')
