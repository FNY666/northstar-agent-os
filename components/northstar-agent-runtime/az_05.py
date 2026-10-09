"""Sliding window pairs. stdlib only."""

def sliding(xs, k):
    return [xs[i:i+k] for i in range(len(xs)-k+1)]

def test():
    assert sliding([1,2,3,4], 2) == [[1,2],[2,3],[3,4]]
    assert sliding([1], 1) == [[1]]
    assert sliding([], 2) == []

if __name__ == '__main__':
    test(); print('ok')
