"""Transpose matrix. stdlib only."""

def transpose(m):
    return [list(r) for r in zip(*m)]

def test():
    assert transpose([[1,2],[3,4]]) == [[1,3],[2,4]]
    assert transpose([[1]]) == [[1]]
    assert transpose([]) == []

if __name__ == '__main__':
    test(); print('ok')
