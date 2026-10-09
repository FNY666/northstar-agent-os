"""Euclidean norm. stdlib only."""

def norm2(v):
    return sum(x*x for x in v) ** 0.5

def test():
    assert norm2([3,4]) == 5.0
    assert norm2([]) == 0.0
    assert norm2([1]) == 1.0

if __name__ == '__main__':
    test(); print('ok')
