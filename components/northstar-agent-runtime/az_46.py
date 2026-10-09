"""Dot product. stdlib only."""

def dot(a, b):
    return sum(x*y for x, y in zip(a, b))

def test():
    assert dot([1,2],[3,4]) == 11
    assert dot([],[]) == 0
    assert dot([5],[2]) == 10

if __name__ == '__main__':
    test(); print('ok')
