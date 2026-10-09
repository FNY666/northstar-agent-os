"""ak_35: Dot product."""

def dot(a, b):
    return sum(x * y for x, y in zip(a, b))

if __name__ == '__main__':
    assert dot([1, 2], [3, 4]) == 11
    assert dot([], []) == 0
    print('ok')
