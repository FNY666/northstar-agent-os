"""ak_30: Transpose a matrix."""

def transpose(m):
    return [list(r) for r in zip(*m)]

if __name__ == '__main__':
    assert transpose([[1, 2], [3, 4]]) == [[1, 3], [2, 4]]
    assert transpose([]) == []
    print('ok')
