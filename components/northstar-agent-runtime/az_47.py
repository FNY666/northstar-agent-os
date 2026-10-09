"""Matrix multiply. stdlib only."""

def matmul(a, b):
    bt = [list(r) for r in zip(*b)]
    return [[sum(x*y for x, y in zip(row, col)) for col in bt] for row in a]

def test():
    assert matmul([[1,2],[3,4]], [[5,6],[7,8]]) == [[19,22],[43,50]]
    assert matmul([[2]], [[3]]) == [[6]]

if __name__ == '__main__':
    test(); print('ok')
