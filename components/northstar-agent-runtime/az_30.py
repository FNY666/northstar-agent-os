"""Hamming distance. stdlib only."""

def hamming(a, b):
    if len(a) != len(b):
        raise ValueError('lengths differ')
    return sum(x != y for x, y in zip(a, b))

def test():
    assert hamming('101', '100') == 1
    assert hamming('abc', 'abc') == 0
    assert hamming('', '') == 0

if __name__ == '__main__':
    test(); print('ok')
