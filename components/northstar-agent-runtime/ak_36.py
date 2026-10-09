"""ak_36: Hamming distance."""

def hamming(a, b):
    return sum(x != y for x, y in zip(a, b)) + abs(len(a) - len(b))

if __name__ == '__main__':
    assert hamming('karolin', 'kathrin') == 3
    assert hamming('abc', 'abc') == 0
    print('ok')
