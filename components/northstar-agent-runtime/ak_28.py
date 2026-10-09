"""ak_28: Interleave two lists."""

def interleave(a, b):
    out = []
    for x, y in zip(a, b):
        out += [x, y]
    return out + list(a[len(b):]) + list(b[len(a):])

if __name__ == '__main__':
    assert interleave([1, 2], ['a', 'b']) == [1, 'a', 2, 'b']
    assert interleave([1], []) == [1]
    print('ok')
