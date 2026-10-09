"""ak_44: Check sorted ascending."""

def is_sorted(xs):
    return all(a <= b for a, b in zip(xs, xs[1:]))

if __name__ == '__main__':
    assert is_sorted([1, 2, 2, 3])
    assert not is_sorted([3, 1])
    print('ok')
