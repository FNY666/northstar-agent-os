"""ak_27: Second largest number."""

def second_largest(xs):
    u = sorted(set(xs))
    return u[-2] if len(u) >= 2 else None

if __name__ == '__main__':
    assert second_largest([1, 5, 3, 5]) == 3
    assert second_largest([1]) is None
    print('ok')
