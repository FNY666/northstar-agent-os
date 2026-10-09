"""ak_49: Take every nth element."""

def every_nth(xs, n):
    return xs[::n]

if __name__ == '__main__':
    assert every_nth([1, 2, 3, 4, 5], 2) == [1, 3, 5]
    assert every_nth([], 3) == []
    print('ok')
