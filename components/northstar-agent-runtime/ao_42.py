"""ao_42: rotate_left utility (stdlib only)."""

def rotate_left(xs, k):
    k %= len(xs) if xs else 1
    return xs[k:] + xs[:k]


def _self_test():
    assert rotate_left([1,2,3,4], 1) == [2,3,4,1], 'rotate_left([1,2,3,4], 1) == [2,3,4,1]'
    assert rotate_left([], 3) == [], 'rotate_left([], 3) == []'


if __name__ == "__main__":
    _self_test()
    print("ok")
