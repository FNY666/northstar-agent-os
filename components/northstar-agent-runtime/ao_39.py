"""ao_39: is_sorted utility (stdlib only)."""

def is_sorted(xs):
    return all(a <= b for a, b in zip(xs, xs[1:]))


def _self_test():
    assert is_sorted([1,2,3]), 'is_sorted([1,2,3])'
    assert not is_sorted([3,1]), 'not is_sorted([3,1])'


if __name__ == "__main__":
    _self_test()
    print("ok")
