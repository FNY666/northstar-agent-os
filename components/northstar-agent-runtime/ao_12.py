"""ao_12: mode utility (stdlib only)."""

def mode(xs):
    return max(set(xs), key=xs.count)


def _self_test():
    assert mode([1, 2, 2, 3]) == 2, 'mode([1, 2, 2, 3]) == 2'
    assert mode([5]) == 5, 'mode([5]) == 5'


if __name__ == "__main__":
    _self_test()
    print("ok")
