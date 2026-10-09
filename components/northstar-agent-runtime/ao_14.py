"""ao_14: mean utility (stdlib only)."""

def mean(xs):
    return sum(xs) / len(xs)


def _self_test():
    assert mean([1, 2, 3]) == 2.0, 'mean([1, 2, 3]) == 2.0'
    assert mean([5]) == 5.0, 'mean([5]) == 5.0'


if __name__ == "__main__":
    _self_test()
    print("ok")
