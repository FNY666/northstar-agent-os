"""ao_15: variance utility (stdlib only)."""

def variance(xs):
    m = sum(xs) / len(xs)
    return sum((x - m) ** 2 for x in xs) / len(xs)


def _self_test():
    assert variance([2, 4, 4, 4, 5, 5, 7, 9]) == 4.0, 'variance([2, 4, 4, 4, 5, 5, 7, 9]) == 4.0'
    assert variance([1]) == 0.0, 'variance([1]) == 0.0'


if __name__ == "__main__":
    _self_test()
    print("ok")
