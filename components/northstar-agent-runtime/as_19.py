"""mean utility."""

def mean(xs):
    return sum(xs) / len(xs) if xs else 0.0


def _selftest():
    assert mean([1, 2, 3]) == 2.0
    assert mean([]) == 0.0


if __name__ == "__main__":
    _selftest()
    print("ok")
