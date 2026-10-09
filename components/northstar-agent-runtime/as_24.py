"""dot_product utility."""

def dot_product(a, b):
    return sum(x * y for x, y in zip(a, b))


def _selftest():
    assert dot_product([1, 2], [3, 4]) == 11
    assert dot_product([], []) == 0


if __name__ == "__main__":
    _selftest()
    print("ok")
