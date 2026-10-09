"""distance utility."""

def distance(a, b):
    return sum((x - y) ** 2 for x, y in zip(a, b)) ** 0.5


def _selftest():
    assert distance((0, 0), (3, 4)) == 5.0
    assert distance((1,), (1,)) == 0.0


if __name__ == "__main__":
    _selftest()
    print("ok")
