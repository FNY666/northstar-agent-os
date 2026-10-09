"""lerp utility."""

def lerp(a, b, t):
    return a + (b - a) * t


def _selftest():
    assert lerp(0, 10, 0.5) == 5.0
    assert lerp(0, 10, 0) == 0


if __name__ == "__main__":
    _selftest()
    print("ok")
