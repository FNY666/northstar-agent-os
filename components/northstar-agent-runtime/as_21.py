"""clamp utility."""

def clamp(v, lo, hi):
    return max(lo, min(hi, v))


def _selftest():
    assert clamp(5, 0, 10) == 5
    assert clamp(-5, 0, 10) == 0
    assert clamp(15, 0, 10) == 10


if __name__ == "__main__":
    _selftest()
    print("ok")
