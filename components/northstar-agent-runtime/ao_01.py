"""ao_01: clamp utility (stdlib only)."""

def clamp(x, lo, hi):
    return max(lo, min(hi, x))


def _self_test():
    assert clamp(5, 0, 10) == 5, 'clamp(5, 0, 10) == 5'
    assert clamp(-3, 0, 10) == 0, 'clamp(-3, 0, 10) == 0'
    assert clamp(99, 0, 10) == 10, 'clamp(99, 0, 10) == 10'


if __name__ == "__main__":
    _self_test()
    print("ok")
