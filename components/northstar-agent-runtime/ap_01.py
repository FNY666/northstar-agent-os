"""clamp utility."""

def clamp(v, lo, hi):
    return max(lo, min(hi, v))


def _self_test():
    assert clamp(5, 1, 10) == 5
    assert clamp(-1, 0, 3) == 0
    assert clamp(9, 0, 3) == 3


if __name__ == "__main__":
    _self_test()
    print("ap_01: OK")
