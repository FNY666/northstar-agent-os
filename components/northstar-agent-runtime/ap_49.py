"""round_to utility."""

def round_to(x, n):
    return round(x, n)


def _self_test():
    assert round_to(3.14159, 2) == 3.14
    assert round_to(2.5, 0) == 2.0


if __name__ == "__main__":
    _self_test()
    print("ap_49: OK")
