"""digital_root utility."""

def digital_root(n):
    while n >= 10:
        n = sum(int(d) for d in str(n))
    return n


def _self_test():
    assert digital_root(38) == 2
    assert digital_root(5) == 5


if __name__ == "__main__":
    _self_test()
    print("ap_31: OK")
