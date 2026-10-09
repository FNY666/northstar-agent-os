"""count_bits utility."""

def count_bits(n):
    return bin(n).count('1')


def _self_test():
    assert count_bits(7) == 3
    assert count_bits(0) == 0


if __name__ == "__main__":
    _self_test()
    print("ap_33: OK")
