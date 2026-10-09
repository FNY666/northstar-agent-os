"""is_power_of_two utility."""

def is_power_of_two(n):
    return n > 0 and (n & (n-1)) == 0


def _self_test():
    assert is_power_of_two(8)
    assert not is_power_of_two(6)


if __name__ == "__main__":
    _self_test()
    print("ap_32: OK")
