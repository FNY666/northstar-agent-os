"""sum_digits utility."""

def sum_digits(n):
    return sum(int(d) for d in str(abs(n)))


def _self_test():
    assert sum_digits(123) == 6
    assert sum_digits(-45) == 9


if __name__ == "__main__":
    _self_test()
    print("ap_30: OK")
