"""ao_05: factorial utility (stdlib only)."""

def factorial(n):
    r = 1
    for i in range(2, n + 1): r *= i
    return r


def _self_test():
    assert factorial(5) == 120, 'factorial(5) == 120'
    assert factorial(0) == 1, 'factorial(0) == 1'


if __name__ == "__main__":
    _self_test()
    print("ok")
