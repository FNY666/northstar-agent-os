"""fib utility."""

def fib(n):
    a, b = 0, 1
    for _ in range(n):
        a, b = b, a+b
    return a


def _self_test():
    assert fib(0) == 0
    assert fib(10) == 55


if __name__ == "__main__":
    _self_test()
    print("ap_08: OK")
