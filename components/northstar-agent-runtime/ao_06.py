"""ao_06: fib utility (stdlib only)."""

def fib(n):
    a, b = 0, 1
    for _ in range(n): a, b = b, a + b
    return a


def _self_test():
    assert fib(10) == 55, 'fib(10) == 55'
    assert fib(0) == 0, 'fib(0) == 0'
    assert fib(1) == 1, 'fib(1) == 1'


if __name__ == "__main__":
    _self_test()
    print("ok")
