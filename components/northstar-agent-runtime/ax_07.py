"""ax_07: fib utility (stdlib only)."""
def fib(n):
    a, b = 0, 1
    for _ in range(n): a, b = b, a + b
    return a


def run_tests():
    assert (fib(10)) == 55, 'fib(10)'
    assert (fib(0)) == 0, 'fib(0)'
    return True


if __name__ == "__main__":
    run_tests()
    print("ax_07: ok")
