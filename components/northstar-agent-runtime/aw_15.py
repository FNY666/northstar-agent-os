"""nth Fibonacci number (0-indexed)."""
def fib_n(n):
    a, b = 0, 1
    for _ in range(n):
        a, b = b, a + b
    return a
if __name__ == "__main__":
    assert fib_n(0) == 0
    assert fib_n(1) == 1
    assert fib_n(10) == 55
    print("ok")
