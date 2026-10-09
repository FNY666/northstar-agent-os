"""Nth Fibonacci number (fib(0)=0, fib(1)=1)."""
def fib(n):
    if n < 0:
        raise ValueError("negative")
    a, b = 0, 1
    for _ in range(n):
        a, b = b, a + b
    return a
if __name__ == "__main__":
    assert fib(0) == 0
    assert fib(10) == 55
    assert fib(1) == 1
    print("ok")
