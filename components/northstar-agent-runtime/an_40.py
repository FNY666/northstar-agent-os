"""an_40: nth fibonacci. Stdlib only."""

def fib(n):
    a, b = 0, 1
    for _ in range(n):
        a, b = b, a + b
    return a

if __name__ == "__main__":
    assert fib(10) == 55
    assert fib(0) == 0
    print("ok")
