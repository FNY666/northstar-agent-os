"""Nth Fibonacci number. stdlib only."""

def fib(n):
    a, b = 0, 1
    for _ in range(n):
        a, b = b, a + b
    return a

def test():
    assert fib(0) == 0
    assert fib(1) == 1
    assert fib(10) == 55

if __name__ == '__main__':
    test(); print('ok')
