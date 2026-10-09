"""Factorial. stdlib only."""

def factorial(n):
    r = 1
    for i in range(2, n+1):
        r *= i
    return r

def test():
    assert factorial(0) == 1
    assert factorial(5) == 120
    assert factorial(1) == 1

if __name__ == '__main__':
    test(); print('ok')
