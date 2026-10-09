"""au_07: Factorial of n."""
def factorial(n):
    """Return n! (raises on negative)."""
    if n < 0:
        raise ValueError('negative')
    r = 1
    for i in range(2, n+1):
        r *= i
    return r

def _run_tests():
    assert factorial(5) == 120
    assert factorial(0) == 1

if __name__ == "__main__":
    _run_tests()
    print("au_07 OK")
