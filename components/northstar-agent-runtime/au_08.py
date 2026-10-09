"""au_08: Nth Fibonacci number."""
def fibonacci(n):
    """Return the nth Fibonacci number (0-based)."""
    a, b = 0, 1
    for _ in range(n):
        a, b = b, a+b
    return a

def _run_tests():
    assert fibonacci(10) == 55
    assert fibonacci(0) == 0

if __name__ == "__main__":
    _run_tests()
    print("au_08 OK")
