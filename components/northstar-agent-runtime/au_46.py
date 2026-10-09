"""au_46: Sum of arithmetic range."""
def range_sum(a, b):
    """Sum of integers from a to b inclusive."""
    if a > b:
        a, b = b, a
    n = b - a + 1
    return n * (a + b) // 2

def _run_tests():
    assert range_sum(1, 10) == 55
    assert range_sum(5, 5) == 5

if __name__ == "__main__":
    _run_tests()
    print("au_46 OK")
