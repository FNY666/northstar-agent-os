"""au_23: Sum of decimal digits."""
def digit_sum(n):
    """Sum the decimal digits of |n|."""
    return sum(int(d) for d in str(abs(n)))

def _run_tests():
    assert digit_sum(123) == 6
    assert digit_sum(-45) == 9

if __name__ == "__main__":
    _run_tests()
    print("au_23 OK")
