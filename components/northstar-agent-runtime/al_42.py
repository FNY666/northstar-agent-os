"""al_42: simple utility module (stdlib only)."""

def product_three(a, b, c):
    return a * b * c

def _run_tests():
    assert product_three(2, 3, 4) == 24, 'al_42'
    assert product_three(1, 0, 5) == 0, 'al_42'
    return True

if __name__ == "__main__":
    _run_tests()
    print("al_42: all tests passed")
