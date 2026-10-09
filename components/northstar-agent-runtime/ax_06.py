"""ax_06: factorial utility (stdlib only)."""
def factorial(n):
    if n < 0: raise ValueError('negative')
    r = 1
    for i in range(2, n + 1): r *= i
    return r


def run_tests():
    assert (factorial(5)) == 120, 'factorial(5)'
    assert (factorial(0)) == 1, 'factorial(0)'
    return True


if __name__ == "__main__":
    run_tests()
    print("ax_06: ok")
