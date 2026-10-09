"""ax_23: is_even utility (stdlib only)."""
def is_even(n):
    return n % 2 == 0


def run_tests():
    assert (is_even(4)) == True, 'is_even(4)'
    assert (is_even(3)) == False, 'is_even(3)'
    return True


if __name__ == "__main__":
    run_tests()
    print("ax_23: ok")
