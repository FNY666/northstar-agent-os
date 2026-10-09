"""ax_22: digits_sum utility (stdlib only)."""
def digits_sum(n):
    return sum(int(d) for d in str(abs(n)))


def run_tests():
    assert (digits_sum(123)) == 6, 'digits_sum(123)'
    assert (digits_sum(0)) == 0, 'digits_sum(0)'
    return True


if __name__ == "__main__":
    run_tests()
    print("ax_22: ok")
