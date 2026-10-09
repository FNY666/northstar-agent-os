"""ax_21: sign utility (stdlib only)."""
def sign(x):
    return (x > 0) - (x < 0)


def run_tests():
    assert (sign(5)) == 1, 'sign(5)'
    assert (sign(-3)) == -1, 'sign(-3)'
    return True


if __name__ == "__main__":
    run_tests()
    print("ax_21: ok")
