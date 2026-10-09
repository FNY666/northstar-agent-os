"""ax_24: power utility (stdlib only)."""
def power(base, exp):
    return base ** exp


def run_tests():
    assert (power(2, 10)) == 1024, 'power(2, 10)'
    assert (power(5, 0)) == 1, 'power(5, 0)'
    return True


if __name__ == "__main__":
    run_tests()
    print("ax_24: ok")
