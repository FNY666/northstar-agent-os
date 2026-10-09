"""ax_25: digit_count utility (stdlib only)."""
def digit_count(n):
    return len(str(abs(int(n))))


def run_tests():
    assert (digit_count(12345)) == 5, 'digit_count(12345)'
    assert (digit_count(0)) == 1, 'digit_count(0)'
    return True


if __name__ == "__main__":
    run_tests()
    print("ax_25: ok")
