"""ax_20: clamp utility (stdlib only)."""
def clamp(v, lo, hi):
    return max(lo, min(hi, v))


def run_tests():
    assert (clamp(5, 0, 10)) == 5, 'clamp(5, 0, 10)'
    assert (clamp(15, 0, 10)) == 10, 'clamp(15, 0, 10)'
    return True


if __name__ == "__main__":
    run_tests()
    print("ax_20: ok")
