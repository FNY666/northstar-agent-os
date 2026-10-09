"""ax_32: unique_words utility (stdlib only)."""
def unique_words(s):
    return sorted(set(s.lower().split()))


def run_tests():
    assert (unique_words('b a b')) == ['a', 'b'], "unique_words('b a b')"
    assert (unique_words('')) == [], "unique_words('')"
    return True


if __name__ == "__main__":
    run_tests()
    print("ax_32: ok")
