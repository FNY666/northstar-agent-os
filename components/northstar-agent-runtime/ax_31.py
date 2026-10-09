"""ax_31: word_count utility (stdlib only)."""
def word_count(s):
    return len(s.split())


def run_tests():
    assert (word_count('a b c')) == 3, "word_count('a b c')"
    assert (word_count('')) == 0, "word_count('')"
    return True


if __name__ == "__main__":
    run_tests()
    print("ax_31: ok")
