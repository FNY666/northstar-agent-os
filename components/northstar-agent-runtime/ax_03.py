"""ax_03: reverse_words utility (stdlib only)."""
def reverse_words(text):
    return ' '.join(reversed(text.split()))


def run_tests():
    assert (reverse_words('hello world')) == 'world hello', "reverse_words('hello world')"
    assert (reverse_words('a')) == 'a', "reverse_words('a')"
    return True


if __name__ == "__main__":
    run_tests()
    print("ax_03: ok")
