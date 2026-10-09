"""ax_05: count_vowels utility (stdlib only)."""
def count_vowels(s):
    return sum(1 for c in s.lower() if c in 'aeiou')


def run_tests():
    assert (count_vowels('hello')) == 2, "count_vowels('hello')"
    assert (count_vowels('xyz')) == 0, "count_vowels('xyz')"
    return True


if __name__ == "__main__":
    run_tests()
    print("ax_05: ok")
