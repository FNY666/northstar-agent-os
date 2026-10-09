"""count_vowels utility."""

def count_vowels(s):
    return sum(1 for c in s.lower() if c in 'aeiou')


def _selftest():
    assert count_vowels("hello") == 2
    assert count_vowels("xyz") == 0


if __name__ == "__main__":
    _selftest()
    print("ok")
