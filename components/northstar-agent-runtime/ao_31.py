"""ao_31: is_anagram utility (stdlib only)."""

def is_anagram(a, b):
    from collections import Counter
    return Counter(a.replace(' ', '').lower()) == Counter(b.replace(' ', '').lower())


def _self_test():
    assert is_anagram('listen', 'silent'), "is_anagram('listen', 'silent')"
    assert not is_anagram('abc', 'abd'), "not is_anagram('abc', 'abd')"


if __name__ == "__main__":
    _self_test()
    print("ok")
