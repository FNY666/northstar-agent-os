"""anagram utility."""

def anagram(a, b):
    from collections import Counter
    return Counter(a) == Counter(b)


def _self_test():
    assert anagram('listen', 'silent')
    assert not anagram('a', 'b')


if __name__ == "__main__":
    _self_test()
    print("ap_36: OK")
