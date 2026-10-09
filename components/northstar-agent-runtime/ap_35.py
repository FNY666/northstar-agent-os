"""first_unique_char utility."""

def first_unique_char(s):
    from collections import Counter
    c = Counter(s)
    for i, ch in enumerate(s):
        if c[ch] == 1: return i
    return -1


def _self_test():
    assert first_unique_char('leetcode') == 0
    assert first_unique_char('aabb') == -1


if __name__ == "__main__":
    _self_test()
    print("ap_35: OK")
