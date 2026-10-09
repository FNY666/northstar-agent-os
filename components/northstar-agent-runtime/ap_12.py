"""count_words utility."""

def count_words(s):
    return len(s.split())


def _self_test():
    assert count_words('hello world') == 2
    assert count_words('') == 0


if __name__ == "__main__":
    _self_test()
    print("ap_12: OK")
