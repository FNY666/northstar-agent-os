"""ao_18: count_words utility (stdlib only)."""

def count_words(text):
    from collections import Counter
    return Counter(text.lower().split())


def _self_test():
    assert count_words('a b a')['a'] == 2, "count_words('a b a')['a'] == 2"
    assert len(count_words('')) == 0, "len(count_words('')) == 0"


if __name__ == "__main__":
    _self_test()
    print("ok")
