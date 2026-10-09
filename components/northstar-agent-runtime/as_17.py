"""word_count utility."""

def word_count(s):
    return len(s.split())


def _selftest():
    assert word_count("hello world") == 2
    assert word_count("") == 0


if __name__ == "__main__":
    _selftest()
    print("ok")
