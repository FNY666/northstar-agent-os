"""count_char utility."""

def count_char(s, c):
    return s.count(c)


def _selftest():
    assert count_char("hello", "l") == 2
    assert count_char("abc", "z") == 0


if __name__ == "__main__":
    _selftest()
    print("ok")
