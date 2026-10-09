"""char_freq utility."""

def char_freq(s):
    f = {}
    for c in s:
        f[c] = f.get(c, 0) + 1
    return f


def _selftest():
    assert char_freq("aab") == {"a": 2, "b": 1}
    assert char_freq("") == {}


if __name__ == "__main__":
    _selftest()
    print("ok")
