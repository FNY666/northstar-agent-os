"""strip_suffix utility."""

def strip_suffix(s, p):
    return s[:-len(p)] if p and s.endswith(p) else s


def _selftest():
    assert strip_suffix("foobar", "bar") == "foo"
    assert strip_suffix("foo", "x") == "foo"


if __name__ == "__main__":
    _selftest()
    print("ok")
