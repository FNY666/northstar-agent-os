"""strip_prefix utility."""

def strip_prefix(s, p):
    return s[len(p):] if s.startswith(p) else s


def _selftest():
    assert strip_prefix("foobar", "foo") == "bar"
    assert strip_prefix("bar", "foo") == "bar"


if __name__ == "__main__":
    _selftest()
    print("ok")
