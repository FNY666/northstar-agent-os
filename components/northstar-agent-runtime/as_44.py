"""to_camel utility."""

def to_camel(s):
    p = s.split('_')
    return p[0] + ''.join(w.capitalize() for w in p[1:])


def _selftest():
    assert to_camel("hello_world") == "helloWorld"
    assert to_camel("x") == "x"


if __name__ == "__main__":
    _selftest()
    print("ok")
