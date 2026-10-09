"""to_snake utility."""

def to_snake(s):
    return ''.join('_' + c.lower() if c.isupper() else c for c in s).lstrip('_')


def _selftest():
    assert to_snake("helloWorld") == "hello_world"
    assert to_snake("x") == "x"


if __name__ == "__main__":
    _selftest()
    print("ok")
