"""reverse_string utility."""

def reverse_string(s):
    return s[::-1]


def _selftest():
    assert reverse_string("hello") == "olleh"
    assert reverse_string("") == ""


if __name__ == "__main__":
    _selftest()
    print("ok")
