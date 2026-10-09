"""ao_22: rot13 utility (stdlib only)."""

import codecs
def rot13(s):
    return codecs.encode(s, 'rot_13')


def _self_test():
    assert rot13('hello') == 'uryyb', "rot13('hello') == 'uryyb'"
    assert rot13(rot13('abc')) == 'abc', "rot13(rot13('abc')) == 'abc'"


if __name__ == "__main__":
    _self_test()
    print("ok")
