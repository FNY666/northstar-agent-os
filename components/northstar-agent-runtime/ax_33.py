"""ax_33: rot13 utility (stdlib only)."""
def rot13(s):
    import codecs
    return codecs.encode(s, 'rot_13')


def run_tests():
    assert (rot13('hello')) == 'uryyb', "rot13('hello')"
    assert (rot13('uryyb')) == 'hello', "rot13('uryyb')"
    return True


if __name__ == "__main__":
    run_tests()
    print("ax_33: ok")
