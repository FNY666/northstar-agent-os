"""ax_38: md5 utility (stdlib only)."""
def md5(s):
    import hashlib
    return hashlib.md5(s.encode()).hexdigest()


def run_tests():
    assert (md5('abc')) == '900150983cd24fb0d6963f7d28e17f72', "md5('abc')"
    assert (len(md5(''))) == 32, "len(md5(''))"
    return True


if __name__ == "__main__":
    run_tests()
    print("ax_38: ok")
