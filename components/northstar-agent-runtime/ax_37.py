"""ax_37: sha256 utility (stdlib only)."""
def sha256(s):
    import hashlib
    return hashlib.sha256(s.encode()).hexdigest()


def run_tests():
    assert (sha256('abc')) == 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad', "sha256('abc')"
    assert (len(sha256(''))) == 64, "len(sha256(''))"
    return True


if __name__ == "__main__":
    run_tests()
    print("ax_37: ok")
