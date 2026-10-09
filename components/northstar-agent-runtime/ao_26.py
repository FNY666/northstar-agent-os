"""ao_26: sha256sum utility (stdlib only)."""

import hashlib
def sha256sum(s):
    return hashlib.sha256(s.encode()).hexdigest()


def _self_test():
    assert len(sha256sum('x')) == 64, "len(sha256sum('x')) == 64"
    assert sha256sum('') == 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', "sha256sum('') == 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'"


if __name__ == "__main__":
    _self_test()
    print("ok")
