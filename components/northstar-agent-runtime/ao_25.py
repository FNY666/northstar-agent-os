"""ao_25: md5sum utility (stdlib only)."""

import hashlib
def md5sum(s):
    return hashlib.md5(s.encode()).hexdigest()


def _self_test():
    assert len(md5sum('x')) == 32, "len(md5sum('x')) == 32"
    assert md5sum('') == 'd41d8cd98f00b204e9800998ecf8427e', "md5sum('') == 'd41d8cd98f00b204e9800998ecf8427e'"


if __name__ == "__main__":
    _self_test()
    print("ok")
