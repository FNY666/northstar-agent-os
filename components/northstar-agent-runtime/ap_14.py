"""dict_merge utility."""

def dict_merge(*ds):
    out = {}
    for d in ds:
        out.update(d)
    return out


def _self_test():
    assert dict_merge({'a':1}, {'b':2}) == {'a':1,'b':2}
    assert dict_merge() == {}


if __name__ == "__main__":
    _self_test()
    print("ap_14: OK")
