"""invert_dict utility."""

def invert_dict(d):
    return {v: k for k, v in d.items()}


def _self_test():
    assert invert_dict({'a':1,'b':2}) == {1:'a',2:'b'}
    assert invert_dict({}) == {}


if __name__ == "__main__":
    _self_test()
    print("ap_15: OK")
