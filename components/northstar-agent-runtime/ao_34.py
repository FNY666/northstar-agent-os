"""ao_34: merge_dicts utility (stdlib only)."""

def merge_dicts(a, b):
    return {**a, **b}


def _self_test():
    assert merge_dicts({'a':1}, {'b':2}) == {'a':1,'b':2}, "merge_dicts({'a':1}, {'b':2}) == {'a':1,'b':2}"
    assert merge_dicts({}, {}) == {}, 'merge_dicts({}, {}) == {}'


if __name__ == "__main__":
    _self_test()
    print("ok")
