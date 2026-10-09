"""ao_33: invert_dict utility (stdlib only)."""

def invert_dict(d):
    return {v: k for k, v in d.items()}


def _self_test():
    assert invert_dict({'a': 1}) == {1: 'a'}, "invert_dict({'a': 1}) == {1: 'a'}"
    assert invert_dict({}) == {}, 'invert_dict({}) == {}'


if __name__ == "__main__":
    _self_test()
    print("ok")
