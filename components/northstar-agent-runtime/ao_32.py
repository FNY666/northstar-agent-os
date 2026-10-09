"""ao_32: zip_dict utility (stdlib only)."""

def zip_dict(keys, vals):
    return dict(zip(keys, vals))


def _self_test():
    assert zip_dict(['a','b'], [1,2]) == {'a':1,'b':2}, "zip_dict(['a','b'], [1,2]) == {'a':1,'b':2}"
    assert zip_dict([], []) == {}, 'zip_dict([], []) == {}'


if __name__ == "__main__":
    _self_test()
    print("ok")
