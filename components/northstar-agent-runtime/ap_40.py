"""pad_center utility."""

def pad_center(s, w, fill=' '):
    return s.center(w, fill)


def _self_test():
    assert pad_center('a', 3) == ' a '
    assert pad_center('ab', 2) == 'ab'


if __name__ == "__main__":
    _self_test()
    print("ap_40: OK")
