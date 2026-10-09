"""ao_50: sign utility (stdlib only)."""

def sign(x):
    return (x > 0) - (x < 0)


def _self_test():
    assert sign(5) == 1, 'sign(5) == 1'
    assert sign(-3) == -1, 'sign(-3) == -1'
    assert sign(0) == 0, 'sign(0) == 0'


if __name__ == "__main__":
    _self_test()
    print("ok")
