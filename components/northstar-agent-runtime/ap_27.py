"""repeat utility."""

def repeat(x, n):
    return [x]*n


def _self_test():
    assert repeat('a', 3) == ['a','a','a']
    assert repeat(1, 0) == []


if __name__ == "__main__":
    _self_test()
    print("ap_27: OK")
