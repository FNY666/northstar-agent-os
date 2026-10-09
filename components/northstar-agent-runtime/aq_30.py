"""Tiny utility: aq_30."""

is_pal_num = lambda n: str(abs(n)) == str(abs(n))[::-1]

def self_test():
    assert is_pal_num(121)
    assert not is_pal_num(123)
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
