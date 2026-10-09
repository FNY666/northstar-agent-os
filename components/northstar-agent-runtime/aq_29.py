"""Tiny utility: aq_29."""

reverse_int = lambda n: int(str(abs(n))[::-1]) * (-1 if n < 0 else 1)

def self_test():
    assert reverse_int(123) == 321
    assert reverse_int(-120) == -21
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
