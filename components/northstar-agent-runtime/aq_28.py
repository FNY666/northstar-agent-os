"""Tiny utility: aq_28."""

digit_sum = lambda n: sum(int(c) for c in str(abs(n)))

def self_test():
    assert digit_sum(123) == 6
    assert digit_sum(-45) == 9
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
