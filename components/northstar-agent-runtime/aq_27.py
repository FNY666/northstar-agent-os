"""Tiny utility: aq_27."""

digital_root = lambda n: 1 + (n-1) % 9 if n else 0

def self_test():
    assert digital_root(38) == 2
    assert digital_root(0) == 0
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
