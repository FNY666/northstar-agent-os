"""Tiny utility: aq_04."""

unique = lambda xs: list(dict.fromkeys(xs))

def self_test():
    assert unique([1,2,2,3,1]) == [1,2,3]
    assert unique([]) == []
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
