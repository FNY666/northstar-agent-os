"""Tiny utility: ar_41 (take)."""

def take(n,xs):
    return list(xs)[:n]

def self_test():
    assert take(2,[1,2,3])==[1,2]
    assert take(9,[1])==[1]
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
