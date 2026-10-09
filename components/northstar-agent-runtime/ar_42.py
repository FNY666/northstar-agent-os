"""Tiny utility: ar_42 (drop)."""

def drop(n,xs):
    return list(xs)[n:]

def self_test():
    assert drop(2,[1,2,3])==[3]
    assert drop(0,[1])==[1]
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
