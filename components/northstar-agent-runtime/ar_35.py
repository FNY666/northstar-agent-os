"""Tiny utility: ar_35 (differences)."""

def diffs(xs):
    return [b-a for a,b in zip(xs,xs[1:])]

def self_test():
    assert diffs([1,3,6])==[2,3]
    assert diffs([5])==[]
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
