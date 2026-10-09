"""Tiny utility: ar_40 (unique sorted)."""

def uniq_sorted(xs):
    return sorted(set(xs))

def self_test():
    assert uniq_sorted([3,1,2,1])==[1,2,3]
    assert uniq_sorted([])==[]
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
