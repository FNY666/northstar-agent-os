"""Tiny utility: aq_15."""

index_of = lambda xs, v: next((i for i, x in enumerate(xs) if x == v), -1)

def self_test():
    assert index_of([5,6,7],6) == 1
    assert index_of([1],9) == -1
    return True

if __name__ == "__main__":
    assert self_test()
    print("ok")
