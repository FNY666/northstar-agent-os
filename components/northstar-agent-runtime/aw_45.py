"""First item matching pred, else default."""
def find_first(xs, pred, default=None):
    for x in xs:
        if pred(x):
            return x
    return default
if __name__ == "__main__":
    assert find_first([1,2,3], lambda x: x > 1) == 2
    assert find_first([1], lambda x: x > 9) is None
    assert find_first([], bool, "d") == "d"
    print("ok")
