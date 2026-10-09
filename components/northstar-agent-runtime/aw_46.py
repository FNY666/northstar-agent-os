"""True if all items equal."""
def all_equal(xs):
    return len(set(xs)) <= 1
if __name__ == "__main__":
    assert all_equal([2,2,2]) is True
    assert all_equal([1,2]) is False
    assert all_equal([]) is True
    print("ok")
