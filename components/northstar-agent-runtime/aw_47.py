"""True if non-decreasing."""
def sorted_asc(xs):
    return all(a <= b for a, b in zip(xs, xs[1:]))
if __name__ == "__main__":
    assert sorted_asc([1,2,2,3]) is True
    assert sorted_asc([1,3,2]) is False
    assert sorted_asc([]) is True
    print("ok")
