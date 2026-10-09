"""Adjacent differences."""
def differences(xs):
    return [b - a for a, b in zip(xs, xs[1:])]
if __name__ == "__main__":
    assert differences([1,4,9]) == [3,5]
    assert differences([5]) == []
    assert differences([2,2,2]) == [0,0]
    print("ok")
