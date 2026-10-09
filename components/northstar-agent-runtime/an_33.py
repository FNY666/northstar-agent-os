"""an_33: sort a list. Stdlib only."""

def sortv(xs):
    return sorted(xs)

if __name__ == "__main__":
    assert sortv([3, 1, 2]) == [1, 2, 3]
    assert sortv([]) == []
    print("ok")
